// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <initcall.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <optee_msg.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <sm/std_smc.h>
#include <sm/spci.h>
#include <spci_private.h>
#include <string.h>

/* Consider 4 mailbox buffers to cover a single non-secure client */
#define SPCI_MSG_BUF_COUNT		4

#define MSG_SEC_RX	SPCI_MEM_REG_ARCH(SPCI_MEM_REG_ARCH_TYPE_RX, \
					  SPCI_MEM_REG_ARCH_SEC_S, \
					  SPCI_MEM_REG_ARCH_GRAN_4K)

#define MSG_SEC_TX	SPCI_MEM_REG_ARCH(SPCI_MEM_REG_ARCH_TYPE_TX, \
					  SPCI_MEM_REG_ARCH_SEC_S, \
					  SPCI_MEM_REG_ARCH_GRAN_4K)

#define MSG_NS_RX	SPCI_MEM_REG_ARCH(SPCI_MEM_REG_ARCH_TYPE_RX, \
					  SPCI_MEM_REG_ARCH_SEC_NS, \
					  SPCI_MEM_REG_ARCH_GRAN_4K)

#define MSG_NS_TX	SPCI_MEM_REG_ARCH(SPCI_MEM_REG_ARCH_TYPE_TX, \
					  SPCI_MEM_REG_ARCH_SEC_NS, \
					  SPCI_MEM_REG_ARCH_GRAN_4K)

#define SPCI_INIT_BUF_HDR	{ \
		.signature = SPCI_BUF_SIGNATURE, \
		.page_count = 1,		\
		.state = SPCI_BUF_STATE_EMPTY,	\
	}

#define SPCI_INIT_MSG_HDR	{ \
		.version = SPCI_MSG_VER(SPCI_MSG_VER_MAJ, \
					SPCI_MSG_VER_MIN), \
		.flags = SPCI_MSG_TYPE(SPCI_MSG_TYPE_ARCH), \
		.length = sizeof(struct spci_arch_msg_hdr) + \
			  sizeof(struct spci_msg_sp_init) +   \
			  sizeof(struct spci_mem_region_desc) * \
			  SPCI_MSG_BUF_COUNT, \
	}

#define SPCI_INIT_ARCH_MSG_HDR	{ \
		.type = SPCI_ARCH_MSG_TYPE(SPCI_ARCH_MSG_TYPE_SP_INIT), \
	}

#define SPCI_INIT_MSG_INIT_HDR	{ \
		.version = SPCI_MSG_VER(SPCI_MSG_VER_MAJ, \
					SPCI_MSG_VER_MIN), \
		.mem_reg_count = 4, \
	}

#define SPCI_INIT_MSG_BUF(_attributes, _idx) { \
		.address = CFG_SPCI_MSG_BUF_BASE + ((_idx) * SMALL_PAGE_SIZE), \
		.page_count = 1,		\
		.attributes = (_attributes),	\
	}

#define SPCI_INIT_MSG_MEMORIES	{ \
		SPCI_INIT_MSG_BUF(MSG_SEC_RX, 0), \
		SPCI_INIT_MSG_BUF(MSG_SEC_TX, 1), \
		SPCI_INIT_MSG_BUF(MSG_NS_RX, 2), \
		SPCI_INIT_MSG_BUF(MSG_NS_TX, 3), \
	}

/* Could remove unused secure msg_buf */
#ifndef CFG_SPCI_MSG_BUF_BASE
#define CFG_SPCI_MSG_BUF_BASE	CFG_SHMEM_START
#define CFG_SPCI_MSG_BUF_SIZE	(SMALL_PAGE_SIZE * 4)
#endif
#define SPCI_MSG_BUF_SEC_BASE	CFG_SPCI_MSG_BUF_BASE
#define SPCI_MSG_BUF_SEC_SIZE	(SMALL_PAGE_SIZE * 2)
#define SPCI_MSG_BUF_NS_BASE	(SPCI_MSG_BUF_SEC_BASE + SPCI_MSG_BUF_SEC_SIZE)
#define SPCI_MSG_BUF_NS_SIZE	(SMALL_PAGE_SIZE * 2)

/*
 * Since there is a single SP that is OP-TEE, SPCI secure SHM is located
 * in non-secure memory. This optimizes secure memory footprint.
 */
#if ((CFG_SHMEM_START > CFG_SPCI_MSG_BUF_BASE) || \
     (CFG_SHMEM_START + CFG_SHMEM_SIZE) < \
	(CFG_SPCI_MSG_BUF_BASE + CFG_SPCI_MSG_BUF_SIZE))
register_phys_mem(MEM_AREA_SPCI_NSEC_SHM, SPCI_MSG_BUF_SEC_BASE,
		  SPCI_MSG_BUF_SEC_SIZE);
register_phys_mem(MEM_AREA_SPCI_NSEC_SHM, SPCI_MSG_BUF_NS_BASE,
		  SPCI_MSG_BUF_NS_SIZE);
#endif

/*
 * Hack: cannot define structure as below. GCC warns on
 * "invalid use of structure with flexible array member".
 * We need to redefine the structure...
 *
 * struct spci_init_buf {
 *	struct spci_buf_hdr buf_hdr;
 *	struct spci_msg_hdr msg_hdr;
 *	struct spci_arch_msg_hdr arch_msg_hdr;
 *	struct spci_msg_sp_init msg_init_hdr;
 *	struct spci_mem_region_desc memories[4];
 * };
 */

struct spci_buf_hdr_only {
	const uint8_t	signature[MAX_SIG_LENGTH];
        uint32_t        page_count;     /* Including this header */
	uint32_t	state;
        uint8_t         reserved[4];
};
struct spci_msg_hdr_only {
	uint16_t		version;
	uint16_t		flags;
	uint32_t		length;
	uint16_t		target_sp;
	uint16_t		target_sp_vcpu;
	uint16_t		source_sp;
	uint16_t		source_sp_vcpu;
};
struct spci_arch_msg_hdr_only {
	uint16_t		type;
	uint8_t                 reserved[6];
};
struct spci_msg_sp_init_hdr_only {
	uint16_t                version;
	uint16_t                mem_reg_count;
	uint8_t                 reserved[4];
};

/* Builds a buffer containing a full SPCI init message incl. headers */
struct spci_init_buf {
	struct spci_buf_hdr_only buf_hdr;
	struct spci_msg_hdr_only msg_hdr;
	struct spci_arch_msg_hdr_only arch_msg_hdr;
	struct spci_msg_sp_init_hdr_only msg_init_hdr;
	struct spci_mem_region_desc memories[4];
};

/* Can be accessed at runtime. Maybe could be released after inits */
static const struct spci_init_buf spci_init_buf = {
	.buf_hdr = SPCI_INIT_BUF_HDR,
	.msg_hdr = SPCI_INIT_MSG_HDR,
	.arch_msg_hdr = SPCI_INIT_ARCH_MSG_HDR,
	.msg_init_hdr = SPCI_INIT_MSG_INIT_HDR,
	.memories = SPCI_INIT_MSG_MEMORIES,
};

/* Override default function: monitor provides the SPCI init message */
spci_buf_t *get_spci_init_msg(void)
{
	return (void *)&spci_init_buf;
}

// TODO: CFG_SPCI_NS_MAX_COUNT to define max nb non-secure VMs
#define SPCI_NS_MAX_COUNT		1

/* 2 message buffers per non-secure VM: RX and TX */
// TODO: replace with 2 instances of struct spci_msg_buf_desc
struct spci_vm_msg_buf {
	uint16_t id;
	uint32_t *rx;
	size_t rx_size;
	uint32_t *tx;
	size_t tx_size;
};

/* Structures for parsing SPCI_MSG_BUF_LIST_EXCHANGE message data */
struct msg_buf_list_exchange_hdr {
	uint32_t signature;
	uint16_t version;
	uint16_t length_h;
	uint16_t length_l;
	uint16_t attributes;
	uint32_t count;
	uint32_t buf_desc[];
};
struct msg_buf_list_exchange_desc {
	uint16_t flags;
	// TODO: remove this "reserved" and use uint64_t pa
	uint16_t reserved[3];
	uint64_t pa;
	uint16_t id;
	TEE_UUID uuid;
};

/* References to RX/TX buffers provided by the non-secure world */
static struct spci_vm_msg_buf *spci_vm_buf;
static unsigned int spci_vm_count;

/* Currently unused */
static __unused size_t hdr2list_len(struct msg_buf_list_exchange_hdr *hdr)
{
	return ((size_t)hdr->length_h << 16) | hdr->length_l;
}

static size_t attr2buf_len(uint16_t attributes)
{
	unsigned int page_count = (attributes & GENMASK_32(9, 2)) >> 2;
	unsigned int granule = attributes & GENMASK_32(1, 0);

	switch (granule) {
	case SPCI_MEM_REG_ARCH_GRAN_4K:
		return page_count << 12;
	case SPCI_MEM_REG_ARCH_GRAN_16K:
		return page_count << 14;
	case SPCI_MEM_REG_ARCH_GRAN_64K:
		return page_count << 16;
	default:
		return 0;
	}
}

static paddr_t desc2pa(struct msg_buf_list_exchange_desc *desc)
{
	uint64_t pa = desc->pa;

	if (pa > UINT32_MAX)
		return 0;

	return pa;
}

static void read_once_desc(struct msg_buf_list_exchange_desc *dst,
			   struct msg_buf_list_exchange_desc *src)
{
	dst->flags = READ_ONCE(src->flags);
	dst->pa = READ_ONCE(src->pa);
	dst->id = READ_ONCE(src->id);
}

static bool realloc_vm_buf(struct spci_vm_msg_buf **buf,
			   unsigned int buf_count, unsigned int added_count)
{
	void *tmp = realloc(*buf, (buf_count + added_count) * sizeof(**buf));

	if (!tmp)
		return false;

	*buf = tmp;
	memset(*buf + buf_count, 0, added_count * sizeof(**buf));
	return true;
}

static struct spci_vm_msg_buf *find_vm_buf(unsigned int vm_id,
					   struct spci_vm_msg_buf *buf,
					   unsigned int count)
{
	unsigned int i = 0;

	for (i = 0; i < count; i++)
		if (buf[i].id == vm_id)
			return &buf[i];

	return NULL;
}

static void save_vm_buf(struct spci_vm_msg_buf *buf,
			struct msg_buf_list_exchange_desc *desc,
			void *va, size_t size)
{
	if (desc->flags & 1) {
		buf->tx = va;
		buf->tx_size = size;
	} else {
		buf->rx = va;
		buf->rx_size = size;
	}
	buf->id = desc->id;
}

static void *map_vm_buf(paddr_t pa, size_t size)
{
	struct mobj *mobj = NULL;
	size_t offset = 0;

	if (core_pbuf_is(CORE_MEM_NSEC_SHM, pa, size)) {
		mobj = mobj_shm_alloc(pa, size, 0);
		if (!mobj)
			return NULL;
	}

	if (!mobj) {
		paddr_t pa2 = ROUNDDOWN(pa, SMALL_PAGE_SIZE);
		size_t sz2 = ROUNDUP(pa + size, SMALL_PAGE_SIZE) - pa2;
		unsigned int pg_count = sz2 / SMALL_PAGE_SIZE;
		paddr_t *pg_pas = NULL;
		unsigned int i = 0;

		pg_pas = malloc(pg_count * sizeof(*pg_pas));
		if (!pg_pas)
			return NULL;

		for (i = 0; i < pg_count; i++)
			pg_pas[i] = pa2 + i * SMALL_PAGE_SIZE;

		mobj = mobj_mapped_shm_alloc(pg_pas, pg_count, 0, 0);
		free(pg_pas);
		if (!mobj)
			return NULL;

		offset = pa - pa2;
	}

	return mobj_get_va(mobj, offset);
}

static void unmap_vm_buf(void *va __unused)
{
	IMSG("Unmapping SPCI shared memory is not yet supported");
}

static void dump_vm_buf(struct spci_vm_msg_buf *buf __maybe_unused,
			unsigned int count)
{
	unsigned int i = 0;

	for (i = 0; i < count; i++)
		EMSG("Message buffer: id %u, RX %u@%p, TX %u@%p",
			buf->id, buf->rx_size, (void *)buf->rx,
			buf->tx_size, (void *)buf->tx);
}

static int32_t msg_buf_list_exchange(struct thread_smc_args *args)
{
	int32_t rc = SPCI_INVALID_PARAMETER;
	uint32_t list_pa = 0;
	uint32_t list_size = 0;
	void *list_va = NULL;
	size_t buf_count = 0;
	uint16_t attributes = 0;
	size_t buf_size = 0;
	struct msg_buf_list_exchange_hdr *hdr = NULL;
	struct msg_buf_list_exchange_desc *buf_desc = NULL;
	unsigned int vm_count = 0;
	struct spci_vm_msg_buf *vm_buf = NULL;
	unsigned int i = 0;

	/*
	 * Contrary to the spec, Aarch32 SMC SPCI_MSG_BUF_LIST_EXCHANGE
	 * fills a1=pa (32bit) and a2=list size (32b)
	 */
	list_pa = args->a1;
	list_size = args->a2;

	if (list_size < sizeof(struct msg_buf_list_exchange_hdr))
		return SPCI_INVALID_PARAMETER;

	list_va = map_vm_buf(list_pa, list_size);
	if (!list_va)
		return SPCI_INVALID_PARAMETER;

	hdr = (void *)list_va;
	buf_count = READ_ONCE(hdr->count);
	attributes = READ_ONCE(hdr->attributes);
	buf_size = attr2buf_len(attributes);

	if (sizeof(struct msg_buf_list_exchange_hdr) +
	    buf_count * sizeof(struct msg_buf_list_exchange_hdr) > list_size)
		goto bail_list_map;

	buf_desc = (void *)(hdr + 1);
	for (i = 0; i < buf_count; i++) {
		struct spci_vm_msg_buf *buf = NULL;
		struct msg_buf_list_exchange_desc desc = { 0 };
		void *va = NULL;

		read_once_desc(&desc, buf_desc);
		buf_desc++;

		va = map_vm_buf(desc2pa(&desc), buf_size);
		if (!va) {
			rc = SPCI_NO_MEMORY;
			goto bail_bufs_map;
		}
		EMSG("map pa %x to va %p", (unsigned)desc2pa(&desc), va);

		/* Allocate a VM message buffer if not already registered */
		buf = find_vm_buf(desc.id, spci_vm_buf, spci_vm_count);
		if (!buf) {
			buf = find_vm_buf(desc.id, vm_buf, vm_count);
		}
		if (!buf) {
			if (!realloc_vm_buf(&vm_buf, vm_count, 1)) {
				rc = SPCI_NO_MEMORY;
				goto bail_bufs_map;
			}
			buf = &vm_buf[vm_count];
			vm_count++;
		}

		save_vm_buf(buf, &desc, va, buf_size);
	}

	if (!realloc_vm_buf(&spci_vm_buf, spci_vm_count, vm_count)) {
		args->a0 = SPCI_NO_MEMORY;
		goto bail_bufs_map;
	}

	memcpy(&spci_vm_buf[spci_vm_count], vm_buf, sizeof(*vm_buf) * vm_count);
	spci_vm_count += vm_count;
	rc = SPCI_SUCCESS;

	dump_vm_buf(spci_vm_buf, spci_vm_count);

bail_bufs_map:
	if (rc != SPCI_SUCCESS) {
		for (i = 0; i < vm_count; i++) {
			unmap_vm_buf(vm_buf[i].rx);
			unmap_vm_buf(vm_buf[i].tx);
		}
	}
bail_list_map:
	unmap_vm_buf(hdr);

	return rc;
}

static TEE_Result init_spci_local_msg_bufs(void)
{
	struct spci_msg_buf_desc *buf_desc = NULL;
	const struct spci_buf empty_buf = {
		.hdr = {
			.signature = { 'B', 'U', 'F', '\0' },
			.page_count = 1,
			.state = SPCI_BUF_STATE_EMPTY,
		},
	};

	buf_desc = get_spci_buffer(SPCI_MEM_REG_ARCH_SEC_NS,
				   SPCI_MEM_REG_ARCH_TYPE_RX);
	memcpy((void *)buf_desc->va, &empty_buf, sizeof(empty_buf));

	buf_desc = get_spci_buffer(SPCI_MEM_REG_ARCH_SEC_NS,
				   SPCI_MEM_REG_ARCH_TYPE_TX);
	memcpy((void *)buf_desc->va, &empty_buf, sizeof(empty_buf));

	return TEE_SUCCESS;
}
service_init(init_spci_local_msg_bufs);

/*
 * Monitor receives SPCI_MSG_SEND: copy message to SP msg buffer
 */
static int32_t vm_msg_send(const struct thread_smc_args *args)
{
	uint32_t attributes = args->a1;
	uint32_t caller_id = args->a7;
	struct spci_vm_msg_buf *vm_buf = NULL;
	struct spci_buf *tx_buf = NULL;
	struct spci_msg_buf_desc *rx_outbuf_desc = NULL;
	struct spci_buf *rx_buf = NULL;
	struct spci_msg_hdr *msg_hdr = NULL;
	size_t msg_size = 0;
	const uint32_t mask_blk_notif = SPCI_MSG_SEND_ATTRS_BLK_MASK <<
					SPCI_MSG_SEND_ATTRS_BLK_SHIFT;
	const uint32_t mask_msg_loc = SPCI_MSG_SEND_ATTRS_MSGLOC_MASK <<
				      SPCI_MSG_SEND_ATTRS_MSGLOC_SHIFT;

	// TODO: handle blocking/notifying behavior
	// here assume blocking only (and always available)

	if (attributes & mask_blk_notif || !(attributes & mask_msg_loc))
		return SPCI_INVALID_PARAMETER;

	// Copy message from caller TX buffer to SP RX buffer
	vm_buf = find_vm_buf(caller_id, spci_vm_buf, spci_vm_count);
	if (!vm_buf) {
		EMSG("find_vm_buf() failed");
		return SPCI_INVALID_PARAMETER;
	}

	/* Caller TX buffer reference */
	tx_buf = (void *)vm_buf->tx;
	if (!tx_buf)
		return SPCI_NO_MEMORY;

	FMSG_RAW("%s: TX buf from NS (%s, %u, %u) at %p",
		__func__, tx_buf->hdr.signature, tx_buf->hdr.page_count,
		tx_buf->hdr.state, (void *)tx_buf);

	if (tx_buf->hdr.state != SPCI_BUF_STATE_FULL)
		return SPCI_INVALID_PARAMETER;

	if (tx_buf->hdr.page_count * SMALL_PAGE_SIZE <
	    sizeof(tx_buf->hdr) + sizeof(struct spci_msg_hdr))
		return SPCI_NO_MEMORY;

	msg_hdr = (void *)(&tx_buf->buf);
	msg_size = sizeof(*msg_hdr) + msg_hdr->length;
	if (tx_buf->hdr.page_count * SMALL_PAGE_SIZE <
	    sizeof(tx_buf->hdr) + msg_size)
		return SPCI_NO_MEMORY;

	/* Monitor RX buffer reference */
	rx_outbuf_desc = get_spci_buffer(SPCI_MEM_REG_ARCH_SEC_NS,
				         SPCI_MEM_REG_ARCH_TYPE_RX);
	rx_buf = (void *)rx_outbuf_desc->va;
	if (!rx_buf)
		return SPCI_NO_MEMORY;

	FMSG_RAW("%s: RX buf from OPTEE (%s, %u, %u) at %p",
		__func__, rx_buf->hdr.signature,
		rx_buf->hdr.page_count, rx_buf->hdr.state,
		(void *)rx_buf);

	if (rx_buf->hdr.state != SPCI_BUF_STATE_EMPTY)
		return SPCI_BUSY;

	if (rx_buf->hdr.page_count * SMALL_PAGE_SIZE <
	    sizeof(rx_buf->hdr) + msg_size)
		return SPCI_NO_MEMORY;

	FMSG("Copy TX %p to RX %" PRIxPA " (phys addr), %u bytes",
		(void *)tx_buf, rx_outbuf_desc->pa, msg_size);

	memcpy(rx_buf->buf, tx_buf->buf, msg_size);
	rx_buf->hdr.state = SPCI_BUF_STATE_FULL;
	memset(tx_buf->buf, 0, msg_size);
	tx_buf->hdr.state = SPCI_BUF_STATE_EMPTY;

	return SPCI_SUCCESS;
}

bool tee_spci_handler(struct thread_smc_args *args,
		      struct sm_nsec_ctx *nsec __maybe_unused)
{
	uint32_t smc_fid = args->a0;
	unsigned int fnum = OPTEE_SMC_FUNC_NUM(smc_fid);

	switch (fnum) {
	case OPTEE_SMC_FUNC_NUM(SPCI_VERSION):
		args->a0 = SPCI_VERSION_COMPILED;
		break;
	case OPTEE_SMC_FUNC_NUM(SPCI_MSG_BUF_LIST_EXCHANGE):
#if 0
		/* TODO: Handle from Yield entry (std_smc, not unpaged!!!) */
		if (args->a3 > SMALL_PAGE_SIZE) {
			args->a0 = SPCI_NOT_SUPPORTED;
			return true;
		}
		args->a0 = OPTEE_SMC_CALL_WITH_ARG;
		/* Move shm phys addr from args->a1 to a1/a2 (MSB/LSB) */
		args->a2 = 0;
		args->a2 = args->a1;	/* expect a0 32b MSB, a2 32b LSB */
		/*
		 * Tag that its a SMC std entry, not a SPCI scheduled msg
		 * I.e. Keep RX buf full, set TX buf state = NO_MSG.
		 * At exit (spci_msg_send_recv_invoke), since NO_MSG,
		 * simply return the Return code (32bit max)
		 *
		 * Could use a0 = SMC ID for SPCI_MSG_BUF_LIST_EXCHANGE
		 * => need to hack a bit in tee_entry_std() to support
		 * a0 == SPCI_MSG_BUF_LIST_EXCHANGE
		 */
		return SM_HANDLER_PENDING_SMC;
#endif
		args->a0 = msg_buf_list_exchange(args);
		break;

	case OPTEE_SMC_FUNC_NUM(SPCI_MSG_SEND):
		args->a0 = vm_msg_send(args);
		break;

	case OPTEE_SMC_FUNC_NUM(SPCI_RUN):
		/*
		 * Set return value as status on completion upon completion
		 * of SPCI_MESG_[SEND_]RECV. Message location will always
		 * be the non-secure RX buffer of the SP.
		 */
		args->a0 = SPCI_MSG_RECV_MSGLOC_NSEC <<
			   SPCI_MSG_RECV_MSGLOC_SHIFT;
		/* Relay message to secure world */
		return false;

	case OPTEE_SMC_FUNC_NUM(SPCI_MSG_PUT):
	case OPTEE_SMC_FUNC_NUM(SPCI_MSG_RECV):
	case OPTEE_SMC_FUNC_NUM(SPCI_MSG_SEND_RECV):
	case OPTEE_SMC_FUNC_NUM(SPCI_YIELD):
		EMSG("Unexpected func num%" PRIx32, fnum);
		/* Fall-through */
	default:
		args->a0 = SPCI_NOT_SUPPORTED;
		break;
	}

	return true;
}

uint32_t realy_msg_to_vm_rx(struct thread_smc_args *args);


uint32_t realy_msg_to_vm_rx(struct thread_smc_args *args __unused)
{
	uint32_t vm_id = 0; /*Force to 0, caller should set args->a7*/;
	struct spci_msg_buf_desc *tx_buf_desc = NULL;
	struct spci_vm_msg_buf *vm_buf = NULL;
	struct spci_buf *rx_buf = NULL;
	struct spci_buf *tx_buf = NULL;
	struct spci_msg_hdr *msg_hdr = NULL;

	vm_buf = find_vm_buf(vm_id, spci_vm_buf, spci_vm_count);
	assert(vm_buf && vm_buf->rx);
	rx_buf = (void *)vm_buf->rx;

	tx_buf_desc = get_spci_buffer(SPCI_MEM_REG_ARCH_SEC_NS,
				      SPCI_MEM_REG_ARCH_TYPE_TX);
	assert(tx_buf_desc && tx_buf_desc->va);
	tx_buf = (void *)tx_buf_desc->va;

	// TODO: wait RX buffer is empty
	if (rx_buf->hdr.state != SPCI_BUF_STATE_EMPTY) {
		EMSG(" RX buffer not empty: waiting...");
		isb();
		while (rx_buf->hdr.state != SPCI_BUF_STATE_EMPTY)
			;
		//panic();
	}

	msg_hdr = (void *)tx_buf->buf;

	memcpy(rx_buf->buf, tx_buf->buf, sizeof(*msg_hdr) + msg_hdr->length);
	rx_buf->hdr.state = SPCI_BUF_STATE_FULL;
	tx_buf->hdr.state = SPCI_BUF_STATE_EMPTY;

	/* TODO: define SPCI_RUN_COMP_REASON_DONE_MSG in sm/spci.h or spci.h */
	return 4;
}

/*
 * Override default implementation to locate OP-TEE RX buffer in the
 * static SHM. This prevent wasting a MMU table for mapping SPCI message
 * buffers.
 */
void carveout_spci_buf_from_exported_reserved_shm(paddr_t *pa, size_t *len)
{
	/*
	 * Carveout a single page for OP-TEE RX message buffer.
	 * No need for a TX buffer as OP-TEE will copy sent message
	 * straight into VM message buffer, without using a intermediate
	 * message buffer.
	 */
	*pa += SMALL_PAGE_SIZE;
	*len -= SMALL_PAGE_SIZE;
}
