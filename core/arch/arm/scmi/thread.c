// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <platform_config.h>

#include <assert.h>
#include <string.h>

#include <kernel/thread.h>

#include <spci.h>
#include <scmi.h>

/*
 * Interface with SCMI server
 * TODO: add them in a dedicated header file
 */
extern void* spci_get_buffer_ospm0(void);
extern void optee_init_scmi(void);
extern void optee_process_scmi(void);
extern void spci_raise_event_ospm0(void);

/*!
 * \brief Message header layout
 *
 * \details Define the memory mayout of a message mailbox
 */
struct __attribute((packed)) scpi_mb_memory {
    uint32_t reserved0;
    uint32_t status;
    uint64_t reserved1;
    uint32_t flags;
    uint32_t length; /* message_header + payload */
    uint32_t message_header;
    uint32_t payload[];
};

#define SCMI_PAYLOAD_SIZE       (128)

int32_t spci_scmi_recv_escape(spci_msg_hdr_t *msg_hdr,
			      struct thread_smc_args *args)
{
	struct __attribute((packed)) scpi_mb_memory *message = NULL;

	/* Get the payload */
	message = (void *)msg_hdr->payload;

	/* Check for escape tag from SCMI payload */
	if (message->reserved0 != 0xDEADBEEF)
		return 0;

	/* Check if message length is larger than mailbox size */
	assert(msg_hdr->length <= SCMI_PAYLOAD_SIZE);

	/* Zero the args */
	memset((void *) args, 0, sizeof(*args));

	/* Setting a0 to 0 will ensure that we will go to alloc and run path */
	args->a0 = 0;
	args->a1 = 0xDEADBEEF;

	/* Copy the message */
	memcpy(spci_get_buffer_ospm0(), msg_hdr->payload, msg_hdr->length);

	/* Clear the original message */
	memset(msg_hdr->payload, 0, msg_hdr->length);

	return 1;
}

int32_t spci_scmi_send_escape(spci_msg_hdr_t *msg_hdr,
			      struct thread_eret_args *args)
{
	struct __attribute((packed)) scpi_mb_memory *message;
	int size;

	/* Check for escape tag from SCMI payload */
	if (args->a1 != 0xDEADBEEF)
		return 0;

	/* Get the payload */
	message = spci_get_buffer_ospm0();

	/* compute payload size */
	size = sizeof(*message) + message->length - sizeof(message->message_header);

	/* Copy the message */
	memcpy(msg_hdr->payload, message, size);

	/* Set the message length */
	msg_hdr->length = size;

	return 1;
}

/*
 * Helper routine for the assembly function thread_std_smc_entry()
 *
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak __thread_std_scmi_entry(struct thread_smc_args *args __unused)
{
	struct __attribute((packed)) scpi_mb_memory *message = NULL;
	unsigned int i = 0;
	unsigned int size = 0;

	message = spci_get_buffer_ospm0();

	DMSG("message header 0x%08x\n", message->message_header);
	DMSG("message lenght %d\n", message->length);

	size = message->length - sizeof(message->message_header);

	for(i=0; i < (size /  sizeof(message->payload[0])) ; i++)
	{
			DMSG("payload 0x%08x\n", message->payload[i]);
	}

	/* Do we need to init SCMI server ? */
	/* TODO: move it to the right place to run it once */
	optee_init_scmi();

	/* Raise event to SCMI server */
	spci_raise_event_ospm0();

	/* Process pending events */
	optee_process_scmi();
}

