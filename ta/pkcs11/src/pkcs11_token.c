// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <confine_array_index.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "attributes.h"
#include "handle.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"
#include "token_capabilities.h"

/* Provide 3 slots/tokens, ID is token index */
#ifndef CFG_PKCS11_TA_TOKEN_COUNT
#define TOKEN_COUNT		3
#else
#define TOKEN_COUNT		CFG_PKCS11_TA_TOKEN_COUNT
#endif

/* Static allocation of tokens runtime instances (reset to 0 at load) */
struct ck_token ck_token[TOKEN_COUNT];

static struct client_list pkcs11_client_list;

static void close_ck_session(struct pkcs11_session *session);

struct ck_token *get_token(unsigned int token_id)
{
	if (token_id < TOKEN_COUNT)
		return &ck_token[confine_array_index(token_id, TOKEN_COUNT)];

	return NULL;
}

unsigned int get_token_id(struct ck_token *token)
{
	ptrdiff_t id = token - ck_token;

	assert(id >= 0 && id < TOKEN_COUNT);
	return id;
}

struct pkcs11_client *tee_session2client(uintptr_t tee_session)
{
	struct pkcs11_client *client = NULL;

	TAILQ_FOREACH(client, &pkcs11_client_list, link)
		if (client == (void *)tee_session)
			break;

	return client;
}

struct pkcs11_session *pkcs11_handle2session(uint32_t handle,
					     struct pkcs11_client *client)
{
	return handle_lookup(&client->session_handle_db, (int)handle);
}

uintptr_t register_client(void)
{
	struct pkcs11_client *client = NULL;

	client = TEE_Malloc(sizeof(*client), TEE_MALLOC_FILL_ZERO);
	if (!client)
		return 0;

	TAILQ_INSERT_HEAD(&pkcs11_client_list, client, link);
	TAILQ_INIT(&client->session_list);
	handle_db_init(&client->session_handle_db);

	return (uintptr_t)(void *)client;
}

void unregister_client(uintptr_t tee_session)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *next = NULL;

	if (!client) {
		EMSG("Invalid TEE session handle");
		return;
	}

	TAILQ_FOREACH_SAFE(session, &client->session_list, link, next)
		close_ck_session(session);

	TAILQ_REMOVE(&pkcs11_client_list, client, link);
	handle_db_destroy(&client->session_handle_db);
	TEE_Free(client);
}

static TEE_Result pkcs11_token_init(unsigned int id)
{
	struct ck_token *token = init_persistent_db(id);

	if (!token)
		return TEE_ERROR_SECURITY;

	if (token->state == PKCS11_TOKEN_RESET) {
		/* As per PKCS#11 spec, token resets to read/write state */
		token->state = PKCS11_TOKEN_READ_WRITE;
		token->session_count = 0;
		token->rw_session_count = 0;
	}

	return TEE_SUCCESS;
}

TEE_Result pkcs11_init(void)
{
	unsigned int id = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	for (id = 0; id < TOKEN_COUNT; id++) {
		ret = pkcs11_token_init(id);
		if (ret)
			break;
	}

	if (!ret)
		TAILQ_INIT(&pkcs11_client_list);

	return ret;
}

void pkcs11_deinit(void)
{
	unsigned int id = 0;

	for (id = 0; id < TOKEN_COUNT; id++)
		close_persistent_db(get_token(id));
}

/*
 * Currently not support dual operations.
 */
int set_processing_state(struct pkcs11_session *session,
			 enum processing_func function,
			 struct pkcs11_object *obj1,
			 struct pkcs11_object *obj2)
{
	enum pkcs11_proc_state state;
	struct active_processing *proc = NULL;

	TEE_MemFill(&state, 0, sizeof(state));

	if (session->processing)
		return PKCS11_CKR_OPERATION_ACTIVE;

	switch (function) {
	case PKCS11_FUNCTION_ENCRYPT:
		state = PKCS11_SESSION_ENCRYPTING;
		break;
	case PKCS11_FUNCTION_DECRYPT:
		state = PKCS11_SESSION_DECRYPTING;
		break;
	case PKCS11_FUNCTION_SIGN:
		state = PKCS11_SESSION_SIGNING;
		break;
	case PKCS11_FUNCTION_VERIFY:
		state = PKCS11_SESSION_VERIFYING;
		break;
	case PKCS11_FUNCTION_DIGEST:
		state = PKCS11_SESSION_DIGESTING;
		break;
	case PKCS11_FUNCTION_DERIVE:
		state = PKCS11_SESSION_READY;
		break;
	default:
		TEE_Panic(function);
		return -1;
	}

	proc = TEE_Malloc(sizeof(*proc), TEE_MALLOC_FILL_ZERO);
	if (!proc)
		return PKCS11_MEMORY;

	/* Boolean are default to false and pointers to NULL */
	proc->state = state;
	proc->tee_op_handle = TEE_HANDLE_NULL;

	if (obj1 && get_bool(obj1->attributes, PKCS11_CKA_ALWAYS_AUTHENTICATE))
		proc->always_authen = true;

	if (obj2 && get_bool(obj2->attributes, PKCS11_CKA_ALWAYS_AUTHENTICATE))
		proc->always_authen = true;

	session->processing = proc;

	return PKCS11_OK;
}

/*
 * TODO: move to presistent token: 1 cipher_login_pin(token, uid, buf, size)
 * for the open/cipher/close atomic operation to not let PIN handle open.
 */
static void cipher_pin(TEE_ObjectHandle key_handle, uint8_t *buf, size_t len)
{
	uint8_t iv[16] = { 0 };
	uint32_t size = len;
	TEE_OperationHandle tee_op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_AllocateOperation(&tee_op_handle,
				    TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_ENCRYPT, 128);
	if (res)
		TEE_Panic(0);

	res = TEE_SetOperationKey(tee_op_handle, key_handle);
	if (res)
		TEE_Panic(0);

	TEE_CipherInit(tee_op_handle, iv, sizeof(iv));

	res = TEE_CipherDoFinal(tee_op_handle, buf, len, buf, &size);
	if (res || size != PKCS11_TOKEN_PIN_SIZE_MAX)
		TEE_Panic(0);

	TEE_FreeOperation(tee_op_handle);
}

/* ctrl=[slot-id][pin-size][pin][label], in=unused, out=unused */
uint32_t entry_ck_token_initialize(uint32_t ptypes, TEE_Param *params)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	uint32_t pin_size = 0;
	void *pin = NULL;
	char label[PKCS11_TOKEN_LABEL_SIZE + 1] = { 0 };
	struct ck_token *token = NULL;
	uint8_t *cpin = NULL;
	int pin_rc = 0;
	struct pkcs11_client *client = NULL;
	TEE_ObjectHandle key_hdl = TEE_HANDLE_NULL;

	if (ptypes != exp_pt)
		return PKCS11_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rv)
		return rv;

	if (pin_size < PKCS11_TOKEN_PIN_SIZE_MIN ||
	    pin_size > PKCS11_TOKEN_PIN_SIZE_MAX)
		return PKCS11_CKR_PIN_LEN_RANGE;

	rv = serialargs_get(&ctrlargs, &label, PKCS11_TOKEN_LABEL_SIZE);
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_BAD_PARAM;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	if (token->db_main->flags & PKCS11_CKFT_SO_PIN_LOCKED) {
		IMSG("Token %"PRIu32": SO PIN locked", token_id);
		return PKCS11_CKR_PIN_LOCKED;
	}

	TAILQ_FOREACH(client, &pkcs11_client_list, link)
		if (!TAILQ_EMPTY(&client->session_list))
			return PKCS11_CKR_SESSION_EXISTS;

	cpin = TEE_Malloc(PKCS11_TOKEN_PIN_SIZE_MAX, TEE_MALLOC_FILL_ZERO);
	if (!cpin)
		return PKCS11_CKR_DEVICE_MEMORY;

	TEE_MemMove(cpin, pin, pin_size);

	// TODO: move into a single cipher_login_pin(token, user, buf, sz)
	if (open_pin_file(token, PKCS11_CKU_SO, &key_hdl)) {
		rv = PKCS11_CKR_GENERAL_ERROR;
		goto out;
	}
	cipher_pin(key_hdl, cpin, PKCS11_TOKEN_PIN_SIZE_MAX);
	close_pin_file(key_hdl);

	if (!token->db_main->so_pin_size) {
		TEE_MemMove(token->db_main->so_pin, cpin,
			    PKCS11_TOKEN_PIN_SIZE_MAX);
		token->db_main->so_pin_size = pin_size;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin),
				     sizeof(token->db_main->so_pin));
		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin_size),
				     sizeof(token->db_main->so_pin_size));

		goto inited;
	}

	pin_rc = 0;
	if (token->db_main->so_pin_size != pin_size)
		pin_rc = 1;
	if (buf_compare_ct(token->db_main->so_pin, cpin,
			   PKCS11_TOKEN_PIN_SIZE_MAX))
		pin_rc = 1;

	if (pin_rc) {
		token->db_main->flags |= PKCS11_CKFT_SO_PIN_COUNT_LOW;
		token->db_main->so_pin_count++;

		if (token->db_main->so_pin_count == 6)
			token->db_main->flags |= PKCS11_CKFT_SO_PIN_FINAL_TRY;
		if (token->db_main->so_pin_count == 7)
			token->db_main->flags |= PKCS11_CKFT_SO_PIN_LOCKED;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      flags),
				     sizeof(token->db_main->flags));

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin_count),
				     sizeof(token->db_main->so_pin_count));

		rv = PKCS11_CKR_PIN_INCORRECT;
		goto out;
	}

	token->db_main->flags &= ~(PKCS11_CKFT_SO_PIN_COUNT_LOW |
				   PKCS11_CKFT_SO_PIN_FINAL_TRY);
	token->db_main->so_pin_count = 0;

inited:
	TEE_MemMove(token->db_main->label, label, PKCS11_TOKEN_LABEL_SIZE);
	token->db_main->flags |= PKCS11_CKFT_TOKEN_INITIALIZED;
	/* Reset user PIN */
	token->db_main->user_pin_size = 0;
	token->db_main->flags &= ~(PKCS11_CKFT_USER_PIN_INITIALIZED |
				   PKCS11_CKFT_USER_PIN_COUNT_LOW |
				   PKCS11_CKFT_USER_PIN_FINAL_TRY |
				   PKCS11_CKFT_USER_PIN_LOCKED |
				   PKCS11_CKFT_USER_PIN_TO_BE_CHANGED);

	update_persistent_db(token, 0, sizeof(*token->db_main));

	label[PKCS11_TOKEN_LABEL_SIZE] = '\0';
	IMSG("PKCS11 token %"PRIu32": initialized \"%s\"", token_id, label);

out:
	TEE_Free(cpin);

	return rv;
}

uint32_t entry_ck_slot_list(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *out = &params[2];
	uint32_t token_id = 0;
	const size_t out_size = sizeof(token_id) * TOKEN_COUNT;
	uint8_t *id = NULL;

	if (ptypes != exp_pt ||
	    params[0].memref.size != TEE_PARAM0_SIZE_MIN)
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (out->memref.size < out_size) {
		out->memref.size = out_size;

		if (out->memref.buffer)
			return PKCS11_CKR_BUFFER_TOO_SMALL;
		else
			return PKCS11_CKR_OK;
	}

	for (token_id = 0, id = out->memref.buffer; token_id < TOKEN_COUNT;
	     token_id++, id += sizeof(token_id))
		TEE_MemMove(id, &token_id, sizeof(token_id));

	out->memref.size = out_size;

	return PKCS11_CKR_OK;
}

static void pad_str(uint8_t *str, size_t size)
{
	int n = strnlen((char *)str, size);

	TEE_MemFill(str + n, ' ', size - n);
}

uint32_t entry_ck_slot_info(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_slot_info info = {
		.slot_description = PKCS11_SLOT_DESCRIPTION,
		.manufacturer_id = PKCS11_SLOT_MANUFACTURER,
		.flags = PKCS11_CKFS_TOKEN_PRESENT,
		.hardware_version = PKCS11_SLOT_HW_VERSION,
		.firmware_version = PKCS11_SLOT_FW_VERSION,
	};

	COMPILE_TIME_ASSERT(sizeof(PKCS11_SLOT_DESCRIPTION) <=
			    sizeof(info.slot_description));
	COMPILE_TIME_ASSERT(sizeof(PKCS11_SLOT_MANUFACTURER) <=
			    sizeof(info.manufacturer_id));

	if (ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	pad_str(info.slot_description, sizeof(info.slot_description));
	pad_str(info.manufacturer_id, sizeof(info.manufacturer_id));

	out->memref.size = sizeof(info);
	TEE_MemMove(out->memref.buffer, &info, out->memref.size);

	return PKCS11_CKR_OK;
}

uint32_t entry_ck_token_info(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_token_info info = {
		.manufacturer_id = PKCS11_TOKEN_MANUFACTURER,
		.model = PKCS11_TOKEN_MODEL,
		.serial_number = PKCS11_TOKEN_SERIAL_NUMBER,
		.max_session_count = UINT32_MAX,
		.max_rw_session_count = UINT32_MAX,
		.max_pin_len = PKCS11_TOKEN_PIN_SIZE_MAX,
		.min_pin_len = PKCS11_TOKEN_PIN_SIZE_MIN,
		.total_public_memory = UINT32_MAX,
		.free_public_memory = UINT32_MAX,
		.total_private_memory = UINT32_MAX,
		.free_private_memory = UINT32_MAX,
		.hardware_version = PKCS11_TOKEN_HW_VERSION,
		.firmware_version = PKCS11_TOKEN_FW_VERSION,
	};

	if (ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	pad_str(info.manufacturer_id, sizeof(info.manufacturer_id));
	pad_str(info.model, sizeof(info.model));
	pad_str(info.serial_number, sizeof(info.serial_number));

	TEE_MemMove(info.label, token->db_main->label, sizeof(info.label));

	info.flags = token->db_main->flags;
	info.session_count = token->session_count;
	info.rw_session_count = token->rw_session_count;

	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return PKCS11_CKR_OK;
}

static void dmsg_print_supported_mechanism(unsigned int token_id __maybe_unused,
					   uint32_t *mecha_array __maybe_unused,
					   size_t count __maybe_unused)
{
	size_t __maybe_unused n = 0;

	if (TRACE_LEVEL < TRACE_DEBUG)
		return;

	for (n = 0; n < count; n++)
		DMSG("PKCS11 token %"PRIu32": mechanism 0x%04"PRIx32": %s",
		     token_id, mecha_array[n], id2str_proc(mecha_array[n]));
}

uint32_t entry_ck_token_mecha_ids(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token __maybe_unused *token = NULL;
	size_t count = 0;
	uint32_t *array = NULL;

	if (ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	count = out->memref.size / sizeof(*array);
	array = tee_malloc_mechanism_list(&count);

	if (out->memref.size < count * sizeof(*array)) {
		assert(!array);
		out->memref.size = count * sizeof(*array);
		return PKCS11_CKR_BUFFER_TOO_SMALL;
	}

	if (!array)
		return PKCS11_CKR_DEVICE_MEMORY;

	dmsg_print_supported_mechanism(token_id, array, count);

	out->memref.size = count * sizeof(*array);
	TEE_MemMove(out->memref.buffer, array, out->memref.size);

	TEE_Free(array);

	return rv;
}

static void supported_mechanism_key_size(uint32_t proc_id,
					 uint32_t *max_key_size,
					 uint32_t *min_key_size)
{
	switch (proc_id) {
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
		*min_key_size = 1;		/* in bits */
		*max_key_size = 4096;		/* in bits */
		break;
	case PKCS11_CKM_MD5_HMAC:
		*min_key_size = 16;
		*max_key_size = 16;
		break;
	case PKCS11_CKM_SHA_1_HMAC:
		*min_key_size = 20;
		*max_key_size = 20;
		break;
	case PKCS11_CKM_SHA224_HMAC:
		*min_key_size = 28;
		*max_key_size = 28;
		break;
	case PKCS11_CKM_SHA256_HMAC:
		*min_key_size = 32;
		*max_key_size = 32;
		break;
	case PKCS11_CKM_SHA384_HMAC:
		*min_key_size = 48;
		*max_key_size = 48;
		break;
	case PKCS11_CKM_SHA512_HMAC:
		*min_key_size = 64;
		*max_key_size = 64;
		break;
	case PKCS11_CKM_AES_XCBC_MAC:
		*min_key_size = 28;
		*max_key_size = 28;
		break;
	case PKCS11_CKM_AES_KEY_GEN:
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTR:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_GCM:
	case PKCS11_CKM_AES_CCM:
	case PKCS11_CKM_AES_GMAC:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_AES_CMAC_GENERAL:
		*min_key_size = 16;
		*max_key_size = 32;
		break;
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
	case PKCS11_CKM_ECDH1_DERIVE:
	case PKCS11_CKM_ECDH1_COFACTOR_DERIVE:
	case PKCS11_CKM_ECMQV_DERIVE:
	case PKCS11_CKM_ECDH_AES_KEY_WRAP:
		*min_key_size = 160;	/* in bits */
		*max_key_size = 521;	/* in bits */
		break;
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
	case PKCS11_CKM_RSA_PKCS:
	case PKCS11_CKM_RSA_9796:
	case PKCS11_CKM_RSA_X_509:
	case PKCS11_CKM_SHA1_RSA_PKCS:
	case PKCS11_CKM_RSA_PKCS_OAEP:
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS:
	case PKCS11_CKM_SHA384_RSA_PKCS:
	case PKCS11_CKM_SHA512_RSA_PKCS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
		*min_key_size = 256;	/* in bits */
		*max_key_size = 4096;	/* in bits */
		break;
	default:
		*min_key_size = 0;
		*max_key_size = 0;
		break;
	}
}

uint32_t entry_ck_token_mecha_info(uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	uint32_t type = 0;
	struct ck_token *token = NULL;
	struct pkcs11_mechanism_info info = { };

	if (ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &type, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	if (!mechanism_is_valid(type))
		return PKCS11_CKR_MECHANISM_INVALID;

	info.flags = mechanism_supported_flags(type);

	supported_mechanism_key_size(type, &info.min_key_size,
				     &info.max_key_size);

	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	DMSG("PKCS11 token %"PRIu32": mechanism 0x%"PRIx32" info",
	     token_id, type);

	return PKCS11_CKR_OK;
}

/* Select the ReadOnly or ReadWrite state for session login state */
static void set_session_state(struct pkcs11_client *client,
			      struct pkcs11_session *session, bool readonly)
{
	struct pkcs11_session *sess = NULL;
	enum pkcs11_session_state state = PKCS11_CKS_RO_PUBLIC_SESSION;

	/* Default to public session if no session already registered */
	if (readonly)
		state = PKCS11_CKS_RO_PUBLIC_SESSION;
	else
		state = PKCS11_CKS_RW_PUBLIC_SESSION;

	/*
	 * No need to check all client sessions, the first found in
	 * target token gives client login configuration.
	 */
	TAILQ_FOREACH(sess, &client->session_list, link) {
		assert(sess != session);

		if (sess->token == session->token) {
			state = sess->state;
			break;
		}
	}

	switch (state) {
	case PKCS11_CKS_RW_PUBLIC_SESSION:
	case PKCS11_CKS_RO_PUBLIC_SESSION:
		if (readonly)
			state = PKCS11_CKS_RO_PUBLIC_SESSION;
		else
			state = PKCS11_CKS_RW_PUBLIC_SESSION;
		break;
	case PKCS11_CKS_RO_USER_FUNCTIONS:
	case PKCS11_CKS_RW_USER_FUNCTIONS:
		if (readonly)
			state = PKCS11_CKS_RO_USER_FUNCTIONS;
		else
			state = PKCS11_CKS_RW_USER_FUNCTIONS;
		break;
	case PKCS11_CKS_RW_SO_FUNCTIONS:
		if (readonly)
			TEE_Panic(0);
		else
			state = PKCS11_CKS_RW_SO_FUNCTIONS;
		break;
	default:
		TEE_Panic(0);
	}

	session->state = state;
}

static void session_login_user(struct pkcs11_session *session)
{
	struct pkcs11_client *client = session->client;
	struct pkcs11_session *sess = NULL;

	TAILQ_FOREACH(sess, &client->session_list, link) {
		if (sess->token != session->token)
			continue;

		if (pkcs11_session_is_read_write(sess))
			sess->state = PKCS11_CKS_RW_USER_FUNCTIONS;
		else
			sess->state = PKCS11_CKS_RO_USER_FUNCTIONS;
	}
}

static void session_login_so(struct pkcs11_session *session)
{
	struct pkcs11_client *client = session->client;
	struct pkcs11_session *sess = NULL;

	TAILQ_FOREACH(sess, &client->session_list, link) {
		if (sess->token != session->token)
			continue;

		if (pkcs11_session_is_read_write(sess))
			sess->state = PKCS11_CKS_RW_SO_FUNCTIONS;
		else
			TEE_Panic(0);
	}
}

static void session_logout(struct pkcs11_session *session)
{
	struct pkcs11_client *client = session->client;
	struct pkcs11_session *sess = NULL;
	struct pkcs11_object *obj = NULL;

	TAILQ_FOREACH(sess, &client->session_list, link) {
		if (sess->token != session->token)
			continue;

		LIST_FOREACH(obj, &sess->object_list, link) {
			if (!object_is_private(obj->attributes))
				continue;

			destroy_object(sess, obj, true);
			handle_put(&sess->object_handle_db,
				   pkcs11_object2handle(obj, sess));
		}

		if (pkcs11_session_is_read_write(sess))
			sess->state = PKCS11_CKS_RW_PUBLIC_SESSION;
		else
			sess->state = PKCS11_CKS_RO_PUBLIC_SESSION;
	}
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
static uint32_t open_ck_session(uintptr_t tee_session, uint32_t ptypes,
				TEE_Param *params, bool readonly)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_session *session = NULL;

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(session->handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	if (!readonly && token->state == PKCS11_TOKEN_READ_ONLY)
		return PKCS11_CKR_TOKEN_WRITE_PROTECTED;

	if (readonly) {
		/* Specifically reject read-only session under SO login */
		TAILQ_FOREACH(session, &client->session_list, link)
			if (pkcs11_session_is_so(session))
				return PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS;
	}

	session = TEE_Malloc(sizeof(*session), TEE_MALLOC_FILL_ZERO);
	if (!session)
		return PKCS11_CKR_DEVICE_MEMORY;

	session->handle = handle_get(&client->session_handle_db, session);
	if (!session->handle) {
		TEE_Free(session);
		return PKCS11_CKR_DEVICE_MEMORY;
	}

	session->tee_session = tee_session;
	session->token = token;
	session->client = client;

	LIST_INIT(&session->object_list);
	handle_db_init(&session->object_handle_db);

	set_session_state(client, session, readonly);

	TAILQ_INSERT_HEAD(&client->session_list, session, link);

	session->token->session_count++;
	if (!readonly)
		session->token->rw_session_count++;

	TEE_MemMove(out->memref.buffer, &session->handle, sizeof(session->handle));
	out->memref.size = sizeof(session->handle);

	IMSG("PKCS11 session %"PRIu32": open", session->handle);

	return PKCS11_OK;
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
uint32_t entry_ck_token_ro_session(uintptr_t tee_session,
				   uint32_t ptypes, TEE_Param *params)
{
	return open_ck_session(tee_session, ptypes, params, true);
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
uint32_t entry_ck_token_rw_session(uintptr_t tee_session,
				   uint32_t ptypes, TEE_Param *params)
{
	return open_ck_session(tee_session, ptypes, params, false);
}

static void close_ck_session(struct pkcs11_session *session)
{
	release_active_processing(session);

	/* No need to put object handles, the whole database is destroyed */
	while (!LIST_EMPTY(&session->object_list))
		destroy_object(session,
			       LIST_FIRST(&session->object_list), true);

	release_session_find_obj_context(session);

	TAILQ_REMOVE(&session->client->session_list, session, link);
	handle_put(&session->client->session_handle_db, session->handle);
	handle_db_destroy(&session->object_handle_db);

	// If no more session, next opened one will simply be Public login

	session->token->session_count--;
	if (pkcs11_session_is_read_write(session))
		session->token->rw_session_count--;

	TEE_Free(session);

	IMSG("Close PKCS11 session %"PRIu32, session->handle);
}

/* ctrl=[session-handle], in=unused, out=unused */
uint32_t entry_ck_token_close_session(uintptr_t tee_session,
				      uint32_t ptypes, TEE_Param *params)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	close_ck_session(session);

	return PKCS11_CKR_OK;
}

uint32_t entry_ck_token_close_all(uintptr_t tee_session,
				  uint32_t ptypes, TEE_Param *params)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *next = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	IMSG("Close all sessions for PKCS11 token %"PRIu32, token_id);

	TAILQ_FOREACH_SAFE(session, &client->session_list, link, next)
		if (session->token == token)
			close_ck_session(session);

	return PKCS11_CKR_OK;
}

static uint32_t set_pin(struct pkcs11_session *session,
			uint8_t *new_pin, size_t new_pin_size,
			uint32_t user_type)
{
	enum pkcs11_user_type ck_user_type = user_type;
	uint32_t rv = PKCS11_CKR_GENERAL_ERROR;
	uint8_t *cpin = NULL;
	uint32_t *pin_count = NULL;
	uint32_t *pin_size = NULL;
	uint8_t *pin = NULL;
	TEE_ObjectHandle pin_key_hdl = TEE_HANDLE_NULL;
	uint32_t flags_clear = 0;
	uint32_t flags_set = 0;

	TEE_MemFill(&pin_key_hdl, 0, sizeof(pin_key_hdl));

	if (session->token->db_main->flags & PKCS11_CKFT_WRITE_PROTECTED)
		return PKCS11_CKR_TOKEN_WRITE_PROTECTED;

	if (!pkcs11_session_is_read_write(session))
		return PKCS11_CKR_SESSION_READ_ONLY;

	if (new_pin_size < PKCS11_TOKEN_PIN_SIZE_MIN ||
	    new_pin_size > PKCS11_TOKEN_PIN_SIZE_MAX)
		return PKCS11_CKR_PIN_LEN_RANGE;

	cpin = TEE_Malloc(PKCS11_TOKEN_PIN_SIZE_MAX, TEE_MALLOC_FILL_ZERO);
	if (!cpin)
		return PKCS11_MEMORY;

	switch (ck_user_type) {
	case PKCS11_CKU_SO:
		pin = session->token->db_main->so_pin;
		pin_size = &session->token->db_main->so_pin_size;
		pin_count = &session->token->db_main->so_pin_count;
		flags_clear = PKCS11_CKFT_SO_PIN_COUNT_LOW |
			      PKCS11_CKFT_SO_PIN_FINAL_TRY |
			      PKCS11_CKFT_SO_PIN_LOCKED |
			      PKCS11_CKFT_SO_PIN_TO_BE_CHANGED;
		break;
	case PKCS11_CKU_USER:
		pin = session->token->db_main->user_pin;
		pin_size = &session->token->db_main->user_pin_size;
		pin_count = &session->token->db_main->user_pin_count;
		flags_clear = PKCS11_CKFT_USER_PIN_COUNT_LOW |
			      PKCS11_CKFT_USER_PIN_FINAL_TRY |
			      PKCS11_CKFT_USER_PIN_LOCKED |
			      PKCS11_CKFT_USER_PIN_TO_BE_CHANGED;
		flags_set = PKCS11_CKFT_USER_PIN_INITIALIZED;
		break;
	default:
		rv = PKCS11_FAILED;
		goto out;
	}

	TEE_MemMove(cpin, new_pin, new_pin_size);

	// TODO: move into a single cipher_login_pin(token, user, buf, sz)
	if (open_pin_file(session->token, ck_user_type, &pin_key_hdl)) {
		rv = PKCS11_CKR_GENERAL_ERROR;
		goto out;
	}
	assert(pin_key_hdl != TEE_HANDLE_NULL);
	cipher_pin(pin_key_hdl, cpin, PKCS11_TOKEN_PIN_SIZE_MAX);
	close_pin_file(pin_key_hdl);

	TEE_MemMove(pin, cpin, PKCS11_TOKEN_PIN_SIZE_MAX);
	*pin_size = new_pin_size;
	*pin_count = 0;

	session->token->db_main->flags &= ~flags_clear;
	session->token->db_main->flags |= flags_set;

	update_persistent_db(session->token, 0,
			     sizeof(*session->token->db_main));

	rv = PKCS11_CKR_OK;

out:
	TEE_Free(cpin);

	return rv;
}

/* ctrl=[session-handle][pin-size]{pin-arrays], in=unused, out=unused */
uint32_t entry_init_pin(uintptr_t tee_session,
			uint32_t ptypes, TEE_Param *params)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;
	uint32_t pin_size = 0;
	void *pin = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_BAD_PARAM;

	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	if (!pkcs11_session_is_so(session))
		return PKCS11_CKR_USER_NOT_LOGGED_IN;

	assert(session->token->db_main->flags & PKCS11_CKFT_TOKEN_INITIALIZED);

	IMSG("PKCS11 session %"PRIu32": init PIN", session_handle);

	return set_pin(session, pin, pin_size, PKCS11_CKU_USER);
}

static uint32_t check_so_pin(struct pkcs11_session *session,
			     uint8_t *pin, size_t pin_size)
{
	TEE_ObjectHandle pin_key_hdl = TEE_HANDLE_NULL;
	struct ck_token *token = session->token;
	uint8_t *cpin = NULL;
	int pin_rc = 0;

	/* Note: intentional return code USER_PIN_NOT_INITIALIZED */
	if (!token->db_main->so_pin_size ||
	    !(token->db_main->flags & PKCS11_CKFT_TOKEN_INITIALIZED))
		return PKCS11_CKR_USER_PIN_NOT_INITIALIZED;

	if (token->db_main->flags & PKCS11_CKFT_SO_PIN_LOCKED)
		return PKCS11_CKR_PIN_LOCKED;

	cpin = TEE_Malloc(PKCS11_TOKEN_PIN_SIZE_MAX, TEE_MALLOC_FILL_ZERO);
	if (!cpin)
		return PKCS11_MEMORY;

	TEE_MemMove(cpin, pin, pin_size);

	// TODO: move into a single cipher_login_pin(token, user, buf, sz)
	open_pin_file(token, PKCS11_CKU_SO, &pin_key_hdl);
	cipher_pin(pin_key_hdl, cpin, PKCS11_TOKEN_PIN_SIZE_MAX);
	close_pin_file(pin_key_hdl);

	pin_rc = 0;

	if (token->db_main->so_pin_size != pin_size)
		pin_rc = 1;

	if (buf_compare_ct(token->db_main->so_pin, cpin,
			   PKCS11_TOKEN_PIN_SIZE_MAX))
		pin_rc = 1;

	TEE_Free(cpin);

	if (pin_rc) {
		token->db_main->flags |= PKCS11_CKFT_SO_PIN_COUNT_LOW;
		token->db_main->so_pin_count++;

		if (token->db_main->so_pin_count == 6)
			token->db_main->flags |= PKCS11_CKFT_SO_PIN_FINAL_TRY;
		if (token->db_main->so_pin_count == 7)
			token->db_main->flags |= PKCS11_CKFT_SO_PIN_LOCKED;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      flags),
				     sizeof(token->db_main->flags));

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin_count),
				     sizeof(token->db_main->so_pin_count));

		if (token->db_main->flags & PKCS11_CKFT_SO_PIN_LOCKED)
			return PKCS11_CKR_PIN_LOCKED;

		return PKCS11_CKR_PIN_INCORRECT;
	}

	if (token->db_main->so_pin_count) {
		token->db_main->so_pin_count = 0;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin_count),
				     sizeof(token->db_main->so_pin_count));
	}

	if (token->db_main->flags & (PKCS11_CKFT_SO_PIN_COUNT_LOW |
					PKCS11_CKFT_SO_PIN_FINAL_TRY)) {
		token->db_main->flags &= ~(PKCS11_CKFT_SO_PIN_COUNT_LOW |
					   PKCS11_CKFT_SO_PIN_FINAL_TRY);

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      flags),
				     sizeof(token->db_main->flags));
	}

	return PKCS11_OK;
}

static uint32_t check_user_pin(struct pkcs11_session *session,
				uint8_t *pin, size_t pin_size)
{
	TEE_ObjectHandle pin_key_hdl = TEE_HANDLE_NULL;
	struct ck_token *token = session->token;
	uint8_t *cpin = NULL;
	int pin_rc = 0;

	if (!token->db_main->user_pin_size ||
	    !(token->db_main->flags & PKCS11_CKFT_USER_PIN_INITIALIZED))
		return PKCS11_CKR_USER_PIN_NOT_INITIALIZED;

	if (token->db_main->flags & PKCS11_CKFT_USER_PIN_LOCKED)
		return PKCS11_CKR_PIN_LOCKED;

	cpin = TEE_Malloc(PKCS11_TOKEN_PIN_SIZE_MAX, TEE_MALLOC_FILL_ZERO);
	if (!cpin)
		return PKCS11_MEMORY;

	TEE_MemMove(cpin, pin, pin_size);

	// TODO: move into a single cipher_login_pin(token, user, buf, sz)
	open_pin_file(token, PKCS11_CKU_USER, &pin_key_hdl);
	cipher_pin(pin_key_hdl, cpin, PKCS11_TOKEN_PIN_SIZE_MAX);
	close_pin_file(pin_key_hdl);

	pin_rc = 0;

	if (token->db_main->user_pin_size != pin_size)
		pin_rc = 1;

	if (buf_compare_ct(token->db_main->user_pin, cpin,
			   PKCS11_TOKEN_PIN_SIZE_MAX))
		pin_rc = 1;

	TEE_Free(cpin);

	if (pin_rc) {
		token->db_main->flags |= PKCS11_CKFT_USER_PIN_COUNT_LOW;
		token->db_main->user_pin_count++;

		if (token->db_main->user_pin_count == 6)
			token->db_main->flags |= PKCS11_CKFT_USER_PIN_FINAL_TRY;
		if (token->db_main->user_pin_count == 7)
			token->db_main->flags |= PKCS11_CKFT_USER_PIN_LOCKED;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      flags),
				     sizeof(token->db_main->flags));

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      user_pin_count),
				     sizeof(token->db_main->user_pin_count));

		if (token->db_main->flags & PKCS11_CKFT_USER_PIN_LOCKED)
			return PKCS11_CKR_PIN_LOCKED;

		return PKCS11_CKR_PIN_INCORRECT;
	}

	if (token->db_main->user_pin_count) {
		token->db_main->user_pin_count = 0;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      user_pin_count),
				     sizeof(token->db_main->user_pin_count));
	}

	if (token->db_main->flags & (PKCS11_CKFT_USER_PIN_COUNT_LOW |
				     PKCS11_CKFT_USER_PIN_FINAL_TRY)) {
		token->db_main->flags &= ~(PKCS11_CKFT_USER_PIN_COUNT_LOW |
					   PKCS11_CKFT_USER_PIN_FINAL_TRY);

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      flags),
				     sizeof(token->db_main->flags));
	}

	return PKCS11_OK;
}

/* ctrl=[session][old-size]{old-pin][pin-size]{pin], in=unused, out=unused */
uint32_t entry_set_pin(uintptr_t tee_session,
		       uint32_t ptypes, TEE_Param *params)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;
	uint32_t old_pin_size = 0;
	uint32_t pin_size = 0;
	void *old_pin = NULL;
	void *pin = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &old_pin_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&ctrlargs, &old_pin, old_pin_size);
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_BAD_PARAM;

	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	if (!pkcs11_session_is_read_write(session))
		return PKCS11_CKR_SESSION_READ_ONLY;

	if (pkcs11_session_is_so(session)) {
		if (!(session->token->db_main->flags &
		      PKCS11_CKFT_TOKEN_INITIALIZED))
			return PKCS11_ERROR;

		rv = check_so_pin(session, old_pin, old_pin_size);
		if (rv)
			return rv;

		return set_pin(session, pin, pin_size, PKCS11_CKU_SO);
	}

	if (!(session->token->db_main->flags &
	      PKCS11_CKFT_USER_PIN_INITIALIZED))
		return PKCS11_ERROR;

	rv = check_user_pin(session, old_pin, old_pin_size);
	if (rv)
		return rv;

	IMSG("PKCS11 session %"PRIu32": set PIN", session_handle);

	return set_pin(session, pin, pin_size, PKCS11_CKU_USER);
}

/* ctrl=[session][user_type][pin-size]{pin], in=unused, out=unused */
uint32_t entry_login(uintptr_t tee_session, uint32_t ptypes, TEE_Param *params)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *sess = NULL;
	uint32_t user_type = 0;
	uint32_t pin_size = 0;
	void *pin = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &user_type, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_BAD_PARAM;

	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	switch ((enum pkcs11_user_type)user_type) {
	case PKCS11_CKU_SO:
		if (pkcs11_session_is_so(session))
			return PKCS11_CKR_USER_ALREADY_LOGGED_IN;

		if (pkcs11_session_is_user(session))
			return PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

		TAILQ_FOREACH(sess, &client->session_list, link)
			if (sess->token == session->token &&
			    !pkcs11_session_is_read_write(sess))
				return PKCS11_CKR_SESSION_READ_ONLY_EXISTS;

		TAILQ_FOREACH(client, &pkcs11_client_list, link) {
			TAILQ_FOREACH(sess, &client->session_list, link) {
				if (sess->token == session->token &&
				    !pkcs11_session_is_public(sess))
					return PKCS11_CKR_USER_TOO_MANY_TYPES;
			}
		}

		rv = check_so_pin(session, pin, pin_size);
		if (rv == PKCS11_OK)
			session_login_so(session);

		break;

	case PKCS11_CKU_USER:
		if (pkcs11_session_is_so(session))
			return PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

		if (pkcs11_session_is_user(session))
			return PKCS11_CKR_USER_ALREADY_LOGGED_IN;

		// TODO: check all client: if SO or user logged, we can return
		// CKR_USER_TOO_MANY_TYPES.

		rv = check_user_pin(session, pin, pin_size);
		if (rv == PKCS11_OK)
			session_login_user(session);

		break;

	case PKCS11_CKU_CONTEXT_SPECIFIC:
		if (!session_is_active(session) ||
		    !session->processing->always_authen)
			return PKCS11_CKR_OPERATION_NOT_INITIALIZED;

		if (pkcs11_session_is_public(session))
			return PKCS11_CKR_FUNCTION_FAILED;

		assert(pkcs11_session_is_user(session) ||
			pkcs11_session_is_so(session));

		if (pkcs11_session_is_so(session))
			rv = check_so_pin(session, pin, pin_size);
		else
			rv = check_user_pin(session, pin, pin_size);

		session->processing->relogged = (rv == PKCS11_OK);

		if (rv == PKCS11_CKR_PIN_LOCKED)
			session_logout(session);

		break;

	default:
		return PKCS11_CKR_USER_TYPE_INVALID;
	}

	if (!rv)
		IMSG("PKCS11 session %"PRIu32": login", session_handle);

	return rv;
}

/* ctrl=[session], in=unused, out=unused */
uint32_t entry_logout(uintptr_t tee_session, uint32_t ptypes, TEE_Param *params)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_BAD_PARAM;

	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	if (pkcs11_session_is_public(session))
		return PKCS11_CKR_USER_NOT_LOGGED_IN;

	session_logout(session);

	IMSG("PKCS11 session %"PRIu32": logout", session_handle);

	return PKCS11_OK;
}
