// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <pkcs11_internal_abi.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>
#include <util.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_token.h"
#include "pkcs11_attributes.h"
#include "processing.h"
#include "serializer.h"
#include "pkcs11_helpers.h"

bool processing_is_tee_symm(uint32_t proc_id)
{
	switch (proc_id) {
	/* Authentication */
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_AES_XCBC_MAC:
	/* Cipherering */
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
	case PKCS11_CKM_AES_CCM:
	case PKCS11_CKM_AES_GCM:
		return true;
	default:
		return false;
	}
}

static uint32_t pkcs2tee_algorithm(uint32_t *tee_id,
			      struct pkcs11_attribute_head *proc_params)
{
	static const uint32_t pkcs2tee_algo[][2] = {
		/* AES flavors */
		{ PKCS11_CKM_AES_ECB, TEE_ALG_AES_ECB_NOPAD },
		{ PKCS11_CKM_AES_CBC, TEE_ALG_AES_CBC_NOPAD },
		{ PKCS11_CKM_AES_CBC_PAD, TEE_ALG_AES_CBC_NOPAD }, // TODO
		{ PKCS11_CKM_AES_CTR, TEE_ALG_AES_CTR },
		{ PKCS11_CKM_AES_CTS, TEE_ALG_AES_CTS },
		{ PKCS11_CKM_AES_CCM, TEE_ALG_AES_CCM },
		{ PKCS11_CKM_AES_GCM, TEE_ALG_AES_GCM },
		{ PKCS11_CKM_AES_CMAC, TEE_ALG_AES_CMAC },
		{ PKCS11_CKM_AES_CMAC_GENERAL, TEE_ALG_AES_CMAC },
		{ PKCS11_CKM_AES_XCBC_MAC, TEE_ALG_AES_CBC_MAC_NOPAD },
		/* HMAC flavors */
		{ PKCS11_CKM_MD5_HMAC, TEE_ALG_HMAC_MD5 },
		{ PKCS11_CKM_SHA_1_HMAC, TEE_ALG_HMAC_SHA1 },
		{ PKCS11_CKM_SHA224_HMAC, TEE_ALG_HMAC_SHA224 },
		{ PKCS11_CKM_SHA256_HMAC, TEE_ALG_HMAC_SHA256 },
		{ PKCS11_CKM_SHA384_HMAC, TEE_ALG_HMAC_SHA384 },
		{ PKCS11_CKM_SHA512_HMAC, TEE_ALG_HMAC_SHA512 },
	};
	size_t end = sizeof(pkcs2tee_algo) / (2 * sizeof(uint32_t));
	size_t n = 0;

	for (n = 0; n < end; n++) {
		if (proc_params->id == pkcs2tee_algo[n][0]) {
			*tee_id = pkcs2tee_algo[n][1];
			break;
		}
	}

	if (n == end)
		return PKCS11_RV_NOT_IMPLEMENTED;

	return PKCS11_CKR_OK;
}

static uint32_t pkcs2tee_key_type(uint32_t *tee_type, struct pkcs11_object *obj)
{
	static const uint32_t pkcs2tee_key_type[][2] = {
		{ PKCS11_CKK_AES, TEE_TYPE_AES },
		{ PKCS11_CKK_GENERIC_SECRET, TEE_TYPE_GENERIC_SECRET },
		{ PKCS11_CKK_MD5_HMAC, TEE_TYPE_HMAC_MD5 },
		{ PKCS11_CKK_SHA_1_HMAC, TEE_TYPE_HMAC_SHA1 },
		{ PKCS11_CKK_SHA224_HMAC, TEE_TYPE_HMAC_SHA224 },
		{ PKCS11_CKK_SHA256_HMAC, TEE_TYPE_HMAC_SHA256 },
		{ PKCS11_CKK_SHA384_HMAC, TEE_TYPE_HMAC_SHA384 },
		{ PKCS11_CKK_SHA512_HMAC, TEE_TYPE_HMAC_SHA512 },
	};
	const size_t last = sizeof(pkcs2tee_key_type) / (2 * sizeof(uint32_t));
	size_t n = 0;
	enum pkcs11_key_type type = get_type(obj->attributes);

	assert(get_class(obj->attributes) == PKCS11_CKO_SECRET_KEY);

	for (n = 0; n < last; n++) {
		if (pkcs2tee_key_type[n][0] == type) {
			*tee_type = pkcs2tee_key_type[n][1];
			return PKCS11_CKR_OK;
		}
	}

	return PKCS11_RV_NOT_FOUND;
}

static uint32_t allocate_tee_operation(struct pkcs11_session *session,
					enum processing_func function,
					struct pkcs11_attribute_head *params,
					struct pkcs11_object *obj)
{
	uint32_t size = (uint32_t)get_object_key_bit_size(obj);
	uint32_t algo = 0;
	uint32_t mode = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(session->processing->tee_op_handle == TEE_HANDLE_NULL);

	if (pkcs2tee_algorithm(&algo, params))
		return PKCS11_CKR_FUNCTION_FAILED;

	/* Sign/Verify with AES or generic key relate to TEE MAC operation */
	switch (params->id) {
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_AES_XCBC_MAC:
		mode = TEE_MODE_MAC;
		break;
	default:
		pkcs2tee_mode(&mode, function);
		break;
	}

	res = TEE_AllocateOperation(&session->processing->tee_op_handle,
				    algo, mode, size);
	if (res)
		EMSG("TEE_AllocateOp. failed %#"PRIx32" %#"PRIx32" %#"PRIx32,
		     algo, mode, size);

	if (res == TEE_ERROR_NOT_SUPPORTED)
		return PKCS11_CKR_MECHANISM_INVALID;

	return tee2pkcs_error(res);
}

static uint32_t load_tee_key(struct pkcs11_session *session,
				struct pkcs11_object *obj)
{
	TEE_Attribute tee_attr;
	size_t object_size = 0;
	uint32_t key_type = 0;
	uint32_t rv = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_MemFill(&tee_attr, 0, sizeof(tee_attr));

	if (obj->key_handle != TEE_HANDLE_NULL) {
		/* Key was already loaded and fits current need */
		goto key_ready;
	}

	if (!pkcs2tee_load_attr(&tee_attr, TEE_ATTR_SECRET_VALUE,
			       obj, PKCS11_CKA_VALUE)) {
		EMSG("No secret found");
		return PKCS11_CKR_FUNCTION_FAILED;
	}

	rv = pkcs2tee_key_type(&key_type, obj);
	if (rv)
		return rv;

	object_size = get_object_key_bit_size(obj);
	if (!object_size)
		return PKCS11_CKR_GENERAL_ERROR;

	res = TEE_AllocateTransientObject(key_type, object_size,
					  &obj->key_handle);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed, %#"PRIx32, res);
		return tee2pkcs_error(res);
	}

	res = TEE_PopulateTransientObject(obj->key_handle, &tee_attr, 1);
	if (res) {
		DMSG("TEE_PopulateTransientObject failed, %#"PRIx32, res);
		goto error;
	}

key_ready:
	res = TEE_SetOperationKey(session->processing->tee_op_handle,
				  obj->key_handle);
	if (res) {
		DMSG("TEE_SetOperationKey failed, %#"PRIx32, res);
		goto error;
	}

	return tee2pkcs_error(res);

error:
	TEE_FreeTransientObject(obj->key_handle);
	obj->key_handle = TEE_HANDLE_NULL;

	return tee2pkcs_error(res);
}

static uint32_t init_tee_operation(struct pkcs11_session *session,
				   struct pkcs11_attribute_head *proc_params)
{
	uint32_t rv = PKCS11_CKR_GENERAL_ERROR;

	switch (proc_params->id) {
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_AES_XCBC_MAC:
		if (proc_params->size)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;

		TEE_MACInit(session->processing->tee_op_handle, NULL, 0);
		rv = PKCS11_CKR_OK;
		break;
	case PKCS11_CKM_AES_ECB:
		if (proc_params->size)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;

		TEE_CipherInit(session->processing->tee_op_handle, NULL, 0);
		rv = PKCS11_CKR_OK;
		break;
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
		if (proc_params->size != 16)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;

		TEE_CipherInit(session->processing->tee_op_handle,
			       proc_params->data, 16);
		rv = PKCS11_CKR_OK;
		break;
	case PKCS11_CKM_AES_CTR:
		rv = tee_init_ctr_operation(session->processing,
					    proc_params->data,
					    proc_params->size);
		break;
	case PKCS11_CKM_AES_CCM:
		rv = tee_init_ccm_operation(session->processing,
					    proc_params->data,
					    proc_params->size);
		break;
	case PKCS11_CKM_AES_GCM:
		rv = tee_init_gcm_operation(session->processing,
					    proc_params->data,
					    proc_params->size);
		break;
	default:
		TEE_Panic(proc_params->id);
		break;
	}

	return rv;
}

uint32_t init_symm_operation(struct pkcs11_session *session,
				enum processing_func function,
				struct pkcs11_attribute_head *proc_params,
				struct pkcs11_object *obj)
{
	uint32_t rv = 0;

	assert(processing_is_tee_symm(proc_params->id));

	rv = allocate_tee_operation(session, function, proc_params, obj);
	if (rv)
		return rv;

	rv = load_tee_key(session, obj);
	if (rv)
		return rv;

	return init_tee_operation(session, proc_params);
}

/* Validate input buffer size as per PKCS#11 constraints */
static uint32_t input_data_size_is_valid(struct active_processing *proc,
					 enum processing_func function,
					 size_t in_size)
{
	switch (proc->mecha_type) {
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
		if (function == PKCS11_FUNCTION_ENCRYPT &&
		    in_size % TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_DATA_LEN_RANGE;
		if (function == PKCS11_FUNCTION_DECRYPT &&
		    in_size % TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE;
		break;
	case PKCS11_CKM_AES_CBC_PAD:
		if (function == PKCS11_FUNCTION_DECRYPT &&
		    in_size % TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE;
		break;
	case PKCS11_CKM_AES_CTS:
		if (function == PKCS11_FUNCTION_ENCRYPT &&
		    in_size < TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_DATA_LEN_RANGE;
		if (function == PKCS11_FUNCTION_DECRYPT &&
		    in_size < TEE_AES_BLOCK_SIZE)
			return PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE;
		break;
	default:
		break;
	}

	return PKCS11_CKR_OK;
}

/*
 * step_sym_cipher - processing symmetric (and related) cipher operation step
 *
 * @session - current session
 * @function - processing function (encrypt, decrypt, sign, ...)
 * @step - step ID in the processing (oneshot, update, final)
 * @ptype - invocation parameter types
 * @params - invocation parameter references
 */
uint32_t step_symm_operation(struct pkcs11_session *session,
			     enum processing_func function,
			     enum processing_step step,
			     uint32_t ptypes, TEE_Param *params)
{
	uint32_t rv = PKCS11_CKR_GENERAL_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	void *in_buf = NULL;
	size_t in_size = 0;
	void *out_buf = NULL;
	uint32_t out_size = 0;
	uint32_t out_size2 = out_size;
	void *in2_buf = NULL;
	uint32_t in2_size = 0;
	bool output_data = false;
	struct active_processing *proc = session->processing;

	if (TEE_PARAM_TYPE_GET(ptypes, 1) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		in_buf = params[1].memref.buffer;
		in_size = params[1].memref.size;
		if (in_size && !in_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		in2_buf = params[2].memref.buffer;
		in2_size = params[2].memref.size;
		if (in2_size && !in2_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		out_buf = params[2].memref.buffer;
		out_size = params[2].memref.size;
		out_size2 = out_size;
		if (out_size && !out_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 3) != TEE_PARAM_TYPE_NONE)
			return PKCS11_CKR_ARGUMENTS_BAD;

	switch (step) {
	case PKCS11_FUNC_STEP_ONESHOT:
	case PKCS11_FUNC_STEP_UPDATE:
	case PKCS11_FUNC_STEP_FINAL:
		break;
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (step != PKCS11_FUNC_STEP_FINAL) {
		rv = input_data_size_is_valid(proc, function, in_size);
		if (rv)
			return rv;
	}

	/*
	 * Feed active operation with with data
	 * (PKCS11_FUNC_STEP_UPDATE/_ONESHOT)
	 */
	switch (proc->mecha_type) {
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_AES_XCBC_MAC:
		if (step == PKCS11_FUNC_STEP_FINAL)
			break;

		if (!in_buf) {
			DMSG("No input data");
			return PKCS11_CKR_ARGUMENTS_BAD;
		}

		switch (function) {
		case PKCS11_FUNCTION_SIGN:
		case PKCS11_FUNCTION_VERIFY:
			TEE_MACUpdate(proc->tee_op_handle, in_buf, in_size);
			rv = PKCS11_CKR_OK;
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
		if (step == PKCS11_FUNC_STEP_FINAL ||
		    step == PKCS11_FUNC_STEP_ONESHOT)
			break;

		if (!in_buf) {
			EMSG("No input data");
			return PKCS11_CKR_ARGUMENTS_BAD;
		}

		switch (function) {
		case PKCS11_FUNCTION_ENCRYPT:
		case PKCS11_FUNCTION_DECRYPT:
			res = TEE_CipherUpdate(proc->tee_op_handle,
						in_buf, in_size,
						out_buf, &out_size);
			output_data = true;
			rv = tee2pkcs_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case PKCS11_CKM_AES_CCM:
	case PKCS11_CKM_AES_GCM:
		if (step == PKCS11_FUNC_STEP_FINAL)
			break;

		if (!in_buf) {
			EMSG("No input data");
			return PKCS11_CKR_ARGUMENTS_BAD;
		}

		switch (function) {
		case PKCS11_FUNCTION_ENCRYPT:
			res = TEE_AEUpdate(proc->tee_op_handle,
					   in_buf, in_size, out_buf, &out_size);
			output_data = true;
			rv = tee2pkcs_error(res);

			if (step == PKCS11_FUNC_STEP_ONESHOT &&
			    (rv == PKCS11_CKR_OK ||
			     rv == PKCS11_CKR_BUFFER_TOO_SMALL)) {
				out_buf = (char *)out_buf + out_size;
				out_size2 -= out_size;
			}
			break;
		case PKCS11_FUNCTION_DECRYPT:
			rv = tee_ae_decrypt_update(proc, in_buf, in_size);
			out_size = 0;
			output_data = true;
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;
	default:
		TEE_Panic(proc->mecha_type);
		break;
	}

	if (step == PKCS11_FUNC_STEP_UPDATE)
		goto bail;

	/*
	 * Finalize (PKCS11_FUNC_STEP_ONESHOT/_FINAL) operation
	 */
	switch (session->processing->mecha_type) {
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
	case PKCS11_CKM_AES_XCBC_MAC:
		switch (function) {
		case PKCS11_FUNCTION_SIGN:
			res = TEE_MACComputeFinal(proc->tee_op_handle,
						  NULL, 0, out_buf, &out_size);
			output_data = true;
			rv = tee2pkcs_error(res);
			break;
		case PKCS11_FUNCTION_VERIFY:
			res = TEE_MACCompareFinal(proc->tee_op_handle,
						  NULL, 0, in2_buf, in2_size);
			rv = tee2pkcs_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
		if (step == PKCS11_FUNC_STEP_ONESHOT && !in_buf) {
			EMSG("No input data");
			return PKCS11_CKR_ARGUMENTS_BAD;
		}

		switch (function) {
		case PKCS11_FUNCTION_ENCRYPT:
		case PKCS11_FUNCTION_DECRYPT:
			res = TEE_CipherDoFinal(proc->tee_op_handle,
						in_buf, in_size,
						out_buf, &out_size);
			output_data = true;
			rv = tee2pkcs_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case PKCS11_CKM_AES_CCM:
	case PKCS11_CKM_AES_GCM:
		switch (function) {
		case PKCS11_FUNCTION_ENCRYPT:
			rv = tee_ae_encrypt_final(proc, out_buf, &out_size2);
			output_data = true;

			/*
			 * FIXME: on failure & ONESHOT, restore operation state
			 * before TEE_AEUpdate() was called
			 */
			if (step == PKCS11_FUNC_STEP_ONESHOT) {
				out_size += out_size2;
			} else {
				out_size = out_size2;
			}
			break;
		case PKCS11_FUNCTION_DECRYPT:
			rv = tee_ae_decrypt_final(proc, out_buf, &out_size);
			output_data = true;
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;
	default:
		TEE_Panic(proc->mecha_type);
		break;
	}

bail:
	if (output_data &&
	    (rv == PKCS11_CKR_OK || rv == PKCS11_CKR_BUFFER_TOO_SMALL)) {
		switch (TEE_PARAM_TYPE_GET(ptypes, 2)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[2].memref.size = out_size;
			break;
		default:
			rv = PKCS11_CKR_GENERAL_ERROR;
			break;
		}
	}

	return rv;
}

uint32_t do_symm_derivation(struct pkcs11_session *session __unused,
			     struct pkcs11_attribute_head *proc_params __unused,
			     struct pkcs11_object *parent_key __unused,
			     struct pkcs11_attrs_head **head __unused)
{
	EMSG("Symm key derivation not yet supported");

	return PKCS11_CKR_GENERAL_ERROR;
}
