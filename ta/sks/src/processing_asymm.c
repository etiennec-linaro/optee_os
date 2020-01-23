// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"
#include "pkcs11_helpers.h"

bool processing_is_tee_asymm(uint32_t proc_id)
{
	switch (proc_id) {
	/* RSA flavors */
	case PKCS11_CKM_RSA_PKCS:
	case PKCS11_CKM_RSA_PKCS_OAEP:
	case PKCS11_CKM_SHA1_RSA_PKCS:
	case PKCS11_CKM_SHA224_RSA_PKCS:
	case PKCS11_CKM_SHA256_RSA_PKCS:
	case PKCS11_CKM_SHA384_RSA_PKCS:
	case PKCS11_CKM_SHA512_RSA_PKCS:
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
	/* EC flavors */
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
	case PKCS11_CKM_ECDH1_DERIVE:
	case PKCS11_CKM_ECDH1_COFACTOR_DERIVE:
		return true;
	default:
		return false;
	}
}

static uint32_t pkcs2tee_algorithm(uint32_t *tee_id,
				  enum processing_func function,
				  struct pkcs11_attribute_head *proc_params,
				  struct pkcs11_object *obj)
{
	static const uint32_t pkcs2tee_algo[][2] = {
		/* RSA flavors */
		{ PKCS11_CKM_RSA_PKCS, TEE_ALG_RSAES_PKCS1_V1_5
				/* TEE_ALG_RSASSA_PKCS1_V1_5 on signatures */ },
		{ PKCS11_CKM_RSA_PKCS_OAEP, 1 }, /* Need to look into params */
		{ PKCS11_CKM_SHA1_RSA_PKCS, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1 },
		{ PKCS11_CKM_SHA224_RSA_PKCS,
					TEE_ALG_RSASSA_PKCS1_V1_5_SHA224 },
		{ PKCS11_CKM_SHA256_RSA_PKCS,
					TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 },
		{ PKCS11_CKM_SHA384_RSA_PKCS,
					TEE_ALG_RSASSA_PKCS1_V1_5_SHA384 },
		{ PKCS11_CKM_SHA512_RSA_PKCS,
					TEE_ALG_RSASSA_PKCS1_V1_5_SHA512 },
		{ PKCS11_CKM_SHA1_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 },
		{ PKCS11_CKM_SHA224_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 },
		{ PKCS11_CKM_SHA256_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 },
		{ PKCS11_CKM_SHA384_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 },
		{ PKCS11_CKM_SHA512_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 },
		/* EC flavors (Must find key size from the object) */
		{ PKCS11_CKM_ECDSA, 1 },
		{ PKCS11_CKM_ECDSA_SHA1, 1 },
		{ PKCS11_CKM_ECDSA_SHA224, 1 },
		{ PKCS11_CKM_ECDSA_SHA256, 1 },
		{ PKCS11_CKM_ECDSA_SHA384, 1 },
		{ PKCS11_CKM_ECDSA_SHA512, 1 },
		{ PKCS11_CKM_ECDH1_DERIVE, 1 },
		{ PKCS11_CKM_ECDH1_COFACTOR_DERIVE, 1 },
	};
	size_t end = sizeof(pkcs2tee_algo) / (2 * sizeof(uint32_t));
	size_t n = 0;
	uint32_t rv = 0;

	for (n = 0; n < end; n++) {
		if (proc_params->id == pkcs2tee_algo[n][0]) {
			*tee_id = pkcs2tee_algo[n][1];
			break;
		}
	}

	switch (proc_params->id) {
	case PKCS11_CKM_RSA_X_509:
	case PKCS11_CKM_RSA_9796:
	case PKCS11_CKM_RSA_PKCS_PSS:
		EMSG("%s not supported by GPD TEE, need an alternative...",
		     id2str_proc(proc_params->id));
		break;
	default:
		break;
	}

	if (n == end)
		return PKCS11_NOT_IMPLEMENTED;

	switch (proc_params->id) {
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
		rv = pkcs2tee_algo_rsa_pss(tee_id, proc_params);
		break;
	case PKCS11_CKM_RSA_PKCS_OAEP:
		rv = pkcs2tee_algo_rsa_oaep(tee_id, proc_params);
		break;
	case PKCS11_CKM_ECDH1_DERIVE:
		rv = pkcs2tee_algo_ecdh(tee_id, proc_params, obj);
		break;
	case PKCS11_CKM_ECDH1_COFACTOR_DERIVE:
		return PKCS11_NOT_IMPLEMENTED;
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
		rv = pkcs2tee_algo_ecdsa(tee_id, proc_params, obj);
		break;
	default:
		rv = PKCS11_OK;
		break;
	}

	if (*tee_id == TEE_ALG_RSAES_PKCS1_V1_5 &&
	    (function == PKCS11_FUNCTION_SIGN ||
	     function == PKCS11_FUNCTION_VERIFY))
		*tee_id = TEE_ALG_RSASSA_PKCS1_V1_5;

	return rv;
}

static uint32_t pkcs2tee_key_type(uint32_t *tee_type, struct pkcs11_object *obj,
				 enum processing_func function)
{
	enum pkcs11_class_id class = get_class(obj->attributes);
	enum pkcs11_key_type type = get_type(obj->attributes);

	switch (class) {
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		break;
	default:
		TEE_Panic(class);
		break;
	}

	switch (type) {
	case PKCS11_CKK_EC:
		if (class == PKCS11_CKO_PRIVATE_KEY)
			*tee_type = (function == PKCS11_FUNCTION_DERIVE) ?
					TEE_TYPE_ECDH_KEYPAIR :
					TEE_TYPE_ECDSA_KEYPAIR;
		else
			*tee_type = (function == PKCS11_FUNCTION_DERIVE) ?
					TEE_TYPE_ECDH_PUBLIC_KEY :
					TEE_TYPE_ECDSA_PUBLIC_KEY;
		break;
	case PKCS11_CKK_RSA:
		if (class == PKCS11_CKO_PRIVATE_KEY)
			*tee_type = TEE_TYPE_RSA_KEYPAIR;
		else
			*tee_type = TEE_TYPE_RSA_PUBLIC_KEY;
		break;
	default:
		TEE_Panic(type);
		break;
	}

	return PKCS11_OK;
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

	if (pkcs2tee_algorithm(&algo, function, params, obj))
		return PKCS11_FAILED;

	pkcs2tee_mode(&mode, function);

	res = TEE_AllocateOperation(&session->processing->tee_op_handle,
				    algo, mode, size);
	if (res)
		EMSG("TEE_AllocateOp. failed %"PRIx32" %"PRIx32" %"PRIx32,
		     algo, mode, size);

	return tee2pkcs_error(res);
}

static uint32_t load_tee_key(struct pkcs11_session *session,
				struct pkcs11_object *obj,
				enum processing_func function)
{
	TEE_Attribute *tee_attrs = NULL;
	size_t tee_attrs_count = 0;
	size_t object_size = 0;
	uint32_t rv = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	enum pkcs11_class_id __maybe_unused class = get_class(obj->attributes);
	enum pkcs11_key_type type = get_type(obj->attributes);

	assert(class == PKCS11_CKO_PUBLIC_KEY ||
	       class == PKCS11_CKO_PRIVATE_KEY);

	if (obj->key_handle != TEE_HANDLE_NULL) {
		switch (type) {
		case PKCS11_CKK_RSA:
			/* RSA loaded keys can be reused */
			assert((obj->key_type == TEE_TYPE_RSA_PUBLIC_KEY &&
				class == PKCS11_CKO_PUBLIC_KEY) ||
			       (obj->key_type == TEE_TYPE_RSA_KEYPAIR &&
				class == PKCS11_CKO_PRIVATE_KEY));
			goto key_ready;
		case PKCS11_CKK_EC:
			/* Reuse EC TEE key only if already DSA or DH */
			switch (obj->key_type) {
			case TEE_TYPE_ECDSA_PUBLIC_KEY:
			case TEE_TYPE_ECDSA_KEYPAIR:
				if (function != PKCS11_FUNCTION_DERIVE)
					goto key_ready;
				break;
			case TEE_TYPE_ECDH_PUBLIC_KEY:
			case TEE_TYPE_ECDH_KEYPAIR:
				if (function == PKCS11_FUNCTION_DERIVE)
					goto key_ready;
				break;
			default:
				assert(0);
				break;
			}
			break;
		default:
			assert(0);
			break;
		}

		TEE_CloseObject(obj->key_handle);
		obj->key_handle = TEE_HANDLE_NULL;
	}

	rv = pkcs2tee_key_type(&obj->key_type, obj, function);
	if (rv)
		return rv;

	object_size = get_object_key_bit_size(obj);
	if (!object_size)
		return PKCS11_ERROR;

	switch (type) {
	case PKCS11_CKK_RSA:
		rv = load_tee_rsa_key_attrs(&tee_attrs, &tee_attrs_count, obj);
		break;
	case PKCS11_CKK_EC:
		rv = load_tee_ec_key_attrs(&tee_attrs, &tee_attrs_count, obj);
		break;
	default:
		break;
	}
	if (rv)
		return rv;

	res = TEE_AllocateTransientObject(obj->key_type, object_size,
					  &obj->key_handle);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed, 0x%"PRIx32, res);

		return tee2pkcs_error(res);
	}

	res = TEE_PopulateTransientObject(obj->key_handle,
					  tee_attrs, tee_attrs_count);

	TEE_Free(tee_attrs);

	if (res) {
		DMSG("TEE_PopulateTransientObject failed, 0x%"PRIx32, res);

		goto error;
	}

key_ready:
	res = TEE_SetOperationKey(session->processing->tee_op_handle,
				  obj->key_handle);
	if (res) {
		DMSG("TEE_SetOperationKey failed, 0x%"PRIx32, res);

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
	uint32_t rv = PKCS11_OK;

	switch (proc_params->id) {
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
		rv = pkcs2tee_proc_params_rsa_pss(session->processing,
						 proc_params);
		break;
	default:
		break;
	}

	return rv;
}

uint32_t init_asymm_operation(struct pkcs11_session *session,
				enum processing_func function,
				struct pkcs11_attribute_head *proc_params,
				struct pkcs11_object *obj)
{
	uint32_t rv = 0;

	assert(processing_is_tee_asymm(proc_params->id));

	rv = allocate_tee_operation(session, function, proc_params, obj);
	if (rv)
		return rv;

	rv = load_tee_key(session, obj, function);
	if (rv)
		return rv;

	return init_tee_operation(session, proc_params);
}

/*
 * step_sym_step - step (update/oneshot/final) on a symmetric crypto operation
 *
 * @session - current session
 * @function -
 * @step - step ID in the processing (oneshot, update,final)
 * @in - input data reference #1
 * @io2 - input/output data reference #2 (direction depends on function)
 */
uint32_t step_asymm_operation(struct pkcs11_session *session,
			      enum processing_func function,
			      enum processing_step step,
			      TEE_Param *in, TEE_Param *io2)
{
	uint32_t rv = PKCS11_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	void *in_buf = in ? in->memref.buffer : NULL;
	size_t in_size = in ? in->memref.size : 0;
	void *out_buf = io2 ? io2->memref.buffer : NULL;
	uint32_t out_size = io2 ? io2->memref.size : 0;
	void *in2_buf = io2 ? io2->memref.buffer : NULL;
	uint32_t in2_size = io2 ? io2->memref.size : 0;
	TEE_Attribute *tee_attrs = NULL;
	size_t tee_attrs_count = 0;
	uint32_t data32 = 0;
	bool output_data = false;
	struct active_processing *proc = session->processing;

	switch (step) {
	case PKCS11_FUNC_STEP_ONESHOT:
	case PKCS11_FUNC_STEP_UPDATE:
	case PKCS11_FUNC_STEP_FINAL:
		break;
	default:
		return PKCS11_ERROR;
	}

	/* TEE attribute(s) required by the operation */
	switch (proc->mecha_type) {
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
		tee_attrs = TEE_Malloc(sizeof(TEE_Attribute),
					TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!tee_attrs) {
			rv = PKCS11_MEMORY;
			goto bail;
		}

		data32 = *(uint32_t *)proc->extra_ctx;
		TEE_InitValueAttribute(&tee_attrs[tee_attrs_count],
					TEE_ATTR_RSA_PSS_SALT_LENGTH,
					data32, 0);
		tee_attrs_count++;
		break;
	default:
		break;
	}

	/* TEE attribute(s) required by the operation */
	switch (proc->mecha_type) {
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
		if (step == PKCS11_FUNC_STEP_FINAL)
			break;

		EMSG("TODO: compute hash for later authentication");
		rv = PKCS11_NOT_IMPLEMENTED;
		goto bail;
	default:
		/* Other mechanism do not expect multi stage operation */
		rv = PKCS11_ERROR;
		break;
	}

	if (step == PKCS11_FUNC_STEP_UPDATE)
		goto bail;

	/*
	 * Finalize
	 */

	/* These ECDSA need to use the computed hash as input data */
	switch (proc->mecha_type) {
	case PKCS11_CKM_ECDSA:
		// TODO: check input size is enough
		if (!in_size) {
			rv = PKCS11_FAILED;
			goto bail;
		}
		break;
	case PKCS11_CKM_ECDSA_SHA1:
		in_buf = proc->extra_ctx;
		in_size = 192;
		break;
	case PKCS11_CKM_ECDSA_SHA224:
		in_buf = proc->extra_ctx;
		in_size = 224;
		break;
	case PKCS11_CKM_ECDSA_SHA256:
		in_buf = proc->extra_ctx;
		in_size = 256;
		break;
	case PKCS11_CKM_ECDSA_SHA384:
		in_buf = proc->extra_ctx;
		in_size = 384;
		break;
	case PKCS11_CKM_ECDSA_SHA512:
		in_buf = proc->extra_ctx;
		in_size = 512;
		break;
	default:
		if (step != PKCS11_FUNC_STEP_ONESHOT) {
			rv = PKCS11_ERROR;
			goto bail;
		}
		break;
	}

	switch (proc->mecha_type) {
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
	case PKCS11_CKM_RSA_PKCS:
	case PKCS11_CKM_RSA_9796:
	case PKCS11_CKM_RSA_X_509:
	case PKCS11_CKM_SHA1_RSA_PKCS:
	case PKCS11_CKM_RSA_PKCS_OAEP:
	case PKCS11_CKM_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS:
	case PKCS11_CKM_SHA256_RSA_PKCS:
	case PKCS11_CKM_SHA384_RSA_PKCS:
	case PKCS11_CKM_SHA512_RSA_PKCS:
		switch (function) {
		case PKCS11_FUNCTION_ENCRYPT:
			// TODO: TEE_ALG_RSAES_PKCS1_OAEP_MGF1_xxx takes an
			// optional argument TEE_ATTR_RSA_OAEP_LABEL.
			res = TEE_AsymmetricEncrypt(proc->tee_op_handle,
						    tee_attrs, tee_attrs_count,
						    in_buf, in_size,
						    out_buf, &out_size);
			output_data = true;
			rv = tee2pkcs_error(res);
			break;

		case PKCS11_FUNCTION_DECRYPT:
			res = TEE_AsymmetricDecrypt(proc->tee_op_handle,
						    tee_attrs, tee_attrs_count,
						    in_buf, in_size,
						    out_buf, &out_size);
			output_data = true;
			rv = tee2pkcs_error(res);
			break;

		case PKCS11_FUNCTION_SIGN:
			res = TEE_AsymmetricSignDigest(proc->tee_op_handle,
							tee_attrs,
							tee_attrs_count,
							in_buf, in_size,
							out_buf, &out_size);
			output_data = true;
			rv = tee2pkcs_error(res);
			break;

		case PKCS11_FUNCTION_VERIFY:
			res = TEE_AsymmetricVerifyDigest(proc->tee_op_handle,
							 tee_attrs,
							 tee_attrs_count,
							 in_buf, in_size,
							 in2_buf, in2_size);
			rv = tee2pkcs_error(res);
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
	if (output_data && (rv == PKCS11_OK || rv == PKCS11_SHORT_BUFFER)) {
		if (io2)
			io2->memref.size = out_size;
		else
			rv = PKCS11_ERROR;
	}

	TEE_Free(tee_attrs);

	return rv;
}

uint32_t do_asymm_derivation(struct pkcs11_session *session,
			     struct pkcs11_attribute_head *proc_params,
			     struct pkcs11_attrs_head **head)
{
	uint32_t rv = PKCS11_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Attribute tee_attrs[2];
	size_t tee_attrs_count = 0;
	TEE_ObjectHandle out_handle = TEE_HANDLE_NULL;
	void *a_ptr = NULL;
	size_t a_size = 0;
	uint32_t key_bit_size = 0;
	uint32_t key_byte_size = 0;

	TEE_MemFill(tee_attrs, 0, sizeof(tee_attrs));

	rv = get_u32_attribute(*head, PKCS11_CKA_VALUE_LEN, &key_bit_size);
	if (rv)
		return rv;

	if (get_type(*head) != PKCS11_CKK_GENERIC_SECRET)
		key_bit_size *= 8;

	key_byte_size = (key_bit_size + 7) / 8;

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
					  key_byte_size * 8, &out_handle);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed, 0x%"PRIx32, res);

		return tee2pkcs_error(res);
	}

	switch (proc_params->id) {
	case PKCS11_CKM_ECDH1_DERIVE:
	case PKCS11_CKM_ECDH1_COFACTOR_DERIVE:
		rv = pkcs2tee_ecdh_param_pub(proc_params, &a_ptr, &a_size);
		if (rv)
			goto bail;

		// TODO: check size is the expected one (active proc key)
		TEE_InitRefAttribute(&tee_attrs[tee_attrs_count],
						TEE_ATTR_ECC_PUBLIC_VALUE_X,
						a_ptr, a_size / 2);
		tee_attrs_count++;

		TEE_InitRefAttribute(&tee_attrs[tee_attrs_count],
						TEE_ATTR_ECC_PUBLIC_VALUE_Y,
						(char *)a_ptr + a_size / 2,
						a_size / 2);
		tee_attrs_count++;
		break;
	case PKCS11_CKM_DH_PKCS_DERIVE:
		TEE_InitRefAttribute(&tee_attrs[tee_attrs_count],
						TEE_ATTR_DH_PUBLIC_VALUE,
						proc_params->data,
						proc_params->size);
		tee_attrs_count++;
		break;
	default:
		TEE_Panic(proc_params->id);
		break;
	}

	TEE_DeriveKey(session->processing->tee_op_handle,
			&tee_attrs[0], tee_attrs_count, out_handle);

	rv = alloc_get_tee_attribute_data(out_handle, TEE_ATTR_SECRET_VALUE,
					  &a_ptr, &a_size);
	if (rv)
		goto bail;

	if (a_size * 8 < key_bit_size)
		rv = PKCS11_CKR_KEY_SIZE_RANGE;
	else
		rv = add_attribute(head, PKCS11_CKA_VALUE, a_ptr,
				   key_byte_size);

	TEE_Free(a_ptr);
bail:
	release_active_processing(session);
	TEE_FreeTransientObject(out_handle);
	return rv;
}
