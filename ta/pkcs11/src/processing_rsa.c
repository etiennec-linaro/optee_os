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

uint32_t pkcs2tee_proc_params_rsa_pss(struct active_processing *processing,
				     struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t data32 = 0;
	uint32_t salt_len = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get(&args, &data32, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &data32, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &salt_len, sizeof(uint32_t));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	processing->extra_ctx = TEE_Malloc(sizeof(uint32_t),
						TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!processing->extra_ctx)
		return PKCS11_CKR_DEVICE_MEMORY;

	*(uint32_t *)processing->extra_ctx = salt_len;

	return PKCS11_CKR_OK;
}

uint32_t pkcs2tee_algo_rsa_pss(uint32_t *tee_id,
				struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t salt_len = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get(&args, &hash, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &mgf, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &salt_len, sizeof(uint32_t));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	switch (*tee_id) {
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		if (hash != PKCS11_CKM_SHA_1 || mgf != PKCS11_CKG_MGF1_SHA1)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		if (hash != PKCS11_CKM_SHA224 || mgf != PKCS11_CKG_MGF1_SHA224)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		if (hash != PKCS11_CKM_SHA256 || mgf != PKCS11_CKG_MGF1_SHA256)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		if (hash != PKCS11_CKM_SHA384 || mgf != PKCS11_CKG_MGF1_SHA384)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		if (hash != PKCS11_CKM_SHA512 || mgf != PKCS11_CKG_MGF1_SHA512)
			return PKCS11_CKR_MECHANISM_PARAM_INVALID;
		break;
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}

	return PKCS11_CKR_OK;
}

// Currently unused
uint32_t tee_init_rsa_aes_key_wrap_operation(struct active_processing *proc,
					     void *proc_params,
					     size_t params_size)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t aes_bit_size = 0;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t source_type = 0;
	void *source_data = NULL;
	uint32_t source_size = 0;

	serialargs_init(&args, proc_params, params_size);

	rc = serialargs_get(&args, &aes_bit_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &hash, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &mgf, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &source_type, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &source_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &source_data, source_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	// TODO
	(void)proc;
	return PKCS11_CKR_GENERAL_ERROR;
}

uint32_t pkcs2tee_algo_rsa_oaep(uint32_t *tee_id,
				struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t source_type = 0;
	void *source_data = NULL;
	uint32_t source_size = 0;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rc = serialargs_get(&args, &hash, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &mgf, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &source_type, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &source_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &source_data, source_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	switch (proc_params->id) {
	case PKCS11_CKM_RSA_PKCS_OAEP:
		switch (hash) {
		case PKCS11_CKM_SHA_1:
			if (mgf != PKCS11_CKG_MGF1_SHA1 || source_size)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1;
			break;
		case PKCS11_CKM_SHA224:
			if (mgf != PKCS11_CKG_MGF1_SHA224 || source_size)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224;
			break;
		case PKCS11_CKM_SHA256:
			if (mgf != PKCS11_CKG_MGF1_SHA256 || source_size)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
			break;
		case PKCS11_CKM_SHA384:
			if (mgf != PKCS11_CKG_MGF1_SHA384 || source_size)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384;
			break;
		case PKCS11_CKM_SHA512:
			if (mgf != PKCS11_CKG_MGF1_SHA512 || source_size)
				return PKCS11_CKR_MECHANISM_PARAM_INVALID;
			*tee_id = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512;
			break;
		default:
			EMSG("Unexpected %#"PRIx32"/%s", hash,
			     id2str_proc(hash));

			return PKCS11_CKR_GENERAL_ERROR;
		}
		break;
	default:
		EMSG("Unexpected mechanism %#"PRIx32"/%s", proc_params->id,
		     id2str_proc(proc_params->id));

		return PKCS11_CKR_GENERAL_ERROR;
	}

	return PKCS11_CKR_OK;
}

// Unused yet...
uint32_t tee_init_rsa_oaep_operation(struct active_processing *processing,
				     void *proc_params, size_t params_size);

uint32_t tee_init_rsa_oaep_operation(struct active_processing *processing,
				     void *proc_params, size_t params_size)
{
	struct serialargs args = { };
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	uint32_t hash = 0;
	uint32_t mgf = 0;
	uint32_t source_type = 0;
	void *source_data = NULL;
	uint32_t source_size = 0;

	serialargs_init(&args, proc_params, params_size);

	rc = serialargs_get(&args, &hash, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &mgf, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &source_type, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&args, &source_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&args, &source_data, source_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&args))
		return PKCS11_CKR_ARGUMENTS_BAD;

	// TODO
	(void)processing;
	return PKCS11_CKR_GENERAL_ERROR;
}

uint32_t load_tee_rsa_key_attrs(TEE_Attribute **tee_attrs, size_t *tee_count,
				struct pkcs11_object *obj)
{
	TEE_Attribute *attrs = NULL;
	size_t count = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *a_ptr = NULL;

	assert(get_key_type(obj->attributes) == PKCS11_CKK_RSA);

	switch (get_class(obj->attributes)) {
	case PKCS11_CKO_PUBLIC_KEY:
		attrs = TEE_Malloc(3 * sizeof(TEE_Attribute),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!attrs)
			return PKCS11_CKR_DEVICE_MEMORY;

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_MODULUS,
					obj, PKCS11_CKA_MODULUS))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PUBLIC_EXPONENT,
					obj, PKCS11_CKA_PUBLIC_EXPONENT))
			count++;

		if (count == 2)
			rc = PKCS11_CKR_OK;

		break;

	case PKCS11_CKO_PRIVATE_KEY:
		attrs = TEE_Malloc(8 * sizeof(TEE_Attribute),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!attrs)
			return PKCS11_CKR_DEVICE_MEMORY;

		if (pkcs2tee_load_attr(&attrs[count], TEE_ATTR_RSA_MODULUS,
					obj, PKCS11_CKA_MODULUS))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PUBLIC_EXPONENT,
					obj, PKCS11_CKA_PUBLIC_EXPONENT))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PRIVATE_EXPONENT,
					obj, PKCS11_CKA_PRIVATE_EXPONENT))
			count++;

		if (count != 3)
			break;

		/* FIXME: check PRIME_2, EXPONENT_*, COEFFICIENT are found? */
		if (get_attribute(obj->attributes, PKCS11_CKA_PRIME_1,
					   NULL, NULL) || !a_ptr) {
			rc = PKCS11_CKR_OK;
			break;
		}

		if (pkcs2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PRIME1,
					obj, PKCS11_CKA_PRIME_1))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PRIME2,
					obj, PKCS11_CKA_PRIME_2))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_EXPONENT1,
					obj, PKCS11_CKA_EXPONENT_1))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_EXPONENT2,
					obj, PKCS11_CKA_EXPONENT_2))
			count++;

		if (pkcs2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_COEFFICIENT,
					obj, PKCS11_CKA_COEFFICIENT))
			count++;

		if (count == 8)
			rc = PKCS11_CKR_OK;

		break;

	default:
		assert(0);
		break;
	}

	if (rc == PKCS11_CKR_OK) {
		*tee_attrs = attrs;
		*tee_count = count;
	}

	return rc;
}

static uint32_t tee2pkcs_rsa_attributes(struct obj_attrs **pub_head,
					struct obj_attrs **priv_head,
					TEE_ObjectHandle tee_obj)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *a_ptr = NULL;

	rc = tee2pkcs_add_attribute(pub_head, PKCS11_CKA_MODULUS,
				   tee_obj, TEE_ATTR_RSA_MODULUS);
	if (rc)
		goto out;

	rc = get_attribute_ptr(*pub_head, PKCS11_CKA_PUBLIC_EXPONENT,
			       &a_ptr, NULL);
	if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
		goto out;

	if (rc == PKCS11_RV_NOT_FOUND || !a_ptr) {
		rc = tee2pkcs_add_attribute(pub_head,
					   PKCS11_CKA_PUBLIC_EXPONENT,
					   tee_obj,
					   TEE_ATTR_RSA_PUBLIC_EXPONENT);
		if (rc)
			goto out;
	}

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_MODULUS,
				   tee_obj, TEE_ATTR_RSA_MODULUS);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_PUBLIC_EXPONENT,
				   tee_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_PRIVATE_EXPONENT,
				   tee_obj, TEE_ATTR_RSA_PRIVATE_EXPONENT);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_PRIME_1,
				   tee_obj, TEE_ATTR_RSA_PRIME1);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_PRIME_2,
				   tee_obj, TEE_ATTR_RSA_PRIME2);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_EXPONENT_1,
				   tee_obj, TEE_ATTR_RSA_EXPONENT1);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_EXPONENT_2,
				   tee_obj, TEE_ATTR_RSA_EXPONENT2);
	if (rc)
		goto out;

	rc = tee2pkcs_add_attribute(priv_head, PKCS11_CKA_COEFFICIENT,
				   tee_obj, TEE_ATTR_RSA_COEFFICIENT);
out:
	return rc;
}

uint32_t generate_rsa_keys(struct pkcs11_attribute_head *proc_params,
			   struct obj_attrs **pub_head,
			   struct obj_attrs **priv_head)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *a_ptr = NULL;
	uint32_t a_size = 0;
	TEE_ObjectHandle tee_obj = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t tee_size = 0;
	TEE_Attribute tee_attrs[1] = { };
	uint32_t tee_count = 0;

	if (!proc_params || !*pub_head || !*priv_head) {
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	rc = get_attribute_ptr(*pub_head, PKCS11_CKA_MODULUS_BITS,
			       &a_ptr, &a_size);
	if (rc != PKCS11_CKR_OK || a_size != sizeof(uint32_t)) {
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	TEE_MemMove(&tee_size, a_ptr, sizeof(uint32_t));

	rc = get_attribute_ptr(*pub_head, PKCS11_CKA_PUBLIC_EXPONENT,
				&a_ptr, &a_size);
	if (rc != PKCS11_CKR_OK && rc != PKCS11_RV_NOT_FOUND)
		return rc;

	if (rc == PKCS11_CKR_OK && a_ptr) {
		TEE_InitRefAttribute(&tee_attrs[tee_count],
				     TEE_ATTR_RSA_PUBLIC_EXPONENT,
				     a_ptr, a_size);

		tee_count++;
	}

	/* Create an ECDSA TEE key: will match PKCS11 ECDSA and ECDH */
	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
					  tee_size, &tee_obj);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed %#"PRIx32, res);

		return tee2pkcs_error(res);
	}

	res = TEE_RestrictObjectUsage1(tee_obj, TEE_USAGE_EXTRACTABLE);
	if (res) {
		DMSG("TEE_RestrictObjectUsage1 failed %#"PRIx32, res);

		rc = tee2pkcs_error(res);
		goto out;
	}

	res = TEE_GenerateKey(tee_obj, tee_size, &tee_attrs[0], tee_count);
	if (res) {
		DMSG("TEE_GenerateKey failed %#"PRIx32, res);

		rc = tee2pkcs_error(res);
		goto out;
	}

	rc = tee2pkcs_rsa_attributes(pub_head, priv_head, tee_obj);

out:
	if (tee_obj != TEE_HANDLE_NULL)
		TEE_CloseObject(tee_obj);

	return rc;
}

