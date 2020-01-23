/*
 * Copyright (c) 2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
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
#include "sks_helpers.h"

uint32_t sks2tee_proc_params_rsa_pss(struct active_processing *processing,
				     struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args;
	uint32_t rv;
	uint32_t data32;
	uint32_t salt_len;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rv = serialargs_get(&args, &data32, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &data32, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &salt_len, sizeof(uint32_t));
	if (rv)
		return rv;

	processing->extra_ctx = TEE_Malloc(sizeof(uint32_t),
						TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!processing->extra_ctx)
		return PKCS11_MEMORY;

	*(uint32_t *)processing->extra_ctx = salt_len;

	return PKCS11_OK;
}

void tee_release_rsa_pss_operation(struct active_processing *processing)
{
	TEE_Free(processing->extra_ctx);
	processing->extra_ctx = NULL;
}

uint32_t sks2tee_algo_rsa_pss(uint32_t *tee_id,
				struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args;
	uint32_t rv;
	uint32_t hash;
	uint32_t mgf;
	uint32_t salt_len;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rv = serialargs_get(&args, &hash, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &mgf, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &salt_len, sizeof(uint32_t));
	if (rv)
		return rv;

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
		return PKCS11_ERROR;
	}

	return PKCS11_OK;
}

// Currently unused
uint32_t tee_init_rsa_aes_key_wrap_operation(struct active_processing *proc,
					     void *proc_params,
					     size_t params_size)
{
	struct serialargs args;
	uint32_t rv;
	uint32_t aes_bit_size;
	uint32_t hash;
	uint32_t mgf;
	uint32_t source_type;
	void *source_data;
	uint32_t source_size;

	serialargs_init(&args, proc_params, params_size);

	rv = serialargs_get(&args, &aes_bit_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &hash, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &mgf, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &source_type, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &source_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&args, &source_data, source_size);
	if (rv)
		return rv;

	// TODO
	(void)proc;
	return PKCS11_ERROR;
}

uint32_t sks2tee_algo_rsa_oaep(uint32_t *tee_id,
				struct pkcs11_attribute_head *proc_params)
{
	struct serialargs args;
	uint32_t rv;
	uint32_t hash;
	uint32_t mgf;
	uint32_t source_type;
	void *source_data;
	uint32_t source_size;

	serialargs_init(&args, proc_params->data, proc_params->size);

	rv = serialargs_get(&args, &hash, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &mgf, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &source_type, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &source_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&args, &source_data, source_size);
	if (rv)
		return rv;

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
			EMSG("Unexpected %s (0x%" PRIx32 ")",
				id2str_proc(hash), hash);
			return PKCS11_ERROR;
		}
		break;
	default:
		EMSG("Unexpected %s (0x%" PRIx32 ")",
			id2str_proc(proc_params->id), proc_params->id);
		return PKCS11_ERROR;
	}

	return PKCS11_OK;
}

// Unused yet...
uint32_t tee_init_rsa_oaep_operation(struct active_processing *processing,
				     void *proc_params, size_t params_size);

uint32_t tee_init_rsa_oaep_operation(struct active_processing *processing,
				     void *proc_params, size_t params_size)
{
	struct serialargs args;
	uint32_t rv;
	uint32_t hash;
	uint32_t mgf;
	uint32_t source_type;
	void *source_data;
	uint32_t source_size;

	serialargs_init(&args, proc_params, params_size);

	rv = serialargs_get(&args, &hash, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &mgf, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &source_type, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&args, &source_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&args, &source_data, source_size);
	if (rv)
		return rv;

	// TODO
	(void)processing;
	return PKCS11_ERROR;
}

uint32_t load_tee_rsa_key_attrs(TEE_Attribute **tee_attrs, size_t *tee_count,
				struct pkcs11_object *obj)
{
	TEE_Attribute *attrs = NULL;
	size_t count = 0;
	uint32_t rv = PKCS11_ERROR;

	assert(get_type(obj->attributes) == PKCS11_CKK_RSA);

	switch (get_class(obj->attributes)) {
	case PKCS11_CKO_PUBLIC_KEY:
		attrs = TEE_Malloc(3 * sizeof(TEE_Attribute),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!attrs)
			return PKCS11_MEMORY;

		if (sks2tee_load_attr(&attrs[count], TEE_ATTR_RSA_MODULUS,
					obj, PKCS11_CKA_MODULUS))
			count++;

		if (sks2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PUBLIC_EXPONENT,
					obj, PKCS11_CKA_PUBLIC_EXPONENT))
			count++;

		if (count == 2)
			rv = PKCS11_OK;

		break;

	case PKCS11_CKO_PRIVATE_KEY:
		attrs = TEE_Malloc(8 * sizeof(TEE_Attribute),
				   TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!attrs)
			return PKCS11_MEMORY;

		if (sks2tee_load_attr(&attrs[count], TEE_ATTR_RSA_MODULUS,
					obj, PKCS11_CKA_MODULUS))
			count++;

		if (sks2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PUBLIC_EXPONENT,
					obj, PKCS11_CKA_PUBLIC_EXPONENT))
			count++;

		if (sks2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PRIVATE_EXPONENT,
					obj, PKCS11_CKA_PRIVATE_EXPONENT))
			count++;

		if (count != 3)
			break;

		if (get_attribute(obj->attributes, PKCS11_CKA_PRIME_1,
					   NULL, NULL)) {
			rv = PKCS11_OK;
			break;
		}

		if (sks2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PRIME1,
					obj, PKCS11_CKA_PRIME_1))
			count++;

		if (sks2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_PRIME2,
					obj, PKCS11_CKA_PRIME_2))
			count++;

		if (sks2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_EXPONENT1,
					obj, PKCS11_CKA_EXPONENT_1))
			count++;

		if (sks2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_EXPONENT2,
					obj, PKCS11_CKA_EXPONENT_2))
			count++;

		if (sks2tee_load_attr(&attrs[count],
					TEE_ATTR_RSA_COEFFICIENT,
					obj, PKCS11_CKA_COEFFICIENT))
			count++;

		if (count == 8)
			rv = PKCS11_OK;

		break;

	default:
		assert(0);
		break;
	}

	if (rv == PKCS11_OK) {
		*tee_attrs = attrs;
		*tee_count = count;
	}

	return rv;
}

static uint32_t tee2sks_rsa_attributes(struct pkcs11_attrs_head **pub_head,
					struct pkcs11_attrs_head **priv_head,
					TEE_ObjectHandle tee_obj)
{
	uint32_t rv;

	rv = tee2sks_add_attribute(pub_head, PKCS11_CKA_MODULUS,
				   tee_obj, TEE_ATTR_RSA_MODULUS);
	if (rv)
		goto bail;

	if (get_attribute_ptr(*pub_head, PKCS11_CKA_PUBLIC_EXPONENT, NULL, NULL)) {
		rv = tee2sks_add_attribute(pub_head,
					   PKCS11_CKA_PUBLIC_EXPONENT,
					   tee_obj,
					   TEE_ATTR_RSA_PUBLIC_EXPONENT);
		if (rv)
			goto bail;
	}

	rv = tee2sks_add_attribute(priv_head, PKCS11_CKA_MODULUS,
				   tee_obj, TEE_ATTR_RSA_MODULUS);
	if (rv)
		goto bail;

	rv = tee2sks_add_attribute(priv_head, PKCS11_CKA_PUBLIC_EXPONENT,
				   tee_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT);
	if (rv)
		goto bail;

	rv = tee2sks_add_attribute(priv_head, PKCS11_CKA_PRIVATE_EXPONENT,
				   tee_obj, TEE_ATTR_RSA_PRIVATE_EXPONENT);
	if (rv)
		goto bail;

	rv = tee2sks_add_attribute(priv_head, PKCS11_CKA_PRIME_1,
				   tee_obj, TEE_ATTR_RSA_PRIME1);
	if (rv)
		goto bail;

	rv = tee2sks_add_attribute(priv_head, PKCS11_CKA_PRIME_2,
				   tee_obj, TEE_ATTR_RSA_PRIME2);
	if (rv)
		goto bail;

	rv = tee2sks_add_attribute(priv_head, PKCS11_CKA_EXPONENT_1,
				   tee_obj, TEE_ATTR_RSA_EXPONENT1);
	if (rv)
		goto bail;

	rv = tee2sks_add_attribute(priv_head, PKCS11_CKA_EXPONENT_2,
				   tee_obj, TEE_ATTR_RSA_EXPONENT2);
	if (rv)
		goto bail;

	rv = tee2sks_add_attribute(priv_head, PKCS11_CKA_COEFFICIENT,
				   tee_obj, TEE_ATTR_RSA_COEFFICIENT);
bail:
	return rv;
}

uint32_t generate_rsa_keys(struct pkcs11_attribute_head *proc_params,
			   struct pkcs11_attrs_head **pub_head,
			   struct pkcs11_attrs_head **priv_head)
{
	uint32_t rv;
	void *a_ptr;
	uint32_t a_size;
	TEE_ObjectHandle tee_obj;
	TEE_Result res;
	uint32_t tee_size;
	TEE_Attribute tee_attrs[1];
	uint32_t tee_count = 0;

	if (!proc_params || !*pub_head || !*priv_head) {
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	if (get_attribute_ptr(*pub_head, PKCS11_CKA_MODULUS_BITS,
				&a_ptr, &a_size)) {
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	if (a_size != sizeof(uint32_t)) {
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	TEE_MemMove(&tee_size, a_ptr, sizeof(uint32_t));

	rv = get_attribute_ptr(*pub_head, PKCS11_CKA_PUBLIC_EXPONENT,
				&a_ptr, &a_size);
	if (rv == PKCS11_OK) {
		TEE_InitRefAttribute(&tee_attrs[tee_count],
				     TEE_ATTR_RSA_PUBLIC_EXPONENT,
				     a_ptr, a_size);

		tee_count++;
	}

	if (!get_attribute(*pub_head, PKCS11_CKA_MODULUS, NULL, NULL) ||
	    !get_attribute(*priv_head, PKCS11_CKA_MODULUS, NULL, NULL) ||
	    !get_attribute(*priv_head, PKCS11_CKA_PUBLIC_EXPONENT, NULL, NULL) ||
	    !get_attribute(*priv_head, PKCS11_CKA_PRIVATE_EXPONENT, NULL, NULL) ||
	    !get_attribute(*priv_head, PKCS11_CKA_PRIME_1, NULL, NULL) ||
	    !get_attribute(*priv_head, PKCS11_CKA_PRIME_2, NULL, NULL) ||
	    !get_attribute(*priv_head, PKCS11_CKA_EXPONENT_1, NULL, NULL) ||
	    !get_attribute(*priv_head, PKCS11_CKA_EXPONENT_2, NULL, NULL) ||
	    !get_attribute(*priv_head, PKCS11_CKA_COEFFICIENT, NULL, NULL)) {
		EMSG("Unexpected attribute(s) found");
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	/* Create an ECDSA TEE key: will match PKCS11 ECDSA and ECDH */
	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
					  tee_size, &tee_obj);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed 0x%" PRIx32, res);
		return tee2sks_error(res);
	}

	res = TEE_RestrictObjectUsage1(tee_obj, TEE_USAGE_EXTRACTABLE);
	if (res) {
		DMSG("TEE_RestrictObjectUsage1 failed 0x%" PRIx32, res);
		rv = tee2sks_error(res);
		goto bail;
	}

	res = TEE_GenerateKey(tee_obj, tee_size, &tee_attrs[0], tee_count);
	if (res) {
		DMSG("TEE_GenerateKey failed 0x%" PRIx32, res);
		rv = tee2sks_error(res);
		goto bail;
	}

	rv = tee2sks_rsa_attributes(pub_head, priv_head, tee_obj);

bail:
	if (tee_obj != TEE_HANDLE_NULL)
		TEE_CloseObject(tee_obj);

	return rv;
}

