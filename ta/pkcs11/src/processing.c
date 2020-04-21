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
#include <util.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

static uint32_t get_ready_session(struct pkcs11_session *session)
{
	if (session_is_active(session))
		return PKCS11_CKR_OPERATION_ACTIVE;

	return PKCS11_CKR_OK;
}

static bool func_matches_state(enum processing_func function,
				enum pkcs11_proc_state state)
{
	switch (function) {
	case PKCS11_FUNCTION_ENCRYPT:
		return state == PKCS11_SESSION_ENCRYPTING ||
		       state == PKCS11_SESSION_DIGESTING_ENCRYPTING ||
		       state == PKCS11_SESSION_SIGNING_ENCRYPTING;
	case PKCS11_FUNCTION_DECRYPT:
		return state == PKCS11_SESSION_DECRYPTING ||
		       state == PKCS11_SESSION_DECRYPTING_DIGESTING ||
		       state == PKCS11_SESSION_DECRYPTING_VERIFYING;
	case PKCS11_FUNCTION_DIGEST:
		return state == PKCS11_SESSION_DIGESTING ||
		       state == PKCS11_SESSION_DIGESTING_ENCRYPTING;
	case PKCS11_FUNCTION_SIGN:
		return state == PKCS11_SESSION_SIGNING ||
		       state == PKCS11_SESSION_SIGNING_ENCRYPTING;
	case PKCS11_FUNCTION_VERIFY:
		return state == PKCS11_SESSION_VERIFYING ||
		       state == PKCS11_SESSION_DECRYPTING_VERIFYING;
	case PKCS11_FUNCTION_SIGN_RECOVER:
		return state == PKCS11_SESSION_SIGNING_RECOVER;
	case PKCS11_FUNCTION_VERIFY_RECOVER:
		return state == PKCS11_SESSION_SIGNING_RECOVER;
	default:
		TEE_Panic(function);
		return false;
	}
}

static uint32_t get_active_session(struct pkcs11_session *session,
				  enum processing_func function)
{
	uint32_t rv = PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	if (session->processing &&
	    func_matches_state(function, session->processing->state))
		rv = PKCS11_CKR_OK;

	return rv;
}

void release_active_processing(struct pkcs11_session *session)
{
	if (!session->processing)
		return;

	switch (session->processing->mecha_type) {
	case PKCS11_CKM_AES_CTR:
		tee_release_ctr_operation(session->processing);
		break;
	case PKCS11_CKM_AES_GCM:
		tee_release_gcm_operation(session->processing);
		break;
	case PKCS11_CKM_AES_CCM:
		tee_release_ccm_operation(session->processing);
		break;
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
		tee_release_rsa_pss_operation(session->processing);
		break;
	default:
		break;
	}

	if (session->processing->tee_op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(session->processing->tee_op_handle);
		session->processing->tee_op_handle = TEE_HANDLE_NULL;
	}

	TEE_Free(session->processing);
	session->processing = NULL;
}

uint32_t entry_import_object(struct pkcs11_client *client,
			     uint32_t ptypes, TEE_Param *params)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attrs_head *head = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	uint32_t obj_handle = 0;

	/*
	 * Collect the arguments of the request
	 */

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(obj_handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rv = PKCS11_CKR_ARGUMENTS_BAD;
		goto bail;
	}


	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temporary template once done.
	 */
	rv = create_attributes_from_template(&head, template, template_size,
					     NULL, PKCS11_FUNCTION_IMPORT,
					     PKCS11_PROCESSING_IMPORT);
	TEE_Free(template);
	template = NULL;
	if (rv)
		goto bail;

	/*
	 * Check target object attributes match target processing
	 * Check target object attributes match token state
	 */
	rv = check_created_attrs_against_processing(PKCS11_PROCESSING_IMPORT,
						    head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, head);
	if (rv)
		goto bail;

	/*
	 * TODO: test object (will check all expected attributes are in place
	 */

	/*
	 * At this stage the object is almost created: all its attributes are
	 * referenced in @head, including the key value and are assume
	 * reliable. Now need to register it and get a handle for it.
	 */
	rv = create_object(session, head, &obj_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct pkcs11_object instance)
	 * owns the serialised buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(obj_handle));
	out->memref.size = sizeof(obj_handle);

	DMSG("PKCS11 session %"PRIu32": import object %#"PRIx32,
	     session->handle, obj_handle);

bail:
	TEE_Free(template);
	TEE_Free(head);

	return rv;
}

size_t get_object_key_bit_size(struct pkcs11_object *obj)
{
	void *a_ptr = NULL;
	uint32_t a_size = 0;
	struct pkcs11_attrs_head *attrs = obj->attributes;

	switch (get_type(attrs)) {
	case PKCS11_CKK_AES:
	case PKCS11_CKK_GENERIC_SECRET:
	case PKCS11_CKK_MD5_HMAC:
	case PKCS11_CKK_SHA_1_HMAC:
	case PKCS11_CKK_SHA224_HMAC:
	case PKCS11_CKK_SHA256_HMAC:
	case PKCS11_CKK_SHA384_HMAC:
	case PKCS11_CKK_SHA512_HMAC:
		if (get_attribute_ptr(attrs, PKCS11_CKA_VALUE, NULL, &a_size))
			return 0;

		return a_size * 8;

	case PKCS11_CKK_RSA:
		if (get_attribute_ptr(attrs, PKCS11_CKA_MODULUS, NULL, &a_size))
			return 0;

		return a_size * 8;

	case PKCS11_CKK_EC:
		if (get_attribute_ptr(attrs, PKCS11_CKA_EC_PARAMS,
				      &a_ptr, &a_size))
			return 0;

		return ec_params2tee_keysize(a_ptr, a_size);

	default:
		TEE_Panic(0);
		return 0;
	}
}

static uint32_t generate_random_key_value(struct pkcs11_attrs_head **head)
{
	uint32_t rv = 0;
	void *data;
	uint32_t data_size;
	uint32_t value_len;
	void *value;

	if (!*head)
		return PKCS11_CKR_TEMPLATE_INCONSISTENT;

	rv = get_attribute_ptr(*head, PKCS11_CKA_VALUE_LEN, &data, &data_size);
	if (rv || data_size != sizeof(uint32_t)) {
		DMSG("%s", rv ? "No attribute value_len found" :
		     "Invalid size for attribute VALUE_LEN");

		return PKCS11_CKR_ATTRIBUTE_VALUE_INVALID;
	}
	TEE_MemMove(&value_len, data, data_size);

	if (get_type(*head) == PKCS11_CKK_GENERIC_SECRET)
		value_len = (value_len + 7) / 8;

	value = TEE_Malloc(value_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!value)
		return PKCS11_CKR_DEVICE_MEMORY;

	TEE_GenerateRandom(value, value_len);

	rv = add_attribute(head, PKCS11_CKA_VALUE, value, value_len);

	TEE_Free(value);

	return rv;
}

uint32_t entry_generate_secret(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	struct pkcs11_attrs_head *head = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	uint32_t obj_handle = 0;

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(obj_handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	rv = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rv)
		goto bail;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		goto bail;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rv = PKCS11_CKR_ARGUMENTS_BAD;
		goto bail;
	}

	rv = get_ready_session(session);
	if (rv)
		goto bail;

	template_size = sizeof(*template) + template->attrs_size;

	rv = check_mechanism_against_processing(session, proc_params->id,
						PKCS11_FUNCTION_GENERATE,
						PKCS11_FUNC_STEP_INIT);
	if (rv)
		goto bail;

	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temporary template once done.
	 */
	rv = create_attributes_from_template(&head, template, template_size,
					     NULL, PKCS11_FUNCTION_GENERATE,
					     proc_params->id);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	rv = check_created_attrs(head, NULL);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_processing(proc_params->id, head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, head);
	if (rv)
		goto bail;

	/*
	 * Execute target processing and add value as attribute
	 * PKCS11_CKA_VALUE. Symm key generation: depends on target
	 * processing to be used.
	 */
	switch (proc_params->id) {
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
	case PKCS11_CKM_AES_KEY_GEN:
		/* Generate random of size specified by attribute VALUE_LEN */
		rv = generate_random_key_value(&head);
		if (rv)
			goto bail;
		break;

	default:
		rv = PKCS11_CKR_MECHANISM_INVALID;
		goto bail;
	}

	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rv = create_object(session, head, &obj_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct pkcs11_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(obj_handle));
	out->memref.size = sizeof(obj_handle);

	DMSG("PKCS11 session %"PRIu32": generate secret %#"PRIx32,
	     session->handle, obj_handle);

bail:
	TEE_Free(proc_params);
	TEE_Free(template);
	TEE_Free(head);

	return rv;
}

uint32_t alloc_get_tee_attribute_data(TEE_ObjectHandle tee_obj,
					     uint32_t attribute,
					     void **data, size_t *size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *ptr = NULL;
	uint32_t sz = 0;

	res = TEE_GetObjectBufferAttribute(tee_obj, attribute, NULL, &sz);
	if (res != TEE_ERROR_SHORT_BUFFER)
		return PKCS11_CKR_FUNCTION_FAILED;

	ptr = TEE_Malloc(sz, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!ptr)
		return PKCS11_CKR_DEVICE_MEMORY;

	res = TEE_GetObjectBufferAttribute(tee_obj, attribute, ptr, &sz);
	if (res) {
		TEE_Free(ptr);
	} else {
		*data = ptr;
		*size = sz;
	}

	return tee2pkcs_error(res);
}

uint32_t tee2pkcs_add_attribute(struct pkcs11_attrs_head **head,
				uint32_t pkcs11_id, TEE_ObjectHandle tee_obj,
				uint32_t tee_id)
{
	uint32_t rv = 0;
	void *a_ptr = NULL;
	size_t a_size = 0;

	rv = alloc_get_tee_attribute_data(tee_obj, tee_id, &a_ptr, &a_size);
	if (rv)
		goto bail;

	rv = add_attribute(head, pkcs11_id, a_ptr, a_size);

	TEE_Free(a_ptr);

bail:
	if (rv)
		EMSG("Failed TEE attribute %#"PRIx32" for %#"PRIx32"/%s",
		     tee_id, pkcs11_id, id2str_attr(pkcs11_id));
	return rv;
}

uint32_t entry_generate_key_pair(struct pkcs11_client *client,
				 uint32_t ptypes, TEE_Param *params)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	struct pkcs11_attrs_head *pub_head = NULL;
	struct pkcs11_attrs_head *priv_head = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	uint32_t pubkey_handle = 0;
	uint32_t privkey_handle = 0;
	uint32_t *hdl_ptr = NULL;
	size_t out_ref_size = sizeof(pubkey_handle) + sizeof(privkey_handle);

	if (!client || ptypes != exp_pt || out->memref.size != out_ref_size)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	/* Get mechanism parameters */
	rv = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rv)
		return rv;

	/* Get and check public key attributes */
	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		goto bail;

	rv = get_ready_session(session);
	if (rv)
		goto bail;

	rv = check_mechanism_against_processing(session, proc_params->id,
						PKCS11_FUNCTION_GENERATE_PAIR,
						PKCS11_FUNC_STEP_INIT);
	if (rv)
		goto bail;

	template_size = sizeof(*template) + template->attrs_size;

	rv = create_attributes_from_template(&pub_head,
					     template, template_size, NULL,
					     PKCS11_FUNCTION_GENERATE_PAIR,
					     proc_params->id);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		goto bail;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rv = PKCS11_CKR_ARGUMENTS_BAD;
		goto bail;
	}

	template_size = sizeof(*template) + template->attrs_size;

	rv = create_attributes_from_template(&priv_head,
					     template, template_size, NULL,
					     PKCS11_FUNCTION_GENERATE_PAIR,
					     proc_params->id);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	/* Generate CKA_ID for keys if not specified by the templates */
	rv = add_missing_attribute_id(&pub_head, &priv_head);
	if (rv)
		goto bail;

	/* Check created object against processing and token state */
	rv = check_created_attrs(pub_head, priv_head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_processing(proc_params->id, pub_head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_processing(proc_params->id, priv_head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, pub_head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, priv_head);
	if (rv)
		goto bail;

	/* Generate key pair */
	switch (proc_params->id) {
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
		rv = generate_ec_keys(proc_params, &pub_head, &priv_head);
		break;

	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
		rv = generate_rsa_keys(proc_params, &pub_head, &priv_head);
		break;
	default:
		rv = PKCS11_CKR_MECHANISM_INVALID;
		break;
	}
	if (rv)
		goto bail;

	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rv = create_object(session, pub_head, &pubkey_handle);
	if (rv)
		goto bail;

	rv = create_object(session, priv_head, &privkey_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct pkcs11_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	pub_head = NULL;
	priv_head = NULL;
	hdl_ptr = (uint32_t *)out->memref.buffer;

	TEE_MemMove(hdl_ptr, &pubkey_handle, sizeof(pubkey_handle));
	TEE_MemMove(hdl_ptr + 1, &privkey_handle, sizeof(privkey_handle));

	DMSG("PKCS11 session %"PRIu32": create key pair %#"PRIx32"/%#"PRIx32,
	     session->handle, privkey_handle, pubkey_handle);

bail:
	TEE_Free(proc_params);
	TEE_Free(template);
	TEE_Free(pub_head);
	TEE_Free(priv_head);

	return rv;
}

/*
 * entry_processing_init - Generic entry for initializing a processing
 *
 * @ctrl = [session-handle]
 * @ptype = Invocation parameter types
 * @params = Invocation parameters reference
 * @function - encrypt, decrypt, sign, verify, digest, ...
 *
 * The generic part come that all the commands uses the same
 * input/output invocation parameters format (ctrl/in/out).
 */
uint32_t entry_processing_init(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params,
			       enum processing_func function)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	uint32_t key_handle = 0;
	struct pkcs11_object *obj = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &key_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rv = PKCS11_CKR_ARGUMENTS_BAD;
		goto bail;
	}

	rv = get_ready_session(session);
	if (rv)
		goto bail;

	obj = pkcs11_handle2object(key_handle, session);
	if (!obj) {
		rv = PKCS11_CKR_KEY_HANDLE_INVALID;
		goto bail;
	}

	rv = set_processing_state(session, function, obj, NULL);
	if (rv)
		goto bail;

	rv = check_mechanism_against_processing(session, proc_params->id,
						function,
						PKCS11_FUNC_STEP_INIT);
	if (rv)
		goto bail;

	rv = check_parent_attrs_against_processing(proc_params->id, function,
						   obj->attributes);
	if (rv)
		goto bail;

	rv = check_access_attrs_against_token(session, obj->attributes);
	if (rv)
		goto bail;

	if (processing_is_tee_symm(proc_params->id))
		rv = init_symm_operation(session, function, proc_params, obj);
	else if (processing_is_tee_asymm(proc_params->id))
		rv = init_asymm_operation(session, function, proc_params, obj);
	else
		rv = PKCS11_CKR_MECHANISM_INVALID;

	if (rv == PKCS11_CKR_OK) {
		session->processing->mecha_type = proc_params->id;
		DMSG("PKCS11 session %"PRIu32": init processing %s %s",
		     session->handle, id2str_proc(proc_params->id),
		     id2str_function(function));
	}

bail:
	if (rv && session)
		release_active_processing(session);

	TEE_Free(proc_params);

	return rv;
}

/*
 * entry_processing_step - Generic entry on active processing
 *
 * @ctrl = [session-handle]
 * @ptype = Invocation parameter types
 * @params = Invocation parameters reference
 * @function - encrypt, decrypt, sign, verify, digest, ...
 * @step - update, oneshot, final
 *
 * The generic part come that all the commands uses the same
 * input/output invocation parameters format (ctrl/in/out).
 */
uint32_t entry_processing_step(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params,
			       enum processing_func function,
			       enum processing_step step)
{
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	uint32_t mecha_type = 0;

	if (!client ||
	    TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	rv = get_active_session(session, function);
	if (rv)
		return rv;

	// TODO: check user authen and object activation dates
	mecha_type = session->processing->mecha_type;
	rv = check_mechanism_against_processing(session, mecha_type,
						function, step);
	if (rv)
		goto bail;

	if (processing_is_tee_symm(mecha_type))
		rv = step_symm_operation(session, function, step,
					 ptypes, params);
	else if (processing_is_tee_asymm(mecha_type))
		rv = step_asymm_operation(session, function, step,
					  ptypes, params);
	else
		rv = PKCS11_CKR_MECHANISM_INVALID;

	if (rv == PKCS11_CKR_OK) {
		session->processing->updated = true;
		DMSG("PKCS11 session%"PRIu32": processing %s %s",
		     session->handle, id2str_proc(mecha_type),
		     id2str_function(function));
	}

bail:
	switch (step) {
	case PKCS11_FUNC_STEP_UPDATE:
		if (rv != PKCS11_CKR_OK && rv != PKCS11_CKR_BUFFER_TOO_SMALL)
			release_active_processing(session);
		break;
	default:
		/* ONESHOT and FINAL terminates processing on success */
		if (rv != PKCS11_CKR_BUFFER_TOO_SMALL)
			release_active_processing(session);
		break;
	}

	return rv;
}

/*
 * entry_verify_oneshot - Generic entry on active processing
 *
 * @ctrl = [session-handle]
 * @ptype = Invocation parameter types
 * @params = Invocation parameters reference
 * @function - encrypt, decrypt, sign, verify, digest, ...
 * @step - update, oneshot, final
 *
 * The generic part come that all the commands uses the same
 * input/output invocation parameters format (ctrl/in/out).
 */
uint32_t entry_verify_oneshot(struct pkcs11_client *client,
			      uint32_t ptypes, TEE_Param *params,
			      enum processing_func function,
			      enum processing_step step)

{
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	uint32_t mecha_type = 0;

	assert(function == PKCS11_FUNCTION_VERIFY);
	if (!client ||
	    TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	rv = get_active_session(session, function);
	if (rv)
		return rv;

	// TODO: check user authen and object activation dates
	mecha_type = session->processing->mecha_type;
	rv = check_mechanism_against_processing(session, mecha_type,
						function, step);
	if (rv)
		goto bail;

	if (processing_is_tee_symm(mecha_type))
		rv = step_symm_operation(session, function, step,
					 ptypes, params);
	else if (processing_is_tee_asymm(mecha_type))
		rv = step_asymm_operation(session, function, step,
					  ptypes, params);
	else
		rv = PKCS11_CKR_MECHANISM_INVALID;

	DMSG("PKCS11 session %"PRIu32": verify %s %s: %s", session->handle,
	     id2str_proc(mecha_type), id2str_function(function),
	     id2str_rc(rv));

bail:
	if (rv != PKCS11_CKR_BUFFER_TOO_SMALL)
		release_active_processing(session);

	return rv;
}

uint32_t entry_derive_key(struct pkcs11_client *client,
			  uint32_t ptypes, TEE_Param *params)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	TEE_Param *out = &params[2];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_attribute_head *proc_params = NULL;
	uint32_t parent_handle = 0;
	struct pkcs11_object *parent_obj;
	struct pkcs11_attrs_head *head = NULL;
	struct pkcs11_object_head *template = NULL;
	size_t template_size = 0;
	uint32_t out_handle = 0;
	uint32_t __maybe_unused mecha_id = 0;

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(out_handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	rv = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rv)
		goto bail;

	rv = serialargs_get(&ctrlargs, &parent_handle, sizeof(uint32_t));
	if (rv)
		goto bail;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		goto bail;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rv = PKCS11_CKR_ARGUMENTS_BAD;
		goto bail;
	}

	rv = get_ready_session(session);
	if (rv)
		goto bail;

	parent_obj = pkcs11_handle2object(parent_handle, session);
	if (!parent_obj) {
		rv = PKCS11_CKR_KEY_HANDLE_INVALID;
		goto bail;
	}

	rv = set_processing_state(session, PKCS11_FUNCTION_DERIVE,
				  parent_obj, NULL);
	if (rv)
		goto bail;

	template_size = sizeof(*template) + template->attrs_size;

	rv = check_mechanism_against_processing(session, proc_params->id,
						PKCS11_FUNCTION_DERIVE,
						PKCS11_FUNC_STEP_INIT);
	if (rv)
		goto bail;

	rv = create_attributes_from_template(&head, template, template_size,
					     parent_obj->attributes,
					     PKCS11_FUNCTION_DERIVE,
					     proc_params->id);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	rv = check_created_attrs(head, NULL);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_processing(proc_params->id, head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, head);
	if (rv)
		goto bail;

	// TODO: check_created_against_parent(session, parent, child);
	// This can handle DERVIE_TEMPLATE attributes from the parent key.

	if (processing_is_tee_symm(proc_params->id)) {
		rv = init_symm_operation(session, PKCS11_FUNCTION_DERIVE,
					 proc_params, parent_obj);
		if (rv)
			goto bail;

		rv = do_symm_derivation(session, proc_params,
					parent_obj, &head);
	} else if (processing_is_tee_asymm(proc_params->id)) {
		rv = init_asymm_operation(session, PKCS11_FUNCTION_DERIVE,
					  proc_params, parent_obj);
		if (rv)
			goto bail;

		rv = do_asymm_derivation(session, proc_params, &head);
	} else {
		rv = PKCS11_CKR_MECHANISM_INVALID;
	}

	if (rv)
		goto bail;

#if 0
	/* Exaustive list */
	switch (proc_params->id) {
	case PKCS11_CKM_ECDH1_DERIVE:	<--------------------------- TODO
	//case PKCS11_CKM_ECDH1_COFACTOR_DERIVE:
	case PKCS11_CKM_DH_PKCS_DERIVE:	<--------------------------- TODO
	case PKCS11_CKM_X9_42_DH_DERIVE:
	case PKCS11_CKM_X9_42_DH_HYBRID_DERIVE:
	case PKCS11_CKM_X9_42_MQV_DERIVE:
	case PKCS11_CKM_AES_GMAC
	case PKCS11_CKM_AES_ECB_ENCRYPT_DATA	<------------------- TODO
	case PKCS11_CKM_AES_CBC_ENCRYPT_DATA	<------------------- TODO
	case PKCS11_CKM_SHA1_KEY_DERIVATION
	case PKCS11_CKM_SHA224_KEY_DERIVATION
	case PKCS11_CKM_SHA256_KEY_DERIVATION
	case PKCS11_CKM_SHA384_KEY_DERIVATION
	case PKCS11_CKM_SHA512_KEY_DERIVATION
	case PKCS11_CKM_SHA512_224_KEY_DERIVATION
	case PKCS11_CKM_SHA512_256_KEY_DERIVATION
	case PKCS11_CKM_SHA512_T_KEY_DERIVATION
	// Exhaustive list is made of Camelia, Aria, Seed, KIP, GOSTR3410,
	// DES, 3DES, SSL3, TLS12, TLS-KDF, WTLS and concatenate  mechanisms.
	case PKCS11_CKM_ECMQV_DERIVE:
	}
#endif

	mecha_id = proc_params->id;
	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rv = create_object(session, head, &out_handle);
	if (rv)
		goto bail;

	/*
	 * Now out_handle (through the related struct pkcs11_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &out_handle, sizeof(out_handle));
	out->memref.size = sizeof(out_handle);

	DMSG("PKCS11 session %"PRIu32": derive key %#"PRIx32"/%s",
	     session->handle, out_handle, id2str_proc(mecha_id));

bail:
	release_active_processing(session);
	TEE_Free(proc_params);
	TEE_Free(template);
	TEE_Free(head);

	return rv;
}
