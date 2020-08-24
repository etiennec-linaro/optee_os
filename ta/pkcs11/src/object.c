// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <inttypes.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "sanitize_object.h"
#include "serializer.h"

struct pkcs11_object *pkcs11_handle2object(uint32_t handle,
				     struct pkcs11_session *session)
{
	return handle_lookup(&session->object_handle_db, handle);
}

uint32_t pkcs11_object2handle(struct pkcs11_object *obj,
			   struct pkcs11_session *session)
{
	return handle_lookup_handle(&session->object_handle_db, obj);
}

/* Currently handle pkcs11 sessions and tokens */

static struct object_list *get_session_objects(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_get_session_objects(ck_session);
}

static struct ck_token *get_session_token(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_session2token(ck_session);
}

/* Release non-persistent resources of an object */
static void cleanup_volatile_obj_ref(struct pkcs11_object *obj)
{
	if (!obj)
		return;

	if (obj->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj->key_handle);

	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(obj->attribs_hdl);

	TEE_Free(obj->attributes);
	TEE_Free(obj->uuid);
	TEE_Free(obj);
}

/* Release resources of a persistent object including volatile resources */
static void cleanup_persistent_object(struct pkcs11_object *obj,
				      struct ck_token *token)
{
	TEE_Result res;

	if (!obj)
		return;

	/* Open handle with write properties to destroy the object */
	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(obj->attribs_hdl);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       obj->uuid, sizeof(TEE_UUID),
				       TEE_DATA_FLAG_ACCESS_WRITE_META,
				       &obj->attribs_hdl);
	assert(!res);
	if (res)
		goto out;

	TEE_CloseAndDeletePersistentObject1(obj->attribs_hdl);

out:
	obj->attribs_hdl = TEE_HANDLE_NULL;
	destroy_object_uuid(token, obj);

	LIST_REMOVE(obj, link);

	cleanup_volatile_obj_ref(obj);
}

/*
 * destroy_object - destroy an PKCS11 TA object
 *
 * @session - session requesting object destruction
 * @object - reference to the PKCS11 TA object
 * @session_only - true if only session object shall be destroyed
 */
void destroy_object(struct pkcs11_session *session, struct pkcs11_object *obj,
		    bool session_only)
{
#ifdef DEBUG
	trace_attributes("[destroy]", obj->attributes);
	if (obj->uuid)
		MSG_RAW("[destroy] obj uuid %pUl", (void *)obj->uuid);
#endif

	/* Remove from session list only if was published */
	if (obj->link.le_next || obj->link.le_prev)
		LIST_REMOVE(obj, link);

	if (session_only) {
		/* Destroy object due to session closure */
		handle_put(&session->object_handle_db,
			   pkcs11_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);

		return;
	}

	/* Destroy target object (persistent or not) */
	if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
		assert(obj->uuid);
		/* Try twice otherwise panic! */
		if (unregister_persistent_object(session->token, obj->uuid) &&
		    unregister_persistent_object(session->token, obj->uuid))
			TEE_Panic(0);

		cleanup_persistent_object(obj, session->token);
		handle_put(&session->object_handle_db,
			   pkcs11_object2handle(obj, session));
	} else {
		handle_put(&session->object_handle_db,
			   pkcs11_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);
	}
}

static struct pkcs11_object *create_obj_instance(struct obj_attrs *head)
{
	struct pkcs11_object *obj = NULL;

	obj = TEE_Malloc(sizeof(struct pkcs11_object), TEE_MALLOC_FILL_ZERO);
	if (!obj)
		return NULL;

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attribs_hdl = TEE_HANDLE_NULL;
	obj->attributes = head;

	return obj;
}

struct pkcs11_object *create_token_object(struct obj_attrs *head,
					  TEE_UUID *uuid)
{
	struct pkcs11_object *obj = create_obj_instance(head);

	if (obj)
		obj->uuid = uuid;

	return obj;
}

/*
 * create_object - create an PKCS11 TA object from its attributes and value
 *
 * @session - session requesting object creation
 * @attributes - reference to serialized attributes
 * @handle - generated handle for the created object
 */
uint32_t create_object(void *sess, struct obj_attrs *head,
		       uint32_t *out_handle)
{
	uint32_t rv = 0;
	TEE_Result res = TEE_SUCCESS;
	struct pkcs11_object *obj = NULL;
	struct pkcs11_session *session = (struct pkcs11_session *)sess;
	uint32_t obj_handle = 0;

#ifdef DEBUG
	trace_attributes("[create]", head);
#endif

	/*
	 * We do not check the key attributes. At this point, key attributes
	 * are expected consistent and reliable.
	 */

	obj = create_obj_instance(head);
	if (!obj)
		return PKCS11_CKR_DEVICE_MEMORY;

	/* Create a handle for the object in the session database */
	obj_handle = handle_get(&session->object_handle_db, obj);
	if (!obj_handle) {
		rv = PKCS11_CKR_DEVICE_MEMORY;
		goto bail;
	}

	if (get_bool(obj->attributes, PKCS11_CKA_TOKEN)) {
		/*
		 * Get an ID for the persistent object
		 * Create the file
		 * Register the object in the persistent database
		 * (move the full sequence to persisent_db.c?)
		 */
		size_t size = attributes_size(obj->attributes);
		uint32_t tee_obj_flags = TEE_DATA_FLAG_ACCESS_READ |
					 TEE_DATA_FLAG_ACCESS_WRITE |
					 TEE_DATA_FLAG_ACCESS_WRITE_META;

		rv = create_object_uuid(get_session_token(session), obj);
		if (rv)
			goto bail;

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj->uuid, sizeof(TEE_UUID),
						 tee_obj_flags,
						 TEE_HANDLE_NULL,
						 obj->attributes, size,
						 &obj->attribs_hdl);
		if (res) {
			rv = tee2pkcs_error(res);
			goto bail;
		}

		rv = register_persistent_object(get_session_token(session),
						obj->uuid);
		if (rv)
			goto bail;

		LIST_INSERT_HEAD(&session->token->object_list, obj, link);
	} else {
		rv = PKCS11_CKR_OK;
		LIST_INSERT_HEAD(get_session_objects(session), obj, link);
	}


	*out_handle = obj_handle;

bail:
	if (rv) {
		handle_put(&session->object_handle_db, obj_handle);
		if (get_bool(obj->attributes, PKCS11_CKA_TOKEN))
			cleanup_persistent_object(obj, session->token);
		else
			cleanup_volatile_obj_ref(obj);
	}

	return rv;
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
	struct obj_attrs *head = NULL;
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

	template_size = sizeof(*template) + template->attrs_size;

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

uint32_t entry_destroy_object(struct pkcs11_client *client,
			      uint32_t ptypes, TEE_Param *params)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	struct serialargs ctrlargs = { };
	uint32_t object_handle = 0;
	struct pkcs11_session *session = NULL;
	struct pkcs11_object *object = NULL;
	uint32_t rv = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	object = pkcs11_handle2object(object_handle, session);
	if (!object)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	destroy_object(session, object, false);

	DMSG("PKCS11 session %"PRIu32": destroy object %#"PRIx32,
	     session->handle, object_handle);

	return rv;
}

static uint32_t token_obj_matches_ref(struct obj_attrs *req_attrs,
				      struct pkcs11_object *obj)
{
	uint32_t rv = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle hdl = obj->attribs_hdl;
	TEE_ObjectInfo info = { };
	struct obj_attrs *attr = NULL;
	uint32_t read_bytes = 0;

	if (obj->attributes) {
		if (!attributes_match_reference(obj->attributes, req_attrs))
			return PKCS11_RV_NOT_FOUND;

		return PKCS11_CKR_OK;
	}

	if (hdl == TEE_HANDLE_NULL) {
		res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					       obj->uuid, sizeof(*obj->uuid),
					       TEE_DATA_FLAG_ACCESS_READ,
					       &hdl);
		if (res) {
			EMSG("OpenPersistent failed %#"PRIx32, res);
			return tee2pkcs_error(res);
		}
	}

	res = TEE_GetObjectInfo1(hdl, &info);
	if (res) {
		EMSG("GetObjectInfo failed %#"PRIx32, res);
		rv = tee2pkcs_error(res);
		goto bail;
	}

	attr = TEE_Malloc(info.dataSize, TEE_MALLOC_FILL_ZERO);
	if (!attr) {
		rv = PKCS11_CKR_DEVICE_MEMORY;
		goto bail;
	}

	res = TEE_ReadObjectData(hdl, attr, info.dataSize, &read_bytes);
	if (!res) {
		res = TEE_SeekObjectData(hdl, 0, TEE_DATA_SEEK_SET);
		if (res)
			EMSG("Seek to 0 failed with %#"PRIx32, res);
	}

	if (res) {
		rv = tee2pkcs_error(res);
		EMSG("Read %"PRIu32" bytes, failed %#"PRIx32,
		     read_bytes, res);
		goto bail;
	}
	if (read_bytes != info.dataSize) {
		EMSG("Read %"PRIu32" bytes, expected %"PRIu32,
		     read_bytes, info.dataSize);
		rv = PKCS11_CKR_GENERAL_ERROR;
		goto bail;
	}

	if (!attributes_match_reference(attr, req_attrs)) {
		rv = PKCS11_RV_NOT_FOUND;
		goto bail;
	}

	obj->attributes = attr;
	attr = NULL;
	obj->attribs_hdl = hdl;
	hdl = TEE_HANDLE_NULL;
	rv = PKCS11_CKR_OK;

bail:
	TEE_Free(attr);
	if (obj->attribs_hdl == TEE_HANDLE_NULL && hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(hdl);

	return rv;
}

static void release_find_obj_context(struct pkcs11_session *session,
				     struct pkcs11_find_objects *find_ctx)
{
	size_t idx = 0;

	if (!find_ctx)
		return;

	/* Release handles not yet published to client */
	idx = find_ctx->next;
	if (idx < find_ctx->temp_start)
		idx = find_ctx->temp_start;

	for (;idx < find_ctx->count; idx++)
		handle_put(&session->object_handle_db, find_ctx->handles[idx]);

	TEE_Free(find_ctx->attributes);
	TEE_Free(find_ctx->handles);
	TEE_Free(find_ctx);
}

uint32_t entry_find_objects_init(struct pkcs11_client *client,
				 uint32_t ptypes, TEE_Param *params)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_object_head *template = NULL;
	struct obj_attrs *req_attrs = NULL;
	struct pkcs11_object *obj = NULL;
	struct pkcs11_find_objects *find_ctx = NULL;

	if (!client || ptypes != exp_pt)
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

	/* Search objects only if no operation is on-going */
	if (session_is_active(session)) {
		rv = PKCS11_CKR_OPERATION_ACTIVE;
		goto bail;
	}

	if (session->find_ctx) {
		EMSG("Active object search already in progress");
		rv = PKCS11_CKR_FUNCTION_FAILED;
		goto bail;
	}

	/* Must zero init the structure */
	find_ctx = TEE_Malloc(sizeof(*find_ctx), TEE_MALLOC_FILL_ZERO);
	if (!find_ctx) {
		rv = PKCS11_CKR_DEVICE_MEMORY;
		goto bail;
	}

	rv = sanitize_client_object(&req_attrs, template,
				    sizeof(*template) + template->attrs_size);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	switch (get_class(req_attrs)) {
	case PKCS11_CKO_UNDEFINED_ID:
	/* Unspecified class searches among data objects */
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_DATA:
		break;
	default:
		EMSG("Find object of class %s (%"PRIu32") is not supported",
		     id2str_class(get_class(req_attrs)),
		     get_class(req_attrs));
		rv = PKCS11_CKR_ARGUMENTS_BAD;
		goto bail;

	}

	/*
	 * Scan all objects (sessions and persistent ones) and set a list of
	 * candidates that match caller attributes. First scan all current
	 * session objects (that are visible to the session). Then scan all
	 * remaining persistent object for which no session object handle was
	 * published to the client.
	 */

	LIST_FOREACH(obj, &session->object_list, link) {
		uint32_t *handles = NULL;

		rv = check_access_attrs_against_token(session, obj->attributes);
		if (rv)
			continue;

		if (!attributes_match_reference(obj->attributes, req_attrs))
			continue;

		handles = TEE_Realloc(find_ctx->handles,
				      (find_ctx->count + 1) * sizeof(*handles));
		if (!handles) {
			rv = PKCS11_CKR_DEVICE_MEMORY;
			goto bail;
		}
		find_ctx->handles = handles;

		*(find_ctx->handles + find_ctx->count) =
			pkcs11_object2handle(obj, session);
		find_ctx->count++;
	}

	/* Remaining handles are those not yet published by the session */
	find_ctx->temp_start = find_ctx->count;

	LIST_FOREACH(obj, &session->token->object_list, link) {
		uint32_t obj_handle = 0;
		uint32_t *handles = NULL;

		/*
		 * If there are no attributes specified, we return
		 * every object
		 */
		if (req_attrs->attrs_count) {
			rv = token_obj_matches_ref(req_attrs, obj);
			if (rv == PKCS11_RV_NOT_FOUND)
				continue;
			if (rv != PKCS11_CKR_OK)
				goto bail;
		}

		rv = check_access_attrs_against_token(session, obj->attributes);
		if (rv)
			continue;

		/* Object may not yet be published in the session */
		obj_handle = pkcs11_object2handle(obj, session);
		if (!obj_handle) {
			obj_handle = handle_get(&session->object_handle_db,
						obj);
			if (!obj_handle) {
				rv = PKCS11_CKR_DEVICE_MEMORY;
				goto bail;
			}
		}

		handles = TEE_Realloc(find_ctx->handles,
				      (find_ctx->count + 1) * sizeof(*handles));
		if (!handles) {
			rv = PKCS11_CKR_DEVICE_MEMORY;
			goto bail;
		}

		/* Store object handle for later publishing */
		find_ctx->handles = handles;
		*(handles + find_ctx->count) = obj_handle;
		find_ctx->count++;
	}

	if (rv == PKCS11_RV_NOT_FOUND)
		rv = PKCS11_CKR_OK;

	/* Save target attributes to search (if needed later) */
	find_ctx->attributes = req_attrs;
	req_attrs = NULL;
	session->find_ctx = find_ctx;
	find_ctx = NULL;
	rv = PKCS11_CKR_OK;

bail:
	TEE_Free(req_attrs);
	TEE_Free(template);
	release_find_obj_context(session, find_ctx);

	return rv;
}

uint32_t entry_find_objects(struct pkcs11_client *client,
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
	struct pkcs11_find_objects *ctx = NULL;
	char *out_handles = NULL;
	size_t out_count = 0;
	size_t count = 0;
	size_t idx = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	out_count = out->memref.size / sizeof(uint32_t);
	out_handles = out->memref.buffer;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	ctx = session->find_ctx;

	/*
	 * TODO: should we check again if these handles are valid?
	 */
	if (!ctx)
		return PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	for (count = 0, idx = ctx->next; idx < ctx->count; idx++, count++) {
		struct pkcs11_object *obj = NULL;

		if (count >= out_count)
			break;

		TEE_MemMove(out_handles + count * sizeof(uint32_t),
			    ctx->handles + idx, sizeof(uint32_t));
		ctx->next = idx + 1;

		if (idx < session->find_ctx->temp_start)
			continue;

		/* Newly published handles: store in session list */
		obj = handle_lookup(&session->object_handle_db,
				    *(ctx->handles + idx));
		if (!obj)
			TEE_Panic(0);

	}

	/* Update output buffer according the number of handles provided */
	out->memref.size = count * sizeof(uint32_t);

	DMSG("PKCS11 session %"PRIu32": finding objects", session->handle);

	return PKCS11_CKR_OK;
}

void release_session_find_obj_context(struct pkcs11_session *session)
{
	release_find_obj_context(session, session->find_ctx);
	session->find_ctx = NULL;
}

uint32_t entry_find_objects_final(struct pkcs11_client *client,
				  uint32_t ptypes, TEE_Param *params)
{
        const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = &params[0];
	uint32_t rv = 0;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!session->find_ctx)
		return PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	release_session_find_obj_context(session);

	return PKCS11_CKR_OK;
}

uint32_t entry_get_attribute_value(struct pkcs11_client *client,
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
	struct pkcs11_object_head *template = NULL;
	struct pkcs11_object *obj = NULL;
	uint32_t object_handle = 0;
	char *cur = NULL;
	size_t len = 0;
	char *end = NULL;
	bool attr_sensitive = 0;
	bool attr_type_invalid = 0;
	bool buffer_too_small = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs)) {
		rv = PKCS11_CKR_ARGUMENTS_BAD;
		goto bail;
	}

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj) {
		rv = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto bail;
	}

	rv = check_access_attrs_against_token(session, obj->attributes);
	if (rv) {
		rv = PKCS11_CKR_OBJECT_HANDLE_INVALID;
		goto bail;
	}

	/* iterate over attributes and set their values */
	/*
	 * 1. If the specified attribute (i.e., the attribute specified by the
	 * type field) for the object cannot be revealed because the object is
	 * sensitive or unextractable, then the ulValueLen field in that triple
	 * is modified to hold the value PKCS11_CK_UNAVAILABLE_INFORMATION.
	 *
	 * 2. Otherwise, if the specified value for the object is invalid (the
	 * object does not possess such an attribute), then the ulValueLen field
	 * in that triple is modified to hold the value
	 * PKCS11_CK_UNAVAILABLE_INFORMATION.
	 *
	 * 3. Otherwise, if the pValue field has the value NULL_PTR, then the
	 * ulValueLen field is modified to hold the exact length of the
	 * specified attribute for the object.
	 *
	 * 4. Otherwise, if the length specified in ulValueLen is large enough
	 * to hold the value of the specified attribute for the object, then
	 * that attribute is copied into the buffer located at pValue, and the
	 * ulValueLen field is modified to hold the exact length of the
	 * attribute.
	 *
	 * 5. Otherwise, the ulValueLen field is modified to hold the value
	 * PKCS11_CK_UNAVAILABLE_INFORMATION.
	 */
	cur = (char *)template + sizeof(struct pkcs11_object_head);
	end = cur + template->attrs_size;

	for (; cur < end; cur += len) {
		struct pkcs11_attribute_head *cli_ref =
			(struct pkcs11_attribute_head *)(void *)cur;

		len = sizeof(*cli_ref) + cli_ref->size;

		/* Check 1. */
		if (!attribute_is_exportable(cli_ref, obj)) {
			cli_ref->size = PKCS11_CK_UNAVAILABLE_INFORMATION;
			attr_sensitive = 1;
			continue;
		}

		/*
		 * We assume that if size is 0, pValue was NULL, so we return
		 * the size of the required buffer for it (3., 4.)
		 */
		rv = get_attribute(obj->attributes, cli_ref->id,
				   cli_ref->size ? cli_ref->data : NULL,
				   &(cli_ref->size));
		/* Check 2. */
		switch (rv) {
		case PKCS11_CKR_OK:
			break;
		case PKCS11_RV_NOT_FOUND:
			cli_ref->size = PKCS11_CK_UNAVAILABLE_INFORMATION;
			attr_type_invalid = 1;
			break;
		case PKCS11_CKR_BUFFER_TOO_SMALL:
			buffer_too_small = 1;
			break;
		default:
			rv = PKCS11_CKR_GENERAL_ERROR;
			goto bail;
		}
	}

	/*
	 * If case 1 applies to any of the requested attributes, then the call
	 * should return the value CKR_ATTRIBUTE_SENSITIVE. If case 2 applies to
	 * any of the requested attributes, then the call should return the
	 * value CKR_ATTRIBUTE_TYPE_INVALID. If case 5 applies to any of the
	 * requested attributes, then the call should return the value
	 * CKR_BUFFER_TOO_SMALL. As usual, if more than one of these error codes
	 * is applicable, Cryptoki may return any of them. Only if none of them
	 * applies to any of the requested attributes will CKR_OK be returned.
	 */

	rv = PKCS11_CKR_OK;
	if (attr_sensitive)
		rv = PKCS11_CKR_ATTRIBUTE_SENSITIVE;
	if (attr_type_invalid)
		rv = PKCS11_CKR_ATTRIBUTE_TYPE_INVALID;
	if (buffer_too_small)
		rv = PKCS11_CKR_BUFFER_TOO_SMALL;

	/* Move updated template to out buffer */
	TEE_MemMove(out->memref.buffer, template, out->memref.size);

	DMSG("PKCS11 session %"PRIu32": get attributes %#"PRIx32,
	     session->handle, object_handle);

bail:
	TEE_Free(template);
	template = NULL;

	return rv;
}

uint32_t entry_get_object_size(struct pkcs11_client *client,
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
	uint32_t object_handle = 0;
	struct pkcs11_object *obj = NULL;
	uint32_t obj_size = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get_session(&ctrlargs, client, &session);
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	obj = pkcs11_handle2object(object_handle, session);
	if (!obj)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	rv = check_access_attrs_against_token(session, obj->attributes);
	if (rv)
		return PKCS11_CKR_OBJECT_HANDLE_INVALID;

	if (out->memref.size != sizeof(uint32_t))
		return PKCS11_CKR_ARGUMENTS_BAD;

	assert(obj->attributes);

	obj_size = ((struct obj_attrs *)obj->attributes)->attrs_size +
		   sizeof(struct obj_attrs);
	TEE_MemMove(out->memref.buffer, &obj_size, sizeof(obj_size));

	return PKCS11_CKR_OK;
}

