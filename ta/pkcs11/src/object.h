/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_OBJECT_H
#define PKCS11_TA_OBJECT_H

#include <sys/queue.h>
#include <tee_internal_api.h>

struct pkcs11_client;
struct pkcs11_session;

struct pkcs11_object {
	LIST_ENTRY(pkcs11_object) link;
	/* pointer to the serialized object attributes */
	void *attributes;
	TEE_ObjectHandle key_handle;	/* Valid handle for TEE operations */
	uint32_t key_type;		/* TEE type of key_handle */

	/* These are for persistent/token objects */
	TEE_UUID *uuid;
	TEE_ObjectHandle attribs_hdl;
};

LIST_HEAD(object_list, pkcs11_object);

struct pkcs11_object *pkcs11_handle2object(uint32_t client_handle,
					   struct pkcs11_session *session);

uint32_t pkcs11_object2handle(struct pkcs11_object *obj,
			      struct pkcs11_session *session);

struct pkcs11_object *create_token_object(struct obj_attrs *head,
					  TEE_UUID *uuid);

uint32_t create_object(void *session, struct obj_attrs *attributes,
		       uint32_t *handle);

void destroy_object(struct pkcs11_session *session,
		    struct pkcs11_object *object, bool session_object_only);

/*
 * Entry function called from the PKCS11 command parser
 */
uint32_t entry_import_object(struct pkcs11_client *client,
			     uint32_t ptypes, TEE_Param *params);

uint32_t entry_destroy_object(struct pkcs11_client *client,
			      uint32_t ptypes, TEE_Param *params);

uint32_t entry_find_objects_init(struct pkcs11_client *client,
				 uint32_t ptypes, TEE_Param *params);

uint32_t entry_find_objects(struct pkcs11_client *client,
			    uint32_t ptypes, TEE_Param *params);

uint32_t entry_find_objects_final(struct pkcs11_client *client,
				  uint32_t ptypes, TEE_Param *params);

uint32_t entry_get_attribute_value(struct pkcs11_client *client,
				   uint32_t ptypes, TEE_Param *params);

uint32_t entry_get_object_size(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params);

void release_session_find_obj_context(struct pkcs11_session *session);

#endif /*PKCS11_TA_OBJECT_H*/
