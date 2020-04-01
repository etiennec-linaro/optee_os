// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <pkcs11_ta.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "pkcs11_token.h"
#include "pkcs11_helpers.h"

#define PERSISTENT_OBJECT_ID_LEN	32

/*
 * Token persistent objects
 *
 * The persistent objects are each identified by a UUID.
 * The persistent object database stores the list of the UUIDs registered. For
 * each it is expected that a file of ID "UUID" is store in the OP-TEE secure
 * storage.
 */
static TEE_Result get_db_file_name(struct ck_token *token,
				   char *name, size_t size)
{
	int n = snprintf(name, size, "token.db.%u", get_token_id(token));

	if (n < 0 || (size_t)n >= size)
		return TEE_ERROR_SECURITY;
	else
		return TEE_SUCCESS;
}

static TEE_Result open_db_file(struct ck_token *token,
			       TEE_ObjectHandle *out_hdl)
{
	char file[PERSISTENT_OBJECT_ID_LEN] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	res = get_db_file_name(token, file, sizeof(file));
	if (res)
		return res;

	return TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, file, sizeof(file),
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE,
					out_hdl);
}

static TEE_Result get_pin_file_name(struct ck_token *token,
				    enum pkcs11_user_type user,
				    char *name, size_t size)
{
	int n = snprintf(name, size,
			 "token.db.%u-pin%d", get_token_id(token), user);

	if (n < 0 || (size_t)n >= size)
		return TEE_ERROR_SECURITY;
	else
		return TEE_SUCCESS;
}

TEE_Result open_pin_file(struct ck_token *token, enum pkcs11_user_type user,
			 TEE_ObjectHandle *out_hdl)
{
	char file[PERSISTENT_OBJECT_ID_LEN] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	res = get_pin_file_name(token, user, file, sizeof(file));
	if (res)
		return res;

	return TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, file, sizeof(file),
					0, out_hdl);
}


uint32_t update_persistent_db(struct ck_token *token, size_t offset,
			      size_t size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;
	uint8_t *field = (uint8_t *)token->db_main + offset;

	res = open_db_file(token, &db_hdl);
	if (!res)
		res = TEE_SeekObjectData(db_hdl, offset, TEE_DATA_SEEK_SET);
	if (!res)
		res = TEE_WriteObjectData(db_hdl, field, size);

	TEE_CloseObject(db_hdl);

	if (!res)
		return PKCS11_CKR_OK;

	return tee2pkcs_error(res);

}

static void init_pin_keys(struct ck_token *token, enum pkcs11_user_type user)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle key_hdl = TEE_HANDLE_NULL;

	res = open_pin_file(token, user, &key_hdl);

	if (res == TEE_SUCCESS)
		DMSG("PIN key found");

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		TEE_Attribute attr = { };
		TEE_ObjectHandle hdl = TEE_HANDLE_NULL;
		uint8_t pin_key[16] = { };
		char file[PERSISTENT_OBJECT_ID_LEN] = { };

		TEE_MemFill(&attr, 0, sizeof(attr));

		TEE_GenerateRandom(pin_key, sizeof(pin_key));
		TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
				     pin_key, sizeof(pin_key));

		res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &hdl);
		if (res)
			TEE_Panic(0);

		res = TEE_PopulateTransientObject(hdl, &attr, 1);
		if (res)
			TEE_Panic(0);

		res = get_pin_file_name(token, user, file, sizeof(file));
		if (res)
			TEE_Panic(0);

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 file, sizeof(file), 0, hdl,
						 pin_key, sizeof(pin_key),
						 &key_hdl);
		TEE_CloseObject(hdl);

		if (res == TEE_SUCCESS)
			DMSG("Token %u: PIN key created", get_token_id(token));
	}

	if (res)
		TEE_Panic(res);

	TEE_CloseObject(key_hdl);
}

/*
 * Release resources relate to persistent database
 */
void close_persistent_db(struct ck_token *token __unused)
{
}

/* UUID for persistent object */
uint32_t create_object_uuid(struct ck_token *token __unused,
			    struct pkcs11_object *obj)
{
	assert(!obj->uuid);

	obj->uuid = TEE_Malloc(sizeof(TEE_UUID),
			       TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!obj->uuid)
		return PKCS11_MEMORY;

	TEE_GenerateRandom(obj->uuid, sizeof(TEE_UUID));

	/*
	 * TODO: check uuid against already registered one (in persistent
	 * database) and the pending created uuids (not already registered
	 * if any).
	 */
	return PKCS11_OK;
}

void destroy_object_uuid(struct ck_token *token __unused,
			 struct pkcs11_object *obj)
{
	if (!obj->uuid)
		return;

	/* TODO: check uuid is not still registered in persistent db ? */
	TEE_Free(obj->uuid);
	obj->uuid = NULL;
}

uint32_t get_persistent_objects_list(struct ck_token *token,
				     TEE_UUID *array, size_t *size)
{
	size_t out_size = *size;

	*size = token->db_objs->count * sizeof(TEE_UUID);

	if (out_size < *size)
		return PKCS11_SHORT_BUFFER;

	if (array)
		TEE_MemMove(array, token->db_objs->uuids, *size);

	return PKCS11_OK;
}

uint32_t unregister_persistent_object(struct ck_token *token, TEE_UUID *uuid)
{
	int index = 0;
	int count = 0;
	struct token_persistent_objs *ptr;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;

	if (!uuid)
		return PKCS11_CKR_OK;

	for (index = (int)(token->db_objs->count) - 1; index >= 0; index--)
		if (!TEE_MemCompare(token->db_objs->uuids + index,
				    uuid, sizeof(TEE_UUID)))
			break;

	if (index < 0) {
		DMSG("Cannot unregister an invalid persistent object");
		return PKCS11_RV_NOT_FOUND;
	}

	ptr = TEE_Malloc(sizeof(struct token_persistent_objs) +
			 ((token->db_objs->count - 1) * sizeof(TEE_UUID)),
			 TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!ptr)
		return PKCS11_CKR_DEVICE_MEMORY;

	res = open_db_file(token, &db_hdl);
	if (res)
		goto out;

	res = TEE_SeekObjectData(db_hdl, sizeof(struct token_persistent_main),
				 TEE_DATA_SEEK_SET);
	if (res) {
		DMSG("Failed to read database");
		goto out;
	}

	TEE_MemMove(ptr, token->db_objs,
		    sizeof(struct token_persistent_objs) +
		    index * sizeof(TEE_UUID));

	ptr->count--;
	count = ptr->count - index;

	TEE_MemMove(&ptr->uuids[index],
		    &token->db_objs->uuids[index + 1],
		    count * sizeof(TEE_UUID));

	res = TEE_WriteObjectData(db_hdl, ptr,
				  sizeof(struct token_persistent_objs) +
				  ptr->count * sizeof(TEE_UUID));
	if (res)
		DMSG("Failed to update database");

out:
	TEE_CloseObject(db_hdl);

	TEE_Free(token->db_objs);
	token->db_objs = ptr;

	if (res) {
		TEE_Free(ptr);
		tee2pkcs_error(res);
	}

	return PKCS11_OK;
}

uint32_t register_persistent_object(struct ck_token *token, TEE_UUID *uuid)
{
	int count = 0;
	void *ptr = NULL;
	size_t __maybe_unused size = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;

	for (count = (int)token->db_objs->count - 1; count >= 0; count--)
		if (!TEE_MemCompare(token->db_objs->uuids + count, uuid,
				    sizeof(TEE_UUID)))
			TEE_Panic(0);

	count = token->db_objs->count;
	ptr = TEE_Realloc(token->db_objs,
			  sizeof(struct token_persistent_objs) +
			  ((count + 1) * sizeof(TEE_UUID)));
	if (!ptr)
		return PKCS11_CKR_DEVICE_MEMORY;

	token->db_objs = ptr;
	TEE_MemMove(token->db_objs->uuids + count, uuid, sizeof(TEE_UUID));

	size = sizeof(struct token_persistent_main) +
	       sizeof(struct token_persistent_objs) +
	       count * sizeof(TEE_UUID);

	res = open_db_file(token, &db_hdl);
	if (res)
		goto out;

	res = TEE_TruncateObjectData(db_hdl, size + sizeof(TEE_UUID));
	if (res)
		goto out;

	res = TEE_SeekObjectData(db_hdl, sizeof(struct token_persistent_main),
				 TEE_DATA_SEEK_SET);
	if (res)
		goto out;

	token->db_objs->count++;

	res = TEE_WriteObjectData(db_hdl, token->db_objs,
				  sizeof(struct token_persistent_objs) +
				  token->db_objs->count * sizeof(TEE_UUID));
	if (res)
		token->db_objs->count--;

out:
	if (db_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(db_hdl);

	if (!res)
		return PKCS11_OK;

	return tee2pkcs_error(res);
}

/*
 * Return the token instance, either initialized from reset or initialized
 * from the token persistent state if found.
 */
struct ck_token *init_persistent_db(unsigned int token_id)
{
	struct ck_token *token = get_token(token_id);
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;
	/* Copy persistent database: main db and object db */
	struct token_persistent_main *db_main = NULL;
	struct token_persistent_objs *db_objs = NULL;
	void *ptr = NULL;

	if (!token)
		return NULL;

	init_pin_keys(token, PKCS11_CKU_SO);
	init_pin_keys(token, PKCS11_CKU_USER);
	COMPILE_TIME_ASSERT(PKCS11_CKU_SO == 0 && PKCS11_CKU_USER == 1 &&
			    PKCS11_MAX_USERS >= 2);

	LIST_INIT(&token->object_list);

	db_main = TEE_Malloc(sizeof(*db_main), TEE_MALLOC_FILL_ZERO);
	db_objs = TEE_Malloc(sizeof(*db_objs), TEE_MALLOC_FILL_ZERO);
	if (!db_main || !db_objs)
		goto error;

	res = open_db_file(token, &db_hdl);

	if (res == TEE_SUCCESS) {
		uint32_t size = 0;
		size_t idx = 0;

		IMSG("PKCS11 token %u: load db", token_id);

		size = sizeof(*db_main);
		res = TEE_ReadObjectData(db_hdl, db_main, size, &size);
		if (res || size != sizeof(*db_main))
			TEE_Panic(0);

		size = sizeof(*db_objs);
		res = TEE_ReadObjectData(db_hdl, db_objs, size, &size);
		if (res || size != sizeof(*db_objs))
			TEE_Panic(0);

		size += db_objs->count * sizeof(TEE_UUID);
		ptr = TEE_Realloc(db_objs, size);
		if (!ptr)
			goto error;

		db_objs = ptr;
		size -= sizeof(struct token_persistent_objs);
		res = TEE_ReadObjectData(db_hdl, db_objs->uuids, size, &size);
		if (res || size != (db_objs->count * sizeof(TEE_UUID)))
			TEE_Panic(0);

		for (idx = 0; idx < db_objs->count; idx++) {
			/* Create an empty object instance */
			struct pkcs11_object *obj = NULL;
			TEE_UUID *uuid = NULL;

			uuid = TEE_Malloc(sizeof(TEE_UUID),
					  TEE_USER_MEM_HINT_NO_FILL_ZERO);
			if (!uuid)
				goto error;

			TEE_MemMove(uuid, &db_objs->uuids[idx], sizeof(*uuid));

			obj = create_token_object(NULL, uuid);
			if (!obj)
				TEE_Panic(0);

			LIST_INSERT_HEAD(&token->object_list, obj, link);
		}

	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		char file[32] = { };

		IMSG("PKCS11 token %u: init db", token_id);

		TEE_MemFill(db_main, 0, sizeof(*db_main));
		TEE_MemFill(db_main->label, '*', sizeof(db_main->label));

		/*
		 * Not supported:
		 *   PKCS11_TOKEN_FULLY_RESTORABLE
		 * TODO: check these:
		 *   PKCS11_TOKEN_HAS_CLOCK => related to TEE time secure level
		 */
		db_main->flags = PKCS11_CKFT_SO_PIN_TO_BE_CHANGED |
				 PKCS11_CKFT_USER_PIN_TO_BE_CHANGED |
				 PKCS11_CKFT_RNG |
				 PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS |
				 PKCS11_CKFT_LOGIN_REQUIRED;

		res = get_db_file_name(token, file, sizeof(file));
		if (res)
			TEE_Panic(0);

		/* Object stores persistent state + persistent object references */
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 file, sizeof(file),
						 TEE_DATA_FLAG_ACCESS_READ |
						 TEE_DATA_FLAG_ACCESS_WRITE,
						 TEE_HANDLE_NULL,
						 db_main, sizeof(*db_main),
						 &db_hdl);
		if (res) {
			EMSG("Failed to create db: %"PRIx32, res);
			goto error;
		}

		res = TEE_TruncateObjectData(db_hdl, sizeof(*db_main) +
						     sizeof(*db_objs));
		if (res)
			TEE_Panic(0);

		res = TEE_SeekObjectData(db_hdl, sizeof(*db_main),
					 TEE_DATA_SEEK_SET);
		if (res)
			TEE_Panic(0);

		db_objs->count = 0;
		res = TEE_WriteObjectData(db_hdl, db_objs, sizeof(*db_objs));
		if (res)
			TEE_Panic(0);

	} else {
		goto error;
	}

	token->db_main = db_main;
	token->db_objs = db_objs;
	TEE_CloseObject(db_hdl);

	return token;

error:
	TEE_Free(db_main);
	TEE_Free(db_objs);
	if (db_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(db_hdl);

	return NULL;
}
