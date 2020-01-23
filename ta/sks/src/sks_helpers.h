/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_TA_PKCS11_HELPERS_H
#define PKCS11_TA_PKCS11_HELPERS_H

#include <sks_ta.h>
#include <stdint.h>
#include <stddef.h>
#include <tee_internal_api.h>

/* Short aliases for return code */
#define PKCS11_OK			PKCS11_CKR_OK
#define PKCS11_ERROR			PKCS11_CKR_GENERAL_ERROR
#define PKCS11_MEMORY			PKCS11_CKR_DEVICE_MEMORY
#define PKCS11_BAD_PARAM		PKCS11_CKR_ARGUMENTS_BAD
#define PKCS11_SHORT_BUFFER		PKCS11_CKR_BUFFER_TOO_SMALL
#define PKCS11_FAILED			PKCS11_CKR_FUNCTION_FAILED
#define PKCS11_NOT_FOUND		PKCS11_RV_NOT_FOUND
#define PKCS11_NOT_IMPLEMENTED		PKCS11_RV_NOT_IMPLEMENTED

struct pkcs11_object;

/*
 * Helper functions to analyse CK fields
 */
bool valid_pkcs11_attribute_id(uint32_t id, uint32_t size);
size_t pkcs11_attr_is_class(uint32_t attribute_id);
size_t pkcs11_attr_is_type(uint32_t attribute_id);
bool pkcs11_class_has_boolprop(uint32_t class);
bool pkcs11_class_has_type(uint32_t class);
bool pkcs11_attr_class_is_key(uint32_t class);
bool key_type_is_symm_key(uint32_t id);
bool key_type_is_asymm_key(uint32_t id);
int pkcs11_attr2boolprop_shift(uint32_t attr);
bool mechanism_is_valid(uint32_t id);
bool mechanism_is_supported(uint32_t id);
size_t get_supported_mechanisms(uint32_t *array, size_t array_count);

void pkcs2tee_mode(uint32_t *tee_id, uint32_t function);
bool pkcs2tee_load_attr(TEE_Attribute *tee_ref, uint32_t tee_id,
			struct pkcs11_object *obj, uint32_t pkcs11_id);

/*
 * Convert PKCS11 TA return code into a GPD TEE result ID when matching.
 * If not, return a TEE success (_noerr) or generic error (_error).
 */
TEE_Result pkcs2tee_noerr(uint32_t rv);
TEE_Result pkcs2tee_error(uint32_t rv);
uint32_t tee2pkcs_error(TEE_Result res);

/* Id-to-string conversions when CFG_TEE_TA_LOG_LEVEL > 0 */
const char *id2str_attr_value(uint32_t id, size_t size, void *value);
const char *id2str_attr(uint32_t id);
const char *id2str_class(uint32_t id);
const char *id2str_type(uint32_t id, uint32_t class);
const char *id2str_key_type(uint32_t id);
const char *id2str_boolprop(uint32_t id);
const char *id2str_ta_cmd(uint32_t id);
const char *id2str_rc(uint32_t id);
const char *id2str_proc_flag(uint32_t id);
const char *id2str_slot_flag(uint32_t id);
const char *id2str_token_flag(uint32_t id);
const char *id2str_proc(uint32_t id);
const char *id2str_function(uint32_t id);

#endif /*PKCS11_TA_PKCS11_HELPERS_H*/
