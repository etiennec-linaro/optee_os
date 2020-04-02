/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_HELPERS_H
#define PKCS11_HELPERS_H

#include <pkcs11_ta.h>
#include <stdint.h>
#include <stddef.h>
#include <tee_internal_api.h>

#include <token_capabilities.h>

/* Short aliases for return code */
#define PKCS11_OK			PKCS11_CKR_OK
#define PKCS11_ERROR			PKCS11_CKR_GENERAL_ERROR
#define PKCS11_MEMORY			PKCS11_CKR_DEVICE_MEMORY
#define PKCS11_BAD_PARAM		PKCS11_CKR_ARGUMENTS_BAD
#define PKCS11_SHORT_BUFFER		PKCS11_CKR_BUFFER_TOO_SMALL
#define PKCS11_FAILED			PKCS11_CKR_FUNCTION_FAILED
#define PKCS11_NOT_FOUND		PKCS11_RV_NOT_FOUND
#define PKCS11_NOT_IMPLEMENTED		PKCS11_RV_NOT_IMPLEMENTED

/*
 * TEE invocation parameter#0 is an in/out buffer of at least 32bit
 * to store the TA PKCS#11 compliant return value.
 */
#define TEE_PARAM0_SIZE_MIN		sizeof(uint32_t)

struct pkcs11_object;

/*
 * Return true if and only if attribute ID with companion attribute value
 * size do match a valid attribute identifier.
 *
 * @attribute_id - Target PKCS11 attribute ID
 * @size - Byte size of the attribute value, 0 if non-constant size
 */
bool valid_pkcs11_attribute_id(uint32_t attribute_id, uint32_t size);

/*
 * Return class attribute byte size if @attribute_id is the ID of a class
 * attribute or 0 if not.
 */
size_t pkcs11_attr_is_class(uint32_t attribute_id);

/*
 * Return type attribute byte size if @attribute_id is the ID of a type
 * attribute or 0 if not.
 */
size_t pkcs11_attr_is_type(uint32_t attribute_id);

/* Return true if the object class has boolprop attribute(s) */
bool pkcs11_class_has_boolprop(uint32_t class);

/* Return true if the object class is related to a type-on-class */
bool pkcs11_class_has_type(uint32_t class_id);

/* Return true if the object class relates to a key */
bool pkcs11_attr_class_is_key(uint32_t class_id);

/* Return true if the key type @attribute_id relates to a symmetric key */
bool key_type_is_symm_key(uint32_t key_type_id);

/* Return true if the key type @attribute_id relates to a asymmetric key */
bool key_type_is_asymm_key(uint32_t key_type_id);

/* Boolprop flag shift position if @attribute_id is boolean, else -1 */
int pkcs11_attr2boolprop_shift(uint32_t attribute_id);

/* Convert PKCS11 TA function ID into a TEE crypto operation mode */
void pkcs2tee_mode(uint32_t *tee_id, uint32_t function);

/* Load TEE operation attributes from a PKCS11 object, return false on error */
bool pkcs2tee_load_attr(TEE_Attribute *tee_ref, uint32_t tee_id,
			struct pkcs11_object *obj, uint32_t pkcs11_id);

/*
 * Convert PKCS11 TA return code into a GPD TEE result ID when matching.
 * If not, return a TEE success (_noerr) or a generic error (_error).
 */
TEE_Result pkcs2tee_noerr(uint32_t rv);
TEE_Result pkcs2tee_error(uint32_t rv);
uint32_t tee2pkcs_error(TEE_Result res);

#if CFG_TEE_TA_LOG_LEVEL > 0
/* Id-to-string conversions only for trace support */
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
const char *id2str_session_flag(uint32_t id);
const char *id2str_session_state(uint32_t id);
const char *id2str_proc(uint32_t id);
const char *id2str_function(uint32_t id);

static inline const char *id2str_mechanism(enum pkcs11_mechanism_id id)
{
	return mechanism_string_id(id);
}
#endif /* CFG_TEE_TA_LOG_LEVEL > 0 */
#endif /*PKCS11_HELPERS_H*/
