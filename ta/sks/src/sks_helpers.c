// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <string.h>
#include <util.h>
#include <tee_internal_api.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "processing.h"
#include "sks_helpers.h"

static const char __maybe_unused unknown[] = "<unknown-identifier>";

struct attr_size {
	uint32_t id;
	uint32_t size;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define PKCS11_ID_SZ(_id, _size)	{ .id = _id, .size = _size, .string = #_id }
#else
#define PKCS11_ID_SZ(_id, _size)	{ .id = _id, .size = _size }
#endif

static const struct attr_size attr_ids[] = {
	PKCS11_ID_SZ(PKCS11_CKA_CLASS, 4),
	PKCS11_ID_SZ(PKCS11_CKA_KEY_TYPE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_VALUE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_VALUE_LEN, 4),
	PKCS11_ID_SZ(PKCS11_CKA_LABEL, 0),
	PKCS11_ID_SZ(PKCS11_CKA_WRAP_TEMPLATE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_UNWRAP_TEMPLATE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_DERIVE_TEMPLATE, 0),
	PKCS11_ID_SZ(PKCS11_CKA_START_DATE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_END_DATE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_OBJECT_ID, 0),
	PKCS11_ID_SZ(PKCS11_CKA_APPLICATION, 0),
	PKCS11_ID_SZ(PKCS11_CKA_MECHANISM_TYPE, 4),
	PKCS11_ID_SZ(PKCS11_CKA_ID, 0),
	PKCS11_ID_SZ(PKCS11_CKA_ALLOWED_MECHANISMS, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EC_POINT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EC_PARAMS, 0),
	PKCS11_ID_SZ(PKCS11_CKA_MODULUS, 0),
	PKCS11_ID_SZ(PKCS11_CKA_MODULUS_BITS, 4),
	PKCS11_ID_SZ(PKCS11_CKA_PUBLIC_EXPONENT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_PRIVATE_EXPONENT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_PRIME_1, 0),
	PKCS11_ID_SZ(PKCS11_CKA_PRIME_2, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EXPONENT_1, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EXPONENT_2, 0),
	PKCS11_ID_SZ(PKCS11_CKA_COEFFICIENT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_SUBJECT, 0),
	PKCS11_ID_SZ(PKCS11_CKA_PUBLIC_KEY_INFO, 0),
	/* Below are boolean attributes */
	PKCS11_ID_SZ(PKCS11_CKA_TOKEN, 1),
	PKCS11_ID_SZ(PKCS11_CKA_PRIVATE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_TRUSTED, 1),
	PKCS11_ID_SZ(PKCS11_CKA_SENSITIVE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_ENCRYPT, 1),
	PKCS11_ID_SZ(PKCS11_CKA_DECRYPT, 1),
	PKCS11_ID_SZ(PKCS11_CKA_WRAP, 1),
	PKCS11_ID_SZ(PKCS11_CKA_UNWRAP, 1),
	PKCS11_ID_SZ(PKCS11_CKA_SIGN, 1),
	PKCS11_ID_SZ(PKCS11_CKA_SIGN_RECOVER, 1),
	PKCS11_ID_SZ(PKCS11_CKA_VERIFY, 1),
	PKCS11_ID_SZ(PKCS11_CKA_VERIFY_RECOVER, 1),
	PKCS11_ID_SZ(PKCS11_CKA_DERIVE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_EXTRACTABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_LOCAL, 1),
	PKCS11_ID_SZ(PKCS11_CKA_NEVER_EXTRACTABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_ALWAYS_SENSITIVE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_MODIFIABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_COPYABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_DESTROYABLE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_ALWAYS_AUTHENTICATE, 1),
	PKCS11_ID_SZ(PKCS11_CKA_WRAP_WITH_TRUSTED, 1),
	/* Specific PKCS11 TA internal attribute ID */
	PKCS11_ID_SZ(PKCS11_CKA_UNDEFINED_ID, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EC_POINT_X, 0),
	PKCS11_ID_SZ(PKCS11_CKA_EC_POINT_Y, 0),
};

struct processing_id {
	uint32_t id;
	bool supported;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define PKCS11_PROCESSING_ID(_id) \
                { .id = (uint32_t)(_id), .supported = true, .string = #_id }
#define PKCS11_UNSUPPORTED_PROCESSING_ID(_id) \
                { .id = (uint32_t)(_id), .supported = false, .string = #_id }
#else
#define PKCS11_PROCESSING_ID(_id) \
                { .id = (uint32_t)(_id), .supported = true }
#define PKCS11_UNSUPPORTED_PROCESSING_ID(_id) \
                { .id = (uint32_t)(_id), .supported = false }
#endif

/*
 * This array centralizes the valid mechanism IDs and whether the
 * current TA implementation supports operation with such mechanism.
 */
static const struct processing_id __maybe_unused processing_ids[] = {
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_ECB),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_CBC),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_AES_CBC_PAD),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_CTR),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_GCM),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_CCM),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_CTS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_GMAC),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_CMAC),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_CMAC_GENERAL),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_ECB_ENCRYPT_DATA),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_CBC_ENCRYPT_DATA),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_KEY_GEN),
        PKCS11_PROCESSING_ID(PKCS11_CKM_GENERIC_SECRET_KEY_GEN),
        PKCS11_PROCESSING_ID(PKCS11_CKM_MD5_HMAC),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA_1_HMAC),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA224_HMAC),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA256_HMAC),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA384_HMAC),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA512_HMAC),
        PKCS11_PROCESSING_ID(PKCS11_CKM_AES_XCBC_MAC),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_EC_KEY_PAIR_GEN),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDSA),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDSA_SHA1),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDSA_SHA224),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDSA_SHA256),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDSA_SHA384),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDSA_SHA512),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDH1_DERIVE),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDH1_COFACTOR_DERIVE),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECMQV_DERIVE),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_ECDH_AES_KEY_WRAP),
        PKCS11_PROCESSING_ID(PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN),
        PKCS11_PROCESSING_ID(PKCS11_CKM_RSA_PKCS),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_RSA_9796),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_RSA_X_509),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA1_RSA_PKCS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_RSA_PKCS_OAEP),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA1_RSA_PKCS_PSS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA256_RSA_PKCS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA384_RSA_PKCS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA512_RSA_PKCS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA256_RSA_PKCS_PSS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA384_RSA_PKCS_PSS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA512_RSA_PKCS_PSS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA224_RSA_PKCS),
        PKCS11_PROCESSING_ID(PKCS11_CKM_SHA224_RSA_PKCS_PSS),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_RSA_AES_KEY_WRAP),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_MD5),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_SHA_1),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_SHA224),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_SHA256),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_SHA384),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_SHA512),
        PKCS11_UNSUPPORTED_PROCESSING_ID(PKCS11_CKM_UNDEFINED_ID)
};

struct string_id {
	uint32_t id;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define PKCS11_ID(_id)		{ .id = _id, .string = #_id }
#else
#define PKCS11_ID(_id)		{ .id = _id }
#endif

static const struct string_id __maybe_unused string_cmd[] = {
	PKCS11_ID(PKCS11_CMD_PING),
	PKCS11_ID(PKCS11_CMD_SLOT_LIST),
	PKCS11_ID(PKCS11_CMD_SLOT_INFO),
	PKCS11_ID(PKCS11_CMD_TOKEN_INFO),
	PKCS11_ID(PKCS11_CMD_MECHANISM_IDS),
	PKCS11_ID(PKCS11_CMD_MECHANISM_INFO),
	PKCS11_ID(PKCS11_CMD_INIT_TOKEN),
	PKCS11_ID(PKCS11_CMD_INIT_PIN),
	PKCS11_ID(PKCS11_CMD_SET_PIN),
	PKCS11_ID(PKCS11_CMD_LOGIN),
	PKCS11_ID(PKCS11_CMD_LOGOUT),
	PKCS11_ID(PKCS11_CMD_OPEN_RO_SESSION),
	PKCS11_ID(PKCS11_CMD_OPEN_RW_SESSION),
	PKCS11_ID(PKCS11_CMD_CLOSE_SESSION),
	PKCS11_ID(PKCS11_CMD_SESSION_INFO),
	PKCS11_ID(PKCS11_CMD_CLOSE_ALL_SESSIONS),
	PKCS11_ID(PKCS11_CMD_GET_SESSION_STATE),
	PKCS11_ID(PKCS11_CMD_SET_SESSION_STATE),
	PKCS11_ID(PKCS11_CMD_IMPORT_OBJECT),
	PKCS11_ID(PKCS11_CMD_COPY_OBJECT),
	PKCS11_ID(PKCS11_CMD_DESTROY_OBJECT),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS_INIT),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS),
	PKCS11_ID(PKCS11_CMD_FIND_OBJECTS_FINAL),
	PKCS11_ID(PKCS11_CMD_GET_OBJECT_SIZE),
	PKCS11_ID(PKCS11_CMD_GET_ATTRIBUTE_VALUE),
	PKCS11_ID(PKCS11_CMD_SET_ATTRIBUTE_VALUE),
	PKCS11_ID(PKCS11_CMD_GENERATE_KEY),
	PKCS11_ID(PKCS11_CMD_ENCRYPT_INIT),
	PKCS11_ID(PKCS11_CMD_DECRYPT_INIT),
	PKCS11_ID(PKCS11_CMD_ENCRYPT_UPDATE),
	PKCS11_ID(PKCS11_CMD_DECRYPT_UPDATE),
	PKCS11_ID(PKCS11_CMD_ENCRYPT_FINAL),
	PKCS11_ID(PKCS11_CMD_DECRYPT_FINAL),
	PKCS11_ID(PKCS11_CMD_ENCRYPT_ONESHOT),
	PKCS11_ID(PKCS11_CMD_DECRYPT_ONESHOT),
	PKCS11_ID(PKCS11_CMD_SIGN_INIT),
	PKCS11_ID(PKCS11_CMD_VERIFY_INIT),
	PKCS11_ID(PKCS11_CMD_SIGN_UPDATE),
	PKCS11_ID(PKCS11_CMD_VERIFY_UPDATE),
	PKCS11_ID(PKCS11_CMD_SIGN_FINAL),
	PKCS11_ID(PKCS11_CMD_VERIFY_FINAL),
	PKCS11_ID(PKCS11_CMD_SIGN_ONESHOT),
	PKCS11_ID(PKCS11_CMD_VERIFY_ONESHOT),
	PKCS11_ID(PKCS11_CMD_DERIVE_KEY),
	PKCS11_ID(PKCS11_CMD_GENERATE_KEY_PAIR),
};

static const struct string_id __maybe_unused string_rc[] = {
	PKCS11_ID(PKCS11_CKR_OK),
	PKCS11_ID(PKCS11_CKR_GENERAL_ERROR),
	PKCS11_ID(PKCS11_CKR_DEVICE_MEMORY),
	PKCS11_ID(PKCS11_CKR_ARGUMENTS_BAD),
	PKCS11_ID(PKCS11_CKR_BUFFER_TOO_SMALL),
	PKCS11_ID(PKCS11_CKR_FUNCTION_FAILED),
	PKCS11_ID(PKCS11_CKR_SIGNATURE_INVALID),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_TYPE_INVALID),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_VALUE_INVALID),
	PKCS11_ID(PKCS11_CKR_OBJECT_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_KEY_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_MECHANISM_INVALID),
	PKCS11_ID(PKCS11_CKR_SESSION_HANDLE_INVALID),
	PKCS11_ID(PKCS11_CKR_SLOT_ID_INVALID),
	PKCS11_ID(PKCS11_CKR_MECHANISM_PARAM_INVALID),
	PKCS11_ID(PKCS11_CKR_TEMPLATE_INCONSISTENT),
	PKCS11_ID(PKCS11_CKR_TEMPLATE_INCOMPLETE),
	PKCS11_ID(PKCS11_CKR_PIN_INCORRECT),
	PKCS11_ID(PKCS11_CKR_PIN_LOCKED),
	PKCS11_ID(PKCS11_CKR_PIN_EXPIRED),
	PKCS11_ID(PKCS11_CKR_PIN_INVALID),
	PKCS11_ID(PKCS11_CKR_PIN_LEN_RANGE),
	PKCS11_ID(PKCS11_CKR_SESSION_EXISTS),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_ONLY),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS),
	PKCS11_ID(PKCS11_CKR_OPERATION_ACTIVE),
	PKCS11_ID(PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED),
	PKCS11_ID(PKCS11_CKR_OPERATION_NOT_INITIALIZED),
	PKCS11_ID(PKCS11_CKR_TOKEN_WRITE_PROTECTED),
	PKCS11_ID(PKCS11_CKR_TOKEN_NOT_PRESENT),
	PKCS11_ID(PKCS11_CKR_TOKEN_NOT_RECOGNIZED),
	PKCS11_ID(PKCS11_CKR_ACTION_PROHIBITED),
	PKCS11_ID(PKCS11_CKR_ATTRIBUTE_READ_ONLY),
	PKCS11_ID(PKCS11_CKR_PIN_TOO_WEAK),
	PKCS11_ID(PKCS11_CKR_CURVE_NOT_SUPPORTED),
	PKCS11_ID(PKCS11_CKR_DOMAIN_PARAMS_INVALID),
	PKCS11_ID(PKCS11_CKR_USER_ALREADY_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_NOT_LOGGED_IN),
	PKCS11_ID(PKCS11_CKR_USER_PIN_NOT_INITIALIZED),
	PKCS11_ID(PKCS11_CKR_USER_TOO_MANY_TYPES),
	PKCS11_ID(PKCS11_CKR_USER_TYPE_INVALID),
	PKCS11_ID(PKCS11_CKR_SESSION_READ_ONLY_EXISTS),
	PKCS11_ID(PKCS11_RV_NOT_FOUND),
	PKCS11_ID(PKCS11_RV_NOT_IMPLEMENTED),
};

static const struct string_id __maybe_unused string_slot_flags[] = {
	PKCS11_ID(PKCS11_CKFS_TOKEN_PRESENT),
	PKCS11_ID(PKCS11_CKFS_REMOVABLE_DEVICE),
	PKCS11_ID(PKCS11_CKFS_HW_SLOT),
};

static const struct string_id __maybe_unused string_token_flags[] = {
	PKCS11_ID(PKCS11_CKFT_RNG),
	PKCS11_ID(PKCS11_CKFT_WRITE_PROTECTED),
	PKCS11_ID(PKCS11_CKFT_LOGIN_REQUIRED),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_INITIALIZED),
	PKCS11_ID(PKCS11_CKFT_RESTORE_KEY_NOT_NEEDED),
	PKCS11_ID(PKCS11_CKFT_CLOCK_ON_TOKEN),
	PKCS11_ID(PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH),
	PKCS11_ID(PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS),
	PKCS11_ID(PKCS11_CKFT_TOKEN_INITIALIZED),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_COUNT_LOW),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_FINAL_TRY),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_LOCKED),
	PKCS11_ID(PKCS11_CKFT_USER_PIN_TO_BE_CHANGED),
	PKCS11_ID(PKCS11_CKFT_SO_PIN_COUNT_LOW),
	PKCS11_ID(PKCS11_CKFT_SO_PIN_FINAL_TRY),
	PKCS11_ID(PKCS11_CKFT_SO_PIN_LOCKED),
	PKCS11_ID(PKCS11_CKFT_SO_PIN_TO_BE_CHANGED),
	PKCS11_ID(PKCS11_CKFT_ERROR_STATE),
};

static const struct string_id __maybe_unused string_class[] = {
	PKCS11_ID(PKCS11_CKO_SECRET_KEY),
	PKCS11_ID(PKCS11_CKO_PUBLIC_KEY),
	PKCS11_ID(PKCS11_CKO_PRIVATE_KEY),
	PKCS11_ID(PKCS11_CKO_OTP_KEY),
	PKCS11_ID(PKCS11_CKO_CERTIFICATE),
	PKCS11_ID(PKCS11_CKO_DATA),
	PKCS11_ID(PKCS11_CKO_DOMAIN_PARAMETERS),
	PKCS11_ID(PKCS11_CKO_HW_FEATURE),
	PKCS11_ID(PKCS11_CKO_MECHANISM),
	PKCS11_ID(PKCS11_CKO_UNDEFINED_ID)
};

static const struct string_id __maybe_unused string_key_type[] = {
	PKCS11_ID(PKCS11_CKK_AES),
	PKCS11_ID(PKCS11_CKK_GENERIC_SECRET),
	PKCS11_ID(PKCS11_CKK_MD5_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA_1_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA224_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA256_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA384_HMAC),
	PKCS11_ID(PKCS11_CKK_SHA512_HMAC),
	PKCS11_ID(PKCS11_CKK_EC),
	PKCS11_ID(PKCS11_CKK_RSA),
	PKCS11_ID(PKCS11_CKK_UNDEFINED_ID)
};

/* Processing IDs not exported in the TA API */
static const struct string_id __maybe_unused string_internal_processing[] = {
	PKCS11_ID(PKCS11_PROCESSING_IMPORT),
	PKCS11_ID(PKCS11_PROCESSING_COPY),
};

static const struct string_id __maybe_unused string_proc_flags[] = {
	PKCS11_ID(PKCS11_CKFM_HW),
	PKCS11_ID(PKCS11_CKFM_ENCRYPT),
	PKCS11_ID(PKCS11_CKFM_DECRYPT),
	PKCS11_ID(PKCS11_CKFM_DIGEST),
	PKCS11_ID(PKCS11_CKFM_SIGN),
	PKCS11_ID(PKCS11_CKFM_SIGN_RECOVER),
	PKCS11_ID(PKCS11_CKFM_VERIFY),
	PKCS11_ID(PKCS11_CKFM_VERIFY_RECOVER),
	PKCS11_ID(PKCS11_CKFM_GENERATE),
	PKCS11_ID(PKCS11_CKFM_GENERATE_PAIR),
	PKCS11_ID(PKCS11_CKFM_WRAP),
	PKCS11_ID(PKCS11_CKFM_UNWRAP),
	PKCS11_ID(PKCS11_CKFM_DERIVE),
	PKCS11_ID(PKCS11_CKFM_EC_F_P),
	PKCS11_ID(PKCS11_CKFM_EC_F_2M),
	PKCS11_ID(PKCS11_CKFM_EC_ECPARAMETERS),
	PKCS11_ID(PKCS11_CKFM_EC_NAMEDCURVE),
	PKCS11_ID(PKCS11_CKFM_EC_UNCOMPRESS),
	PKCS11_ID(PKCS11_CKFM_EC_COMPRESS),
};

static const struct string_id __maybe_unused string_functions[] = {
	PKCS11_ID(PKCS11_FUNCTION_ENCRYPT),
	PKCS11_ID(PKCS11_FUNCTION_DECRYPT),
	PKCS11_ID(PKCS11_FUNCTION_SIGN),
	PKCS11_ID(PKCS11_FUNCTION_VERIFY),
	PKCS11_ID(PKCS11_FUNCTION_DERIVE),
};

/*
 * Helper functions to analyse PKCS11 TA identifiers
 */

size_t pkcs11_attr_is_class(uint32_t attribute_id)
{
	if (attribute_id == PKCS11_CKA_CLASS)
		return sizeof(uint32_t);
	else
		return 0;
}

size_t pkcs11_attr_is_type(uint32_t attribute_id)
{
	switch (attribute_id) {
	case PKCS11_CKA_KEY_TYPE:
	case PKCS11_CKA_MECHANISM_TYPE:
		return sizeof(uint32_t);
	default:
		return 0;
	}
}

bool pkcs11_class_has_type(uint32_t class)
{
	switch (class) {
	case PKCS11_CKO_CERTIFICATE:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_MECHANISM:
	case PKCS11_CKO_HW_FEATURE:
		return 1;
	default:
		return 0;
	}
}

bool pkcs11_attr_class_is_key(uint32_t class)
{
	switch (class) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		return 1;
	default:
		return 0;
	}
}

/* Returns shift position or -1 on error */
int pkcs11_attr2boolprop_shift(uint32_t attr)
{
	COMPILE_TIME_ASSERT(PKCS11_BOOLPROPS_BASE == 0);

	if (attr > PKCS11_BOOLPROPS_LAST)
		return -1;

	return attr;
}

/*
 * Conversion between PKCS11 TA and GPD TEE return codes
 */

TEE_Result pkcs2tee_error(uint32_t rv)
{
	switch (rv) {
	case PKCS11_CKR_OK:
		return TEE_SUCCESS;

	case PKCS11_CKR_ARGUMENTS_BAD:
		return TEE_ERROR_BAD_PARAMETERS;

	case PKCS11_CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case PKCS11_CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;

	default:
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result pkcs2tee_noerr(uint32_t rc)
{
	switch (rc) {
	case PKCS11_CKR_ARGUMENTS_BAD:
		return TEE_ERROR_BAD_PARAMETERS;

	case PKCS11_CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case PKCS11_CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;

	case PKCS11_CKR_GENERAL_ERROR:
		return TEE_ERROR_GENERIC;

	default:
		return TEE_SUCCESS;
	}
}

uint32_t tee2pkcs_error(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return PKCS11_CKR_OK;

	case TEE_ERROR_BAD_PARAMETERS:
		return PKCS11_CKR_ARGUMENTS_BAD;

	case TEE_ERROR_OUT_OF_MEMORY:
		return PKCS11_CKR_DEVICE_MEMORY;

	case TEE_ERROR_SHORT_BUFFER:
		return PKCS11_CKR_BUFFER_TOO_SMALL;

	case TEE_ERROR_MAC_INVALID:
		return PKCS11_CKR_SIGNATURE_INVALID;

	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}
}

bool valid_pkcs11_attribute_id(uint32_t id, uint32_t size)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(attr_ids); n++) {
		if (id != attr_ids[n].id)
			continue;

		/* Check size matches if provided */
		return !attr_ids[n].size || size == attr_ids[n].size;
	}

	return false;
}

bool key_type_is_symm_key(uint32_t id)
{
	switch (id) {
	case PKCS11_CKK_AES:
	case PKCS11_CKK_GENERIC_SECRET:
	case PKCS11_CKK_MD5_HMAC:
	case PKCS11_CKK_SHA_1_HMAC:
	case PKCS11_CKK_SHA224_HMAC:
	case PKCS11_CKK_SHA256_HMAC:
	case PKCS11_CKK_SHA384_HMAC:
	case PKCS11_CKK_SHA512_HMAC:
		return true;
	default:
		return false;
	}
}

bool key_type_is_asymm_key(uint32_t id)
{
	switch (id) {
	case PKCS11_CKK_EC:
	case PKCS11_CKK_RSA:
		return true;
	default:
		return false;
	}
}

bool mechanism_is_valid(uint32_t id)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(processing_ids); n++)
		if (id == processing_ids[n].id)
			return true;

	return false;
}

bool mechanism_is_supported(uint32_t id)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(processing_ids); n++)
		if (processing_ids[n].id == id)
			return processing_ids[n].supported;

	return false;
}

size_t get_supported_mechanisms(uint32_t *array, size_t array_count)
{
	size_t n = 0;
	size_t m = 0;
	size_t count = 0;

	for (n = 0; n < ARRAY_SIZE(processing_ids); n++)
		if (processing_ids[n].supported)
			count++;

	if (array_count == 0)
		return count;

	if (array_count < count) {
		EMSG("Expect well sized array");
		return 0;
	}

	for (n = 0, m = 0; n < ARRAY_SIZE(processing_ids); n++) {
		if (processing_ids[n].supported) {
			array[m] = processing_ids[n].id;
			m++;
		}
	}

	assert(m == count);

	return m;
}

/* Initialize a TEE attribute for a target PKCS11 TA attribute in an object */
bool pkcs2tee_load_attr(TEE_Attribute *tee_ref, uint32_t tee_id,
			struct pkcs11_object *obj, uint32_t pkcs11_id)
{
	void *a_ptr = NULL;
	uint32_t a_size = 0;
	uint32_t data32 = 0;

	switch (tee_id) {
	case TEE_ATTR_ECC_PUBLIC_VALUE_X:
	case TEE_ATTR_ECC_PUBLIC_VALUE_Y:
		// FIXME: workaround until we get parse DER data
		break;
	case TEE_ATTR_ECC_CURVE:
		if (get_attribute_ptr(obj->attributes, PKCS11_CKA_EC_PARAMS,
					&a_ptr, &a_size)) {
			EMSG("Missing EC_PARAMS attribute");
			return false;
		}

		data32 = ec_params2tee_curve(a_ptr, a_size);

		TEE_InitValueAttribute(tee_ref, TEE_ATTR_ECC_CURVE, data32, 0);
		return true;

	default:
		break;
	}

	if (get_attribute_ptr(obj->attributes, pkcs11_id, &a_ptr, &a_size))
		return false;

	TEE_InitRefAttribute(tee_ref, tee_id, a_ptr, a_size);

	return true;
}

/* Easy conversion between PKCS11 TA function of TEE crypto mode */
void pkcs2tee_mode(uint32_t *tee_id, uint32_t function)
{
	switch (function) {
	case PKCS11_FUNCTION_ENCRYPT:
		*tee_id = TEE_MODE_ENCRYPT;
		break;
	case PKCS11_FUNCTION_DECRYPT:
		*tee_id = TEE_MODE_DECRYPT;
		break;
	case PKCS11_FUNCTION_SIGN:
		*tee_id = TEE_MODE_SIGN;
		break;
	case PKCS11_FUNCTION_VERIFY:
		*tee_id = TEE_MODE_VERIFY;
		break;
	case PKCS11_FUNCTION_DERIVE:
		*tee_id = TEE_MODE_DERIVE;
		break;
	default:
		TEE_Panic(function);
	}
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/*
 * Convert a PKCS11 TA ID into its label string
 */
const char *id2str_attr(uint32_t id)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(attr_ids); n++) {
		if (id != attr_ids[n].id)
			continue;

		/* Skip PKCS11_ prefix */
		return (char *)attr_ids[n].string + strlen("PKCS11_CKA_");
	}

	return unknown;
}

static const char *id2str_mechanism_type(uint32_t id)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(processing_ids); n++) {
		if (id != processing_ids[n].id)
			continue;

		/* Skip PKCS11_ prefix */
		return (char *)processing_ids[n].string + strlen("PKCS11_CKM_");
	}

	return unknown;
}

static const char *id2str(uint32_t id, const struct string_id *table,
			  size_t count, const char *prefix)
{
	size_t n = 0;
	const char *str = NULL;

	for (n = 0; n < count; n++) {
		if (id != table[n].id)
			continue;

		str = table[n].string;

		/* Skip prefix provided matches found */
		if (prefix && !TEE_MemCompare(str, prefix, strlen(prefix)))
			str += strlen(prefix);

		return str;
	}

	return unknown;
}

#define ID2STR(id, table, prefix)	\
	id2str(id, table, ARRAY_SIZE(table), prefix)

const char *id2str_rc(uint32_t id)
{
	return ID2STR(id, string_rc, "PKCS11_CKR_");
}

const char *id2str_ta_cmd(uint32_t id)
{
	return ID2STR(id, string_cmd, NULL);
}

const char *id2str_class(uint32_t id)
{
	return ID2STR(id, string_class, "PKCS11_CKO_");
}

const char *id2str_type(uint32_t id, uint32_t class)
{
	switch (class) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		return id2str_key_type(id);
	default:
		return unknown;
	}
}

const char *id2str_key_type(uint32_t id)
{
	return ID2STR(id, string_key_type, "PKCS11_CKK_");
}

const char *id2str_boolprop(uint32_t id)
{
	if (id < 64)
		return id2str_attr(id);

	return unknown;
}

const char *id2str_proc(uint32_t id)
{
	const char *str = ID2STR(id, string_internal_processing,
				 "PKCS11_PROCESSING_");

	if (str != unknown)
		return str;

	return id2str_mechanism_type(id);
}

const char *id2str_proc_flag(uint32_t id)
{
	return ID2STR(id, string_proc_flags, "PKCS11_CKFM_");
}

const char *id2str_slot_flag(uint32_t id)
{
	return ID2STR(id, string_slot_flags, "PKCS11_CKFS_");
}

const char *id2str_token_flag(uint32_t id)
{
	return ID2STR(id, string_token_flags, "PKCS11_CKFT_");
}

const char *id2str_attr_value(uint32_t id, size_t size, void *value)
{
	static const char str_true[] = "TRUE";
	static const char str_false[] = "FALSE";
	static const char str_unknown[] = "*";
	uint32_t type = 0;

	if (pkcs11_attr2boolprop_shift(id) >= 0)
		return !!*(uint8_t *)value ? str_true : str_false;

	if (size < sizeof(uint32_t))
		return str_unknown;

	TEE_MemMove(&type, value, sizeof(uint32_t));

	if (pkcs11_attr_is_class(id))
		return id2str_class(type);

	if (id == PKCS11_CKA_KEY_TYPE)
		return id2str_key_type(type);

	if (id == PKCS11_CKA_MECHANISM_TYPE)
		return id2str_mechanism_type(type);

	return str_unknown;
}

const char *id2str_function(uint32_t id)
{
	return ID2STR(id, string_functions, "PKCS11_FUNCTION_");
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
