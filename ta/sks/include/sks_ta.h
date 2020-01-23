/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_TA_H
#define PKCS11_TA_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#define PKCS11_TA_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
			 { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

/* PKCS11 trusted application version information */
#define PKCS11_TA_VERSION_MAJOR			0
#define PKCS11_TA_VERSION_MINOR			1
#define PKCS11_TA_VERSION_PATCH			0

/* Attribute specific values */
#define PKCS11_UNAVAILABLE_INFORMATION		UINT32_C(0xFFFFFFFF)
#define PKCS11_UNDEFINED_ID			PKCS11_UNAVAILABLE_INFORMATION
#define PKCS11_FALSE				false
#define PKCS11_TRUE				true

/*
 * Note on PKCS#11 TA commands ABI
 *
 * For evolution of the TA API and to not mess with the GPD TEE 4 parameters
 * constraint, all the PKCS11 TA invocation commands use a subset of available
 * the GPD TEE invocation parameter types.
 *
 * Param#0 is used for the so-called control arguments of the invoked command
 * and for providing a PKCS#11 compliant status code for the request command.
 * Param#0 is an in/out memory reference (aka memref[0]). The input buffer
 * stores the command arguments serialized inside. The output buffer will
 * store the 32bit TA return code for the command. Client shall get this
 * return code and override the GPD TEE Client API legacy TEE_Result value.
 *
 * Param#1 is used for input data arguments of the invoked command.
 * It is unused or is a input memory reference, aka memref[1].
 * Evolution of the API may use memref[1] for output data as well.
 *
 * Param#2 is mostly used for output data arguments of the invoked command
 * and for output handles generated from invoked commands.
 * Few commands uses it for a secondary input data buffer argument.
 * It is unused or is a input/output/in-out memory reference, aka memref[2].
 *
 * Param#3 is currently unused and reserved for evolution of the API.
 */

/*
 * PKCS11_CMD_PING		Acknowledge TA presence and return version info
 *
 * Optional invocation parameter (if none, command simply returns with success)
 * [out]        memref[2] = [
 *                      32bit version major value (PKCS11_TA_VERSION_MAJOR),
 *                      32bit version minor value (PKCS11_TA_VERSION_MINOR),
 *                      32bit version patch value (PKCS11_TA_VERSION_PATCH),
 *              ]
 */
#define PKCS11_CMD_PING				0

/*
 * PKCS11_CMD_SLOT_LIST - Get the table of the valid slot IDs
 *
 * [out]        memref[2] = 32bit array slot_ids[slot counts]
 *
 * The TA instance may represent several PKCS#11 slots and associated tokens.
 * This command relates the PKCS#11 API function C_GetSlotList() and returns
 * the valid IDs recognized by the trusted application.
 */
#define PKCS11_CMD_SLOT_LIST			1

/*
 * PKCS11_CMD_SLOT_INFO - Get cryptoki structured slot information
 *
 * [in]		memref[0] = 32bit slot ID
 * [out]	memref[0] = 32bit fine grain return code
 * [out]        memref[2] = (struct pkcs11_slot_info)info
 *
 * The TA instance may represent several PKCS#11 slots and associated tokens.
 * This command relates the PKCS#11 API function C_GetSlotInfo() and returns
 * the information about the target slot.
 */
#define PKCS11_CMD_SLOT_INFO			2

#define PKCS11_SLOT_DESC_SIZE			64
#define PKCS11_SLOT_MANUFACTURER_SIZE		32
#define PKCS11_SLOT_VERSION_SIZE			2

struct pkcs11_slot_info {
	uint8_t slotDescription[PKCS11_SLOT_DESC_SIZE];
	uint8_t manufacturerID[PKCS11_SLOT_MANUFACTURER_SIZE];
	uint32_t flags;
	uint8_t hardwareVersion[PKCS11_SLOT_VERSION_SIZE];
	uint8_t firmwareVersion[PKCS11_SLOT_VERSION_SIZE];
};

/*
 * Values for pkcs11_token_info::flags.
 * PKCS11_CKFS_<x> corresponds to cryptoki flag CKF_<x> related to slot flags.
 */
#define PKCS11_CKFS_TOKEN_PRESENT		(1U << 0)
#define PKCS11_CKFS_REMOVABLE_DEVICE		(1U << 1)
#define PKCS11_CKFS_HW_SLOT			(1U << 2)

/*
 * PKCS11_CMD_TOKEN_INFO - Get cryptoki structured token information
 *
 * [in]		memref[0] = 32bit slot ID
 * [out]	memref[0] = 32bit fine grain return code
 * [out]        memref[2] = (struct pkcs11_token_info)info
 *
 * The TA instance may represent several PKCS#11 slots and associated tokens.
 * This command relates the PKCS#11 API function C_GetTokenInfo() and returns
 * the information about the target represented token.
 */
#define PKCS11_CMD_TOKEN_INFO			3

#define PKCS11_TOKEN_LABEL_SIZE			32
#define PKCS11_TOKEN_MANUFACTURER_SIZE		32
#define PKCS11_TOKEN_MODEL_SIZE			16
#define PKCS11_TOKEN_SERIALNUM_SIZE		16

struct pkcs11_token_info {
	uint8_t label[PKCS11_TOKEN_LABEL_SIZE];
	uint8_t manufacturerID[PKCS11_TOKEN_MANUFACTURER_SIZE];
	uint8_t model[PKCS11_TOKEN_MODEL_SIZE];
	uint8_t serialNumber[PKCS11_TOKEN_SERIALNUM_SIZE];
	uint32_t flags;
	uint32_t ulMaxSessionCount;
	uint32_t ulSessionCount;
	uint32_t ulMaxRwSessionCount;
	uint32_t ulRwSessionCount;
	uint32_t ulMaxPinLen;
	uint32_t ulMinPinLen;
	uint32_t ulTotalPublicMemory;
	uint32_t ulFreePublicMemory;
	uint32_t ulTotalPrivateMemory;
	uint32_t ulFreePrivateMemory;
	uint8_t hardwareVersion[2];
	uint8_t firmwareVersion[2];
	uint8_t utcTime[16];
};

/*
 * Values for pkcs11_token_info::flags.
 * PKCS11_CKFT_<x> corresponds to cryptoki CKF_<x> related to token flags.
 */
#define PKCS11_CKFT_RNG					(1U << 0)
#define PKCS11_CKFT_WRITE_PROTECTED			(1U << 1)
#define PKCS11_CKFT_LOGIN_REQUIRED			(1U << 2)
#define PKCS11_CKFT_USER_PIN_INITIALIZED		(1U << 3)
#define PKCS11_CKFT_RESTORE_KEY_NOT_NEEDED		(1U << 4)
#define PKCS11_CKFT_CLOCK_ON_TOKEN			(1U << 5)
#define PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH	(1U << 6)
#define PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS		(1U << 7)
#define PKCS11_CKFT_TOKEN_INITIALIZED			(1U << 8)
#define PKCS11_CKFT_USER_PIN_COUNT_LOW			(1U << 9)
#define PKCS11_CKFT_USER_PIN_FINAL_TRY			(1U << 10)
#define PKCS11_CKFT_USER_PIN_LOCKED			(1U << 11)
#define PKCS11_CKFT_USER_PIN_TO_BE_CHANGED		(1U << 12)
#define PKCS11_CKFT_SO_PIN_COUNT_LOW			(1U << 13)
#define PKCS11_CKFT_SO_PIN_FINAL_TRY			(1U << 14)
#define PKCS11_CKFT_SO_PIN_LOCKED			(1U << 15)
#define PKCS11_CKFT_SO_PIN_TO_BE_CHANGED		(1U << 16)
#define PKCS11_CKFT_ERROR_STATE				(1U << 17)

/*
 * PKCS11_CMD_MECHANISM_IDS - Get list of the supported mechanisms
 *
 * [in]		memref[0] = 32bit slot ID
 * [out]	memref[0] = 32bit fine grain return code
 * [out]        memref[2] = 32bit array mechanism IDs
 *
 * This command relates to the PKCS#11 API function C_GetMechanismList().
 */
#define PKCS11_CMD_MECHANISM_IDS		4

/*
 * PKCS11_CMD_MECHANISM_INFO - Get information on a specific mechanism
 *
 * [in]		memref[0] = [
 *			32bit slot ID,
 *			32bit mechanism ID
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 * [out]        memref[2] = (struct pkcs11_mechanism_info)info
 *
 * This command relates to the PKCS#11 API function C_GetMechanismInfo().
 */
#define PKCS11_CMD_MECHANISM_INFO		5

struct pkcs11_mechanism_info {
	uint32_t min_key_size;
	uint32_t max_key_size;
	uint32_t flags;
};

/*
 * Values for pkcs11_mechanism_info::flags.
 * PKCS11_CKFM_<x> strictly matches cryptoki CKF_<x> related to mechanism flags.
 */
#define PKCS11_CKFM_HW			(1U << 0)
#define PKCS11_CKFM_ENCRYPT		(1U << 8)
#define PKCS11_CKFM_DECRYPT		(1U << 9)
#define PKCS11_CKFM_DIGEST		(1U << 10)
#define PKCS11_CKFM_SIGN		(1U << 11)
#define PKCS11_CKFM_SIGN_RECOVER	(1U << 12)
#define PKCS11_CKFM_VERIFY		(1U << 13)
#define PKCS11_CKFM_VERIFY_RECOVER	(1U << 14)
#define PKCS11_CKFM_GENERATE		(1U << 15)
#define PKCS11_CKFM_GENERATE_PAIR	(1U << 16)
#define PKCS11_CKFM_WRAP		(1U << 17)
#define PKCS11_CKFM_UNWRAP		(1U << 18)
#define PKCS11_CKFM_DERIVE		(1U << 19)
#define PKCS11_CKFM_EC_F_P		(1U << 20)
#define PKCS11_CKFM_EC_F_2M		(1U << 21)
#define PKCS11_CKFM_EC_ECPARAMETERS	(1U << 22)
#define PKCS11_CKFM_EC_NAMEDCURVE	(1U << 23)
#define PKCS11_CKFM_EC_UNCOMPRESS	(1U << 24)
#define PKCS11_CKFM_EC_COMPRESS		(1U << 25)

/*
 * PKCS11_CMD_INIT_TOKEN - Initialize PKCS#11 token
 *
 * [in]		memref[0] = [
 *			32bit slot ID,
 *			32bit PIN length,
 *			8bit array PIN[PIN length],
 *			8bit array label[32]
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_InitToken().
 */
#define PKCS11_CMD_INIT_TOKEN			6

/*
 * PKCS11_CMD_INIT_PIN - Initialize user PIN
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit PIN length,
 *			8bit array PIN[PIN length]
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_InitPIN().
 */
#define PKCS11_CMD_INIT_PIN			7

/*
 * PKCS11_CMD_SET_PIN - Change user PIN
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit old_pin_length,
 *			8bit array old_pin[old_pin_length],
 *			32bit new_pin_length,
 *			8bit array new_pin[new_pin_length]
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_SetPIN().
 */
#define PKCS11_CMD_SET_PIN			8

/*
 * PKCS11_CMD_LOGIN - Initialize user PIN
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit user identifier,
 *			32bit PIN byte size,
 *			byte array: PIN data
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_Login().
 */
#define PKCS11_CMD_LOGIN			9

/*
 * Values for user identifier parameter in PKCS11_CMD_LOGIN
 */
#define PKCS11_CKU_SO			0x000
#define PKCS11_CKU_USER			0x001
#define PKCS11_CKU_CONTEXT_SPECIFIC	0x002

/*
 * PKCS11_CMD_LOGOUT - Log out from token
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_Logout().
 */
#define PKCS11_CMD_LOGOUT			10

/*
 * PKCS11_CMD_OPEN_RO_SESSION - Open read-only session
 *
 * [in]		memref[0] = 32bit slot ID
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = 32bit session handle
 *
 * This commands relates to the PKCS#11 API function C_OpenSession() for a
 * read-only session.
 */
#define PKCS11_CMD_OPEN_RO_SESSION		11

/*
 * PKCS11_CMD_OPEN_RW_SESSION - Open read/write session
 *
 * [in]		memref[0] = 32bit slot
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = 32bit session handle
 *
 * This commands relates to the PKCS#11 API function C_OpenSession() for a
 * read/write session.
 */
#define PKCS11_CMD_OPEN_RW_SESSION		12

/*
 * PKCS11_CMD_CLOSE_SESSION - Close an opened session
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This commands relates to the PKCS#11 API function C_CloseSession().
 */
#define PKCS11_CMD_CLOSE_SESSION		13

/*
 * PKCS11_CMD_SESSION_INFO - Get Cryptoki information on a session
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [out]        memref[2] = (struct pkcs11_session_info)info
 *
 * This command relates to the PKCS#11 API function C_GetSessionInfo().
 */
#define PKCS11_CMD_SESSION_INFO			14

struct pkcs11_session_info {
	uint32_t slot_id;
	uint32_t state;
	uint32_t flags;
	uint32_t error_code;
};

/*
 * PKCS11_CMD_CLOSE_ALL_SESSIONS - Close all client sessions on slot/token
 *
 * [in]		memref[0] = 32bit slot
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_CloseAllSessions().
 */
#define PKCS11_CMD_CLOSE_ALL_SESSIONS		15

/*
 * PKCS11_CMD_GET_SESSION_STATE - Retrieve the session state for later restore
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = byte array containing session state binary blob
 *
 * This command relates to the PKCS#11 API function C_GetOperationState().
 */
#define PKCS11_CMD_GET_SESSION_STATE		16

/*
 * PKCS11_CMD_SET_SESSION_STATE - Retrieve the session state for later restore
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [in]		memref[1] = byte array containing session state binary blob
 *
 * This command relates to the PKCS#11 API function C_SetOperationState().
 */
#define PKCS11_CMD_SET_SESSION_STATE		17

/*
 * PKCS11_CMD_IMPORT_OBJECT - Import a raw object in the session or token
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct pkcs11_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = 32bit object handle
 *
 * This command relates to the PKCS#11 API function C_CreateObject().
 */
#define PKCS11_CMD_IMPORT_OBJECT		18

/*
 * pkcs11_object_head - Header of object whose data are serialized in memory
 *
 * An object is made of several attributes. Attributes are stored one next to
 * the other with byte alignment as a serialized byte arrays. Appended
 * attributes byte arrays are prepend with this header structure that
 * defines the number of attribute items and the overall byte size of byte
 * array field pkcs11_object_head::attrs.
 *
 * @attrs_size - byte size of whole byte array attrs[]
 * @attrs_count - number of attribute items stored in attrs[]
 * @attrs - then starts the attributes data
 */
struct pkcs11_object_head {
	uint32_t attrs_size;
	uint32_t attrs_count;
	uint8_t attrs[];
};

/*
 * Attribute reference in the TA ABI. Each attribute starts with a header
 * structure followed by the attribute value. The attribute byte size is
 * defined in the attribute header.
 *
 * @id - the 32bit identifier of the attribute, see PKCS11_CKA_<x>
 * @size - the 32bit value attribute byte size
 * @data - then starts the attribute value
 */
struct pkcs11_attribute_head {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

/*
 * PKCS11_CMD_COPY_OBJECT - Duplicate an object possibly with new attributes
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle,
 *			(struct pkcs11_object_head)attribs + attributes data,
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = 32bit object handle
 *
 * This command relates to the PKCS#11 API function C_CopyObject().
 */
#define PKCS11_CMD_COPY_OBJECT			19

/*
 * PKCS11_CMD_DESTROY_OBJECT - Destroy an object
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_DestroyObject().
 */
#define PKCS11_CMD_DESTROY_OBJECT		20

/*
 * PKCS11_CMD_FIND_OBJECTS_INIT - Initialize an object search
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct pkcs11_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_FindOjectsInit().
 */
#define PKCS11_CMD_FIND_OBJECTS_INIT		21

/*
 * PKCS11_CMD_FIND_OBJECTS - Get handles of matching objects
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = 32bit array object_handle_array[N]
 *
 * This command relates to the PKCS#11 API function C_FindOjects().
 * The size of object_handle_array depends on the size of the output buffer
 * provided by the client.
 */
#define PKCS11_CMD_FIND_OBJECTS			22

/*
 * PKCS11_CMD_FIND_OBJECTS_FINAL - Finalize current objects search
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_FindOjectsFinal().
 */
#define PKCS11_CMD_FIND_OBJECTS_FINAL		23

/*
 * PKCS11_CMD_GET_OBJECT_SIZE - Get byte size used by object in the TEE
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = 32bit object_byte_size
 *
 * This command relates to the PKCS#11 API function C_GetObjectSize().
 */
#define PKCS11_CMD_GET_OBJECT_SIZE		24

/*
 * PKCS11_CMD_GET_ATTRIBUTE_VALUE - Get the value of object attribute(s)
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle,
 *			(struct pkcs11_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = (struct pkcs11_object_head)attribs + attributes data
 *
 * This command relates to the PKCS#11 API function C_GetAttributeValue.
 * Caller provides an attribute template as 3rd argument in memref[0]
 * (referred here as attribs + attributes data). Upon successful completion,
 * the TA returns the provided template filled with expected data through
 * output argument memref[2] (referred here again as attribs + attributes data).
 */
#define PKCS11_CMD_GET_ATTRIBUTE_VALUE		25

/*
 * PKCS11_CMD_SET_ATTRIBUTE_VALUE - Set the value for object attribute(s)
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle,
 *			(struct pkcs11_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * This command relates to the PKCS#11 API function C_SetAttributeValue().
 */
#define PKCS11_CMD_SET_ATTRIBUTE_VALUE		26

/*
 * PKCS11_CMD_GENERATE_KEY - Generate a symmetric key or domain parameters
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct pkcs11_attribute_head)mechanism + mecha params,
 *			(struct pkcs11_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = 32bit object handle
 *
 * This command relates to the PKCS#11 API functions C_GenerateKey().
 */
#define PKCS11_CMD_GENERATE_KEY			27

/*
 * PKCS11_CMD_ENCRYPT_INIT - Initialize encryption processing
 * PKCS11_CMD_DECRYPT_INIT - Initialize decryption processing
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit object handle of the key,
 *			(struct pkcs11_attribute_head)mechanism + mecha params
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * These commands relate to the PKCS#11 API functions C_EncryptInit() and
 * C_DecryptInit().
 */
#define PKCS11_CMD_ENCRYPT_INIT			28
#define PKCS11_CMD_DECRYPT_INIT			29

/*
 * PKCS11_CMD_ENCRYPT_UPDATE - Update encryption processing
 * PKCS11_CMD_DECRYPT_UPDATE - Update decryption processing
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [in]		memref[1] = input data to be processed
 * [out]	memref[2] = output processed data
 *
 * These commands relate to the PKCS#11 API functions C_EncryptUpdate() and
 * C_DecryptUpdate().
 */
#define PKCS11_CMD_ENCRYPT_UPDATE		30
#define PKCS11_CMD_DECRYPT_UPDATE		31

/*
 * PKCS11_CMD_ENCRYPT_FINAL - Finalize encryption processing
 * PKCS11_CMD_DECRYPT_FINAL - Finalize decryption processing
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = output processed data
 *
 * These commands relate to the PKCS#11 API functions C_EncryptFinal() and
 * C_DecryptFinal().
 */
#define PKCS11_CMD_ENCRYPT_FINAL		32
#define PKCS11_CMD_DECRYPT_FINAL		33

/*
 * PKCS11_CMD_ENCRYPT_ONESHOT - Update and finalize encryption processing
 * PKCS11_CMD_DECRYPT_ONESHOT - Update and finalize decryption processing
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [in]		memref[1] = input data to be processed
 * [out]	memref[2] = output processed data
 *
 * These commands relate to the PKCS#11 API functions C_Encrypt and
 * C_Decrypt.
 */
#define PKCS11_CMD_ENCRYPT_ONESHOT		34
#define PKCS11_CMD_DECRYPT_ONESHOT		35

/*
 * PKCS11_CMD_SIGN_INIT - Initialize a signature computation processing
 * PKCS11_CMD_VERIFY_INIT - Initialize a signature verification processing
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			32bit key handle,
 *			(struct pkcs11_attribute_head)mechanism + mecha params,
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 *
 * These commands relate to the PKCS#11 API functions C_SignInit() and
 * C_VerifyInit().
 */
#define PKCS11_CMD_SIGN_INIT			36
#define PKCS11_CMD_VERIFY_INIT			37

/*
 * PKCS11_CMD_SIGN_UPDATE - Update a signature computation processing
 * PKCS11_CMD_VERIFY_UPDATE - Update a signature verification processing
 *
 * [in]		memref[0] = 32bit session handle
 * [in]		memref[1] = input data to be processed
 * [out]	memref[0] = 32bit fine grain return code
 *
 * These commands relate to the PKCS#11 API functions C_SignUpdate() and
 * C_VerifyUpdate().
 */
#define PKCS11_CMD_SIGN_UPDATE			38
#define PKCS11_CMD_VERIFY_UPDATE		39

/*
 * PKCS11_CMD_SIGN_FINAL - Finalize a signature computation processing
 * PKCS11_CMD_VERIFY_FINAL - Finalize a signature verification processing
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = output processed data
 *
 * These commands relate to the PKCS#11 API functions C_SignFinal() and
 * C_VerifyFinal.
 */
#define PKCS11_CMD_SIGN_FINAL			40
#define PKCS11_CMD_VERIFY_FINAL			41

/*
 * PKCS11_CMD_SIGN_ONESHOT - Update and finalize a signature computation
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [in]		memref[1] = input data to be processed
 * [out]	memref[2] = byte array: generated signature
 *
 * This command relates to the PKCS#11 API function C_Sign().
 */
#define PKCS11_CMD_SIGN_ONESHOT			42

/*
 * PKCS11_CMD_VERIFY_ONESHOT - Update and finalize a signature verification
 *
 * [in]		memref[0] = 32bit session handle
 * [out]	memref[0] = 32bit fine grain return code
 * [in]		memref[1] = input data to be processed
 * [in]		memref[2] = input signature to be processed
 *
 * This command relates to the PKCS#11 API function C_Verify().
 */
#define PKCS11_CMD_VERIFY_ONESHOT		43

/*
 * PKCS11_CMD_DERIVE_KEY - Derive a key from already provisioned parent key
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct pkcs11_attribute_head)mechanism + mecha params,
 *			32bit key handle,
 *			(struct pkcs11_object_head)attribs + attributes data
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = 32bit object handle
 *
 * This command relates to the PKCS#11 API functions C_DeriveKey().
 */
#define PKCS11_CMD_DERIVE_KEY			44

/*
 * PKCS11_CMD_GENERATE_KEY_PAIR - Generate an asymmetric key pair
 *
 * [in]		memref[0] = [
 *			32bit session handle,
 *			(struct pkcs11_attribute_head)mechanism + mecha params,
 *			(struct pkcs11_object_head)pubkey_attribs + attributes,
 *			(struct pkcs11_object_head)privkeyattribs + attributes,
 *		]
 * [out]	memref[0] = 32bit fine grain return code
 * [out]	memref[2] = [
 *			32bit public key handle,
 *			32bit prive key handle
 *		]
 *
 * This command relates to the PKCS#11 API functions C_GenerateKeyPair().
 */
#define PKCS11_CMD_GENERATE_KEY_PAIR		45

/*
 * Command return codes
 * PKCS11_CKR_<x> relates cryptoki CKR_<x> in meaning if not in value.
 */
#define PKCS11_CKR_OK					0x00000000
#define PKCS11_CKR_GENERAL_ERROR			0x00000001
#define PKCS11_CKR_DEVICE_MEMORY			0x00000002
#define PKCS11_CKR_ARGUMENTS_BAD			0x00000003
#define PKCS11_CKR_BUFFER_TOO_SMALL			0x00000004
#define PKCS11_CKR_FUNCTION_FAILED			0x00000005
#define PKCS11_CKR_SIGNATURE_INVALID			0x00000007
#define PKCS11_CKR_ATTRIBUTE_TYPE_INVALID		0x00000008
#define PKCS11_CKR_ATTRIBUTE_VALUE_INVALID		0x00000009
#define PKCS11_CKR_OBJECT_HANDLE_INVALID		0x0000000a
#define PKCS11_CKR_KEY_HANDLE_INVALID			0x0000000b
#define PKCS11_CKR_MECHANISM_INVALID			0x0000000c
#define PKCS11_CKR_SESSION_HANDLE_INVALID		0x0000000d
#define PKCS11_CKR_SLOT_ID_INVALID			0x0000000e
#define PKCS11_CKR_MECHANISM_PARAM_INVALID		0x0000000f
#define PKCS11_CKR_TEMPLATE_INCONSISTENT		0x00000010
#define PKCS11_CKR_TEMPLATE_INCOMPLETE			0x00000011
#define PKCS11_CKR_PIN_INCORRECT			0x00000012
#define PKCS11_CKR_PIN_LOCKED				0x00000013
#define PKCS11_CKR_PIN_EXPIRED				0x00000014
#define PKCS11_CKR_PIN_INVALID				0x00000015
#define PKCS11_CKR_PIN_LEN_RANGE			0x00000016
#define PKCS11_CKR_SESSION_EXISTS			0x00000017
#define PKCS11_CKR_SESSION_READ_ONLY			0x00000018
#define PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS		0x00000019
#define PKCS11_CKR_OPERATION_ACTIVE			0x0000001a
#define PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED		0x0000001b
#define PKCS11_CKR_OPERATION_NOT_INITIALIZED		0x0000001c
#define PKCS11_CKR_TOKEN_WRITE_PROTECTED		0x0000001d
#define PKCS11_CKR_TOKEN_NOT_PRESENT			0x0000001e
#define PKCS11_CKR_TOKEN_NOT_RECOGNIZED			0x0000001f
#define PKCS11_CKR_ACTION_PROHIBITED			0x00000020
#define PKCS11_CKR_ATTRIBUTE_READ_ONLY			0x00000021
#define PKCS11_CKR_PIN_TOO_WEAK				0x00000022
#define PKCS11_CKR_CURVE_NOT_SUPPORTED			0x00000023
#define PKCS11_CKR_DOMAIN_PARAMS_INVALID		0x00000024
#define PKCS11_CKR_USER_ALREADY_LOGGED_IN		0x00000025
#define PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN	0x00000026
#define PKCS11_CKR_USER_NOT_LOGGED_IN			0x00000027
#define PKCS11_CKR_USER_PIN_NOT_INITIALIZED		0x00000028
#define PKCS11_CKR_USER_TOO_MANY_TYPES			0x00000029
#define PKCS11_CKR_USER_TYPE_INVALID			0x0000002a
#define PKCS11_CKR_SESSION_READ_ONLY_EXISTS		0x0000002b
#define PKCS11_CKR_KEY_SIZE_RANGE			0x0000002c
#define PKCS11_CKR_ATTRIBUTE_SENSITIVE			0x0000002d

/* Status without strict equivalence in Cryptoki API */
#define PKCS11_RV_NOT_FOUND				0x00001000
#define PKCS11_RV_NOT_IMPLEMENTED			0x00001001

/*
 * Attribute identification IDs
 * Valid values for struct pkcs11_attribute_head::id
 *
 * PKCS11_CKA_<x> relates to cryptoki CKA_<x>.
 * Value range [0 63] is reserved to boolean value attributes.
 */
#define PKCS11_BOOLPROPH_FLAG		(1U << 31)
#define PKCS11_BOOLPROPS_BASE		0
#define PKCS11_BOOLPROPS_MAX		63

#define PKCS11_CKA_TOKEN				0x00000000
#define PKCS11_CKA_PRIVATE				0x00000001
#define PKCS11_CKA_TRUSTED				0x00000002
#define PKCS11_CKA_SENSITIVE				0x00000003
#define PKCS11_CKA_ENCRYPT				0x00000004
#define PKCS11_CKA_DECRYPT				0x00000005
#define PKCS11_CKA_WRAP					0x00000006
#define PKCS11_CKA_UNWRAP				0x00000007
#define PKCS11_CKA_SIGN					0x00000008
#define PKCS11_CKA_SIGN_RECOVER				0x00000009
#define PKCS11_CKA_VERIFY				0x0000000a
#define PKCS11_CKA_VERIFY_RECOVER			0x0000000b
#define PKCS11_CKA_DERIVE				0x0000000c
#define PKCS11_CKA_EXTRACTABLE				0x0000000d
#define PKCS11_CKA_LOCAL				0x0000000e
#define PKCS11_CKA_NEVER_EXTRACTABLE			0x0000000f
#define PKCS11_CKA_ALWAYS_SENSITIVE			0x00000010
#define PKCS11_CKA_MODIFIABLE				0x00000011
#define PKCS11_CKA_COPYABLE				0x00000012
#define PKCS11_CKA_DESTROYABLE				0x00000013
#define PKCS11_CKA_ALWAYS_AUTHENTICATE			0x00000014
#define PKCS11_CKA_WRAP_WITH_TRUSTED			0x00000015
#define PKCS11_BOOLPROPS_LAST				PKCS11_CKA_WRAP_WITH_TRUSTED
#define PKCS11_BOOLPROPS_END				PKCS11_BOOLPROPS_MAX

#define PKCS11_CKA_LABEL				0x00000040
#define PKCS11_CKA_VALUE				0x00000041
#define PKCS11_CKA_VALUE_LEN				0x00000042
#define PKCS11_CKA_WRAP_TEMPLATE			0x00000043
#define PKCS11_CKA_UNWRAP_TEMPLATE			0x00000044
#define PKCS11_CKA_DERIVE_TEMPLATE			0x00000045
#define PKCS11_CKA_START_DATE				0x00000046
#define PKCS11_CKA_END_DATE				0x00000047
#define PKCS11_CKA_OBJECT_ID				0x00000048
#define PKCS11_CKA_APPLICATION				0x00000049
#define PKCS11_CKA_MECHANISM_TYPE			0x0000004a
#define PKCS11_CKA_ID					0x0000004b
#define PKCS11_CKA_ALLOWED_MECHANISMS			0x0000004c
#define PKCS11_CKA_CLASS				0x0000004d
#define PKCS11_CKA_KEY_TYPE				0x0000004e
#define PKCS11_CKA_EC_POINT				0x0000004f
#define PKCS11_CKA_EC_PARAMS				0x00000050
#define PKCS11_CKA_MODULUS				0x00000051
#define PKCS11_CKA_MODULUS_BITS				0x00000052
#define PKCS11_CKA_PUBLIC_EXPONENT			0x00000053
#define PKCS11_CKA_PRIVATE_EXPONENT			0x00000054
#define PKCS11_CKA_PRIME_1				0x00000055
#define PKCS11_CKA_PRIME_2				0x00000056
#define PKCS11_CKA_EXPONENT_1				0x00000057
#define PKCS11_CKA_EXPONENT_2				0x00000058
#define PKCS11_CKA_COEFFICIENT				0x00000059
#define PKCS11_CKA_SUBJECT				0x0000005a
#define PKCS11_CKA_PUBLIC_KEY_INFO			0x0000005b
/* Temporary storage until DER/BigInt conversion is available */
#define PKCS11_CKA_EC_POINT_X				0x88800001
#define PKCS11_CKA_EC_POINT_Y				0x88800002
/* Vendor extension: reserved for undefined ID (~0U) */
#define PKCS11_CKA_UNDEFINED_ID				PKCS11_UNDEFINED_ID

/*
 * Valid values for attribute PKCS11_CKA_CLASS
 * PKCS11_CKO_<x> corresponds to cryptoki CKO_<x>.
 */
#define PKCS11_CKO_SECRET_KEY				0x000
#define PKCS11_CKO_PUBLIC_KEY				0x001
#define PKCS11_CKO_PRIVATE_KEY				0x002
#define PKCS11_CKO_OTP_KEY				0x003
#define PKCS11_CKO_CERTIFICATE				0x004
#define PKCS11_CKO_DATA					0x005
#define PKCS11_CKO_DOMAIN_PARAMETERS			0x006
#define PKCS11_CKO_HW_FEATURE				0x007
#define PKCS11_CKO_MECHANISM				0x008
/* Vendor extension: reserved for undefined ID (~0U) */
#define PKCS11_CKO_UNDEFINED_ID				PKCS11_UNDEFINED_ID

/*
 * Valid values for attribute PKCS11_CKA_KEY_TYPE
 * PKCS11_CKK_<x> corresponds to cryptoki CKK_<x> related to symmetric keys
 */
#define PKCS11_CKK_AES					0x000
#define PKCS11_CKK_GENERIC_SECRET			0x001
#define PKCS11_CKK_MD5_HMAC				0x002
#define PKCS11_CKK_SHA_1_HMAC				0x003
#define PKCS11_CKK_SHA224_HMAC				0x004
#define PKCS11_CKK_SHA256_HMAC				0x005
#define PKCS11_CKK_SHA384_HMAC				0x006
#define PKCS11_CKK_SHA512_HMAC				0x007
#define PKCS11_CKK_EC					0x008
#define PKCS11_CKK_RSA					0x009
#define PKCS11_CKK_DSA					0x00a
#define PKCS11_CKK_DH					0x00b
/* Vendor extension: reserved for undefined ID (~0U) */
#define PKCS11_CKK_UNDEFINED_ID				PKCS11_UNDEFINED_ID

/*
 * Valid values for attribute PKCS11_CKA_MECHANISM_TYPE
 * PKCS11_CKM_<x> corresponds to cryptoki CKM_<x>.
 */
#define PKCS11_CKM_AES_ECB				0x000
#define PKCS11_CKM_AES_CBC				0x001
#define PKCS11_CKM_AES_CBC_PAD				0x002
#define PKCS11_CKM_AES_CTS				0x003
#define PKCS11_CKM_AES_CTR				0x004
#define PKCS11_CKM_AES_GCM				0x005
#define PKCS11_CKM_AES_CCM				0x006
#define PKCS11_CKM_AES_GMAC				0x007
#define PKCS11_CKM_AES_CMAC				0x008
#define PKCS11_CKM_AES_CMAC_GENERAL			0x009
#define PKCS11_CKM_AES_ECB_ENCRYPT_DATA			0x00a
#define PKCS11_CKM_AES_CBC_ENCRYPT_DATA			0x00b
#define PKCS11_CKM_AES_KEY_GEN				0x00c
#define PKCS11_CKM_GENERIC_SECRET_KEY_GEN		0x00d
#define PKCS11_CKM_MD5_HMAC				0x00e
#define PKCS11_CKM_SHA_1_HMAC				0x00f
#define PKCS11_CKM_SHA224_HMAC				0x010
#define PKCS11_CKM_SHA256_HMAC				0x011
#define PKCS11_CKM_SHA384_HMAC				0x012
#define PKCS11_CKM_SHA512_HMAC				0x013
#define PKCS11_CKM_AES_XCBC_MAC				0x014
#define PKCS11_CKM_EC_KEY_PAIR_GEN			0x015
#define PKCS11_CKM_ECDSA				0x016
#define PKCS11_CKM_ECDSA_SHA1				0x017
#define PKCS11_CKM_ECDSA_SHA224				0x018	/* /!\ CK !PKCS#11 */
#define PKCS11_CKM_ECDSA_SHA256				0x019	/* /!\ CK !PKCS#11 */
#define PKCS11_CKM_ECDSA_SHA384				0x01a	/* /!\ CK !PKCS#11 */
#define PKCS11_CKM_ECDSA_SHA512				0x01b	/* /!\ CK !PKCS#11 */
#define PKCS11_CKM_ECDH1_DERIVE				0x01c
#define PKCS11_CKM_ECDH1_COFACTOR_DERIVE		0x01d
#define PKCS11_CKM_ECMQV_DERIVE				0x01e
#define PKCS11_CKM_ECDH_AES_KEY_WRAP			0x01f
#define PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN		0x020
#define PKCS11_CKM_RSA_PKCS				0x021
#define PKCS11_CKM_RSA_9796				0x022
#define PKCS11_CKM_RSA_X_509				0x023
#define PKCS11_CKM_SHA1_RSA_PKCS			0x024
#define PKCS11_CKM_RSA_PKCS_OAEP			0x025
#define PKCS11_CKM_SHA1_RSA_PKCS_PSS			0x026
#define PKCS11_CKM_SHA256_RSA_PKCS			0x027
#define PKCS11_CKM_SHA384_RSA_PKCS			0x028
#define PKCS11_CKM_SHA512_RSA_PKCS			0x029
#define PKCS11_CKM_SHA256_RSA_PKCS_PSS			0x02a
#define PKCS11_CKM_SHA384_RSA_PKCS_PSS			0x02b
#define PKCS11_CKM_SHA512_RSA_PKCS_PSS			0x02c
#define PKCS11_CKM_SHA224_RSA_PKCS			0x02d
#define PKCS11_CKM_SHA224_RSA_PKCS_PSS			0x02e
#define PKCS11_CKM_RSA_AES_KEY_WRAP			0x02f
#define PKCS11_CKM_RSA_PKCS_PSS				0x030
#define PKCS11_CKM_MD5					0x031
#define PKCS11_CKM_SHA_1				0x032
#define PKCS11_CKM_SHA224				0x033
#define PKCS11_CKM_SHA256				0x034
#define PKCS11_CKM_SHA384				0x035
#define PKCS11_CKM_SHA512				0x036
#define PKCS11_CKM_DH_PKCS_DERIVE			0x037

/* PKCS11 TA added IDs for operation without cryptoki mechanism ID defined */
#define PKCS11_PROCESSING_IMPORT				0x1000
#define PKCS11_PROCESSING_COPY				0x1001
/* Vendor extension: reserved for undefined ID (~0U) */
#define PKCS11_CKM_UNDEFINED_ID				PKCS11_UNDEFINED_ID

/*
 * Valid values key differentiation function identifiers
 * PKCS11_CKD_<x> reltaes to cryptoki CKD_<x>.
 */
#define PKCS11_CKD_NULL					0x0000UL
#define PKCS11_CKD_SHA1_KDF				0x0001UL
#define PKCS11_CKD_SHA1_KDF_ASN1			0x0002UL
#define PKCS11_CKD_SHA1_KDF_CONCATENATE			0x0003UL
#define PKCS11_CKD_SHA224_KDF				0x0004UL
#define PKCS11_CKD_SHA256_KDF				0x0005UL
#define PKCS11_CKD_SHA384_KDF				0x0006UL
#define PKCS11_CKD_SHA512_KDF				0x0007UL
#define PKCS11_CKD_CPDIVERSIFY_KDF			0x0008UL
/* Vendor extension: reserved for undefined ID (~0U) */
#define PKCS11_CKD_UNDEFINED_ID				PKCS11_UNDEFINED_ID

/*
 * Valid values MG function identifiers
 * PKCS11_CKG_<x> reltaes to cryptoki CKG_<x>.
 */
#define PKCS11_CKG_MGF1_SHA1				0x0001UL
#define PKCS11_CKG_MGF1_SHA224				0x0005UL
#define PKCS11_CKG_MGF1_SHA256				0x0002UL
#define PKCS11_CKG_MGF1_SHA384				0x0003UL
#define PKCS11_CKG_MGF1_SHA512				0x0004UL
/* Vendor extension: reserved for undefined ID (~0U) */
#define PKCS11_CKG_UNDEFINED_ID				PKCS11_UNDEFINED_ID

/*
 * Valid values for RSA PKCS/OAEP source type identifier
 * PKCS11_CKZ_<x> reltaes to cryptoki CKZ_<x>.
 */
#define PKCS11_CKZ_DATA_SPECIFIED		0x0001

/*
 * Processing parameters
 *
 * These can hardly be described by ANSI-C structures since the byte size of
 * some fields of the structure are specified by a previous field in the
 * structure. Therefore the format of the parameter binary data for each
 * supported processing is defined here from this comment rather than using
 * C structures.
 *
 * Processing parameters are used as arguments to C_EncryptInit and friends
 * using struct pkcs11_attribute_head format where field 'type' is the
 * PKCS11 mechanism ID and field 'size' is the mechanism parameters byte size.
 * Below is shown the head structure struct pkcs11_attribute_head fields and
 * the trailing data that are the effective parameters binary blob for the
 * target processing/mechanism.
 *
 * AES and generic secret generation
 *   head:	32bit: type = PKCS11_CKM_AES_KEY_GEN
 *			   or PKCS11_CKM_GENERIC_SECRET_KEY_GEN
 *		32bit: size = 0
 *
 * AES ECB
 *   head:	32bit: type = PKCS11_CKM_AES_ECB
 *		32bit: params byte size = 0
 *
 * AES CBC, CBC_PAD and CTS
 *   head:	32bit: type = PKCS11_CKM_AES_CBC
 *			  or PKCS11_CKM_AES_CBC_PAD
 *			  or PKCS11_CKM_AES_CTS
 *		32bit: params byte size = 16
 *  params:	16byte: IV
 *
 * AES CTR, params relates to struct CK_AES_CTR_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_AES_CTR
 *		32bit: params byte size = 20
 *  params:	32bit: counter bit increment
 *		16byte: IV
 *
 * AES GCM, params relates to struct CK_AES_GCM_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_AES_GCM
 *		32bit: params byte size
 *  params:	32bit: IV_byte_size
 *		byte array: IV (IV_byte_size bytes)
 *		32bit: AAD_byte_size
 *		byte array: AAD data (AAD_byte_size bytes)
 *		32bit: tag bit size
 *
 * AES CCM, params relates to struct CK_AES_CCM_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_AES_CCM
 *		32bit: params byte size
 *  params:	32bit: data_byte_size
 *		32bit: nonce_byte_size
 *		byte array: nonce data (nonce_byte_size bytes)
 *		32bit: AAD_byte_size
 *		byte array: AAD data (AAD_byte_size bytes)
 *		32bit: MAC byte size
 *
 * AES GMAC
 *   head:	32bit: type = PKCS11_CKM_AES_GMAC
 *		32bit: params byte size = 12
 *  params:	12byte: IV
 *
 * AES CMAC with general length, params relates to struct CK_MAC_GENERAL_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_AES_CMAC_GENERAL
 *		32bit: params byte size = 12
 *  params:	32bit: byte size of the output CMAC data
 *
 * AES CMAC fixed size (16byte CMAC)
 *   head:	32bit: type = PKCS11_CKM_AES_CMAC_GENERAL
 *		32bit: size = 0
 *
 * AES derive by ECB, params relates to struct CK_KEY_DERIVATION_STRING_DATA.
 *   head:	32bit: type = PKCS11_CKM_AES_ECB_ENCRYPT_DATA
 *		32bit: params byte size
 *  params:	32bit: byte size of the data to encrypt
 *		byte array: data to encrypt
 *
 * AES derive by CBC, params relates to struct CK_AES_CBC_ENCRYPT_DATA_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_AES_CBC_ENCRYPT_DATA
 *		32bit: params byte size
 *  params:	16byte: IV
 *		32bit: byte size of the data to encrypt
 *		byte array: data to encrypt
 *
 * AES and generic secret generation
 *   head:	32bit: type = PKCS11_CKM_AES_KEY_GEN
 *			   or PKCS11_CKM_GENERIC_SECRET_KEY_GEN
 *		32bit: size = 0
 *
 * ECDH, params relates to struct CK_ECDH1_DERIVE_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_ECDH1_DERIVE
 *			   or PKCS11_CKM_ECDH1_COFACTOR_DERIVE
 *		32bit: params byte size
 *  params:	32bit: key derivation function (PKCS11_CKD_xxx)
 *		32bit: byte size of the shared data
 *		byte array: shared data
 *		32bit: byte: size of the public data
 *		byte array: public data
 *
 * AES key wrap by ECDH, params relates to struct CK_ECDH_AES_KEY_WRAP_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_ECDH_AES_KEY_WRAP
 *		32bit: params byte size
 *  params:	32bit: bit size of the AES key
 *		32bit: key derivation function (PKCS11_CKD_xxx)
 *		32bit: byte size of the shared data
 *		byte array: shared data
 *
 * RSA_PKCS (pre-hashed payload)
 *   head:	32bit: type = PKCS11_CKM_RSA_PKCS
 *		32bit: size = 0
 *
 * RSA PKCS OAEP, params relates to struct CK_RSA_PKCS_OAEP_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_RSA_PKCS_OAEP
 *		32bit: params byte size
 *  params:	32bit: hash algorithm identifier (PKCS11_CK_M_xxx)
 *		32bit: PKCS11_CK_RSA_PKCS_MGF_TYPE
 *		32bit: PKCS11_CK_RSA_PKCS_OAEP_SOURCE_TYPE
 *		32bit: byte size of the source data
 *		byte array: source data
 *
 * RSA PKCS PSS, params relates to struct CK_RSA_PKCS_PSS_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_RSA_PKCS_PSS
 *			   or PKCS11_CKM_SHA256_RSA_PKCS_PSS
 *			   or PKCS11_CKM_SHA384_RSA_PKCS_PSS
 *			   or PKCS11_CKM_SHA512_RSA_PKCS_PSS
 *		32bit: params byte size
 *  params:	32bit: hash algorithm identifier (PKCS11_CK_M_xxx)
 *		32bit: PKCS11_CK_RSA_PKCS_MGF_TYPE
 *		32bit: byte size of the salt in the PSS encoding
 *
 * AES key wrapping by RSA, params relates to struct CK_RSA_AES_KEY_WRAP_PARAMS.
 *   head:	32bit: type = PKCS11_CKM_RSA_AES_KEY_WRAP
 *		32bit: params byte size
 *  params:	32bit: bit size of the AES key
 *		32bit: hash algorithm identifier (PKCS11_CK_M_xxx)
 *		32bit: PKCS11_CK_RSA_PKCS_MGF_TYPE
 *		32bit: PKCS11_CK_RSA_PKCS_OAEP_SOURCE_TYPE
 *		32bit: byte size of the source data
 *		byte array: source data
 */
#endif /*PKCS11_TA_H*/
