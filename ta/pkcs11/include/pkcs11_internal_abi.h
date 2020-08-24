/*
 * Copyright (c) 2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PKCS11_INTERNAL_ABI_H
#define PKCS11_INTERNAL_ABI_H

/* Internal format is based on the API IDs */
#include <pkcs11_ta.h>
#include <stddef.h>


/**
 * Serialization of object attributes
 *
 * An object is defined by the list of its attributes among which identifiers
 * for the type of the object (symmetric key, asymmetric key, ...) and the
 * object value (i.e the AES key value). In the end, an object is a list of
 * attributes.
 *
 * PKCS11 TA uses a serialized format for defining the attributes of an object.
 * The attributes content starts with a header structure header followed by
 * each attributes, stored in serialized fields:
 * - the 32bit identifier of the attribute
 * - the 32bit value attribute byte size
 * - the effective value of the attribute (variable size)
 */
struct pkcs11_ref {
	uint32_t id;
	uint32_t size;
	uint8_t data[];
};

#endif /*PKCS11_INTERNAL_ABI_H*/
