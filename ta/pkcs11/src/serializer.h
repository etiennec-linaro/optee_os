/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_SERIALIZER_H
#define PKCS11_TA_SERIALIZER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_internal_api.h>

struct pkcs11_client;
struct pkcs11_session;

/*
 * Util routines for serializes unformated arguments in a client memref
 */
struct serialargs {
	char *start;
	char *next;
	size_t size;
};

void serialargs_init(struct serialargs *args, void *in, size_t size);

uint32_t serialargs_get(struct serialargs *args, void *out, size_t sz);

uint32_t serialargs_get_ptr(struct serialargs *args, void **out, size_t size);

uint32_t serialargs_alloc_get_one_attribute(struct serialargs *args,
					    struct pkcs11_attribute_head **out);

uint32_t serialargs_alloc_get_attributes(struct serialargs *args,
					 struct pkcs11_object_head **out);

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				  void **out, size_t size);

bool serialargs_remaining_bytes(struct serialargs *args);

uint32_t serialargs_get_session(struct serialargs *args,
				struct pkcs11_client *client,
				struct pkcs11_session **session);

#define PKCS11_MAX_BOOLPROP_SHIFT	64
#define PKCS11_MAX_BOOLPROP_ARRAY	(PKCS11_MAX_BOOLPROP_SHIFT / \
					 sizeof(uint32_t))

/**
 * serialize - Append data into a serialized buffer
 */
uint32_t serialize(char **bstart, size_t *blen, void *data, size_t len);

#endif /*PKCS11_TA_SERIALIZER_H*/
