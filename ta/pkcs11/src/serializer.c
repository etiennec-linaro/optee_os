// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <pkcs11_internal_abi.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

#include "serializer.h"
#include "pkcs11_helpers.h"

/*
 * Util routines for serializes unformatted arguments in a client memref
 */
void serialargs_init(struct serialargs *args, void *in, size_t size)
{
	args->start = in;
	args->next = in;
	args->size = size;
}

uint32_t serialargs_get(struct serialargs *args, void *out, size_t size)
{
	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return PKCS11_BAD_PARAM;
	}

	TEE_MemMove(out, args->next, size);

	args->next += size;

	return PKCS11_OK;
}

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				  void **out, size_t size)
{
	void *ptr = NULL;

	if (!size) {
		*out = NULL;
		return PKCS11_OK;
	}

	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return PKCS11_BAD_PARAM;
	}

	ptr = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	if (!ptr)
		return PKCS11_MEMORY;

	TEE_MemMove(ptr, args->next, size);

	args->next += size;
	*out = ptr;

	return PKCS11_OK;
}

uint32_t serialargs_get_ptr(struct serialargs *args, void **out, size_t size)
{
	void *ptr = args->next;

	if (!size) {
		*out = NULL;
		return PKCS11_OK;
	}

	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return PKCS11_BAD_PARAM;
	}

	args->next += size;
	*out = ptr;

	return PKCS11_OK;
}

uint32_t serialargs_alloc_get_one_attribute(struct serialargs *args,
					    struct pkcs11_attribute_head **out)
{
	struct pkcs11_attribute_head head;
	size_t out_size = sizeof(head);
	void *pref = NULL;

	TEE_MemFill(&head, 0, sizeof(head));

	if (args->next + out_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect at least %zd",
		     args->size, args->size - (args->next - args->start),
		     out_size);
		return PKCS11_BAD_PARAM;
	}

	TEE_MemMove(&head, args->next, out_size);

	out_size += head.size;
	if (args->next + out_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start),
		     out_size);
		return PKCS11_BAD_PARAM;
	}

	pref = TEE_Malloc(out_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!pref)
		return PKCS11_MEMORY;

	TEE_MemMove(pref, args->next, out_size);
	args->next += out_size;

	*out = pref;

	return PKCS11_OK;
}

uint32_t serialargs_alloc_get_attributes(struct serialargs *args,
					 struct pkcs11_object_head **out)
{
	struct pkcs11_object_head attr;
	struct pkcs11_object_head *pattr = NULL;
	size_t attr_size = sizeof(attr);

	TEE_MemFill(&attr, 0, sizeof(attr));

	if (args->next + attr_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect at least %zd",
		     args->size, args->size - (args->next - args->start),
		     attr_size);
		return PKCS11_BAD_PARAM;
	}

	TEE_MemMove(&attr, args->next, attr_size);

	attr_size += attr.attrs_size;
	if (args->next + attr_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start),
		     attr_size);
		return PKCS11_BAD_PARAM;
	}

	pattr = TEE_Malloc(attr_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!pattr)
		return PKCS11_MEMORY;

	TEE_MemMove(pattr, args->next, attr_size);
	args->next += attr_size;

	*out = pattr;

	return PKCS11_OK;
}

bool serialargs_remaining_bytes(struct serialargs *args)
{
	return args->next < args->start + args->size;
}

/*
 * serialize - serialize input data in buffer
 *
 * Serialize data in provided buffer.
 * Insure 64byte alignment of appended data in the buffer.
 */
uint32_t serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	char *buf = NULL;
	size_t nlen = *blen + len;

	buf = TEE_Realloc(*bstart, nlen);
	if (!buf)
		return PKCS11_MEMORY;

	TEE_MemMove(buf + *blen, data, len);

	*blen = nlen;
	*bstart = buf;

	return PKCS11_OK;
}
