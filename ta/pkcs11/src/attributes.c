// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <pkcs11_ta.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <util.h>

#include "attributes.h"
#include "pkcs11_helpers.h"
#include "serializer.h"

enum pkcs11_rc init_attributes_head(struct obj_attrs **head)
{
	*head = TEE_Malloc(sizeof(**head), TEE_MALLOC_FILL_ZERO);
	if (!*head)
		return PKCS11_CKR_DEVICE_MEMORY;

#ifdef PKCS11_SHEAD_WITH_TYPE
	(*head)->class = PKCS11_CKO_UNDEFINED_ID;
	(*head)->type = PKCS11_CKK_UNDEFINED_ID;
#endif

	return PKCS11_CKR_OK;
}

#if defined(PKCS11_SHEAD_WITH_TYPE) || defined(PKCS11_SHEAD_WITH_BOOLPROPS)
static bool attribute_is_in_head(uint32_t attribute)
{
#ifdef PKCS11_SHEAD_WITH_TYPE
	if (attribute == PKCS11_CKA_CLASS || pkcs11_attr_is_type(attribute))
		return true;
#endif

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	if (pkcs11_attr2boolprop_shift(attribute) >= 0)
		return true;
#endif

	return false;
}
#endif

enum pkcs11_rc add_attribute(struct obj_attrs **head, uint32_t attribute,
			     void *data, size_t size)
{
	size_t buf_len = sizeof(struct obj_attrs) + (*head)->attrs_size;
	char **bstart = (void *)head;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint32_t data32 = 0;
	int __maybe_unused shift = 0;

#ifdef PKCS11_SHEAD_WITH_TYPE
	if (attribute == PKCS11_CKA_CLASS || pkcs11_attr_is_type(attribute)) {
		assert(size == sizeof(uint32_t));

		TEE_MemMove(attribute == PKCS11_CKA_CLASS ?
				&(*head)->class : &(*head)->type,
			    data, sizeof(uint32_t));

		return PKCS11_CKR_OK;
	}
#endif

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	shift = pkcs11_attr2boolprop_shift(attribute);
	if (head_contains_boolprops(*head) && shift >= 0) {
		uint32_t mask = shift < 32 ? BIT(shift) : BIT(shift - 32);
		uint32_t val = *(uint8_t *)data ? mask : 0;

		if (size != sizeof(uint8_t)) {
			EMSG("Invalid size %zu", size);
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}

		if (shift < 32)
			(*head)->boolpropl = ((*head)->boolpropl & ~mask) | val;
		else
			(*head)->boolproph = ((*head)->boolproph & ~mask) | val;

		return PKCS11_CKR_OK;
	}
#endif

	data32 = attribute;
	rc = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rc)
		return rc;

	data32 = size;
	rc = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialize(bstart, &buf_len, data, size);
	if (rc)
		return rc;

	/* Alloced buffer is always well aligned */
	head = (void *)bstart;
	(*head)->attrs_size += 2 * sizeof(uint32_t) + size;
	(*head)->attrs_count++;

	return rc;
}

static enum pkcs11_rc _remove_attribute(struct obj_attrs **head,
					uint32_t attribute, bool empty)
{
	struct obj_attrs *h = *head;
	char *cur = NULL;
	char *end = NULL;
	size_t next_off = 0;

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	/* Can't remove an attribute that is defined in the head */
	if (head_contains_boolprops(*head) && attribute_is_in_head(attribute)) {
		EMSG("Can't remove attribute %s from head",
		     id2str_attr(attribute));
		TEE_Panic(0);
	}
#endif

	/* Let's find the target attribute */
	cur = (char *)h + sizeof(struct obj_attrs);
	end = cur + h->attrs_size;
	for (; cur < end; cur += next_off) {
		struct pkcs11_attribute_head pkcs11_ref;

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		if (pkcs11_ref.id != attribute)
			continue;

		if (empty && pkcs11_ref.size)
			return PKCS11_CKR_FUNCTION_FAILED;

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		h->attrs_count--;
		h->attrs_size -= next_off;
		end -= next_off;
		next_off = 0;

		return PKCS11_CKR_OK;
	}

	DMSG("Attribute %s (%#x) not found", id2str_attr(attribute), attribute);
	return PKCS11_RV_NOT_FOUND;
}

enum pkcs11_rc remove_attribute(struct obj_attrs **head, uint32_t attribute)
{
	return _remove_attribute(head, attribute, false);
}

enum pkcs11_rc remove_empty_attribute(struct obj_attrs **head,
				      uint32_t attribute)
{
	return _remove_attribute(head, attribute, true /* empty */);
}

enum pkcs11_rc remove_attribute_check(struct obj_attrs **head,
				      uint32_t attribute, size_t max_check)
{
	struct obj_attrs *h = *head;
	char *cur = NULL;
	char *end = NULL;
	size_t next_off = 0;
	size_t found = 0;

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	/* Can't remove an attribute that is defined in the head */
	if (head_contains_boolprops(*head) && attribute_is_in_head(attribute)) {
		EMSG("Can't remove attribute %s from head",
		     id2str_attr(attribute));
		TEE_Panic(0);
	}
#endif

	/* Let's find the target attribute */
	cur = (char *)h + sizeof(struct obj_attrs);
	end = cur + h->attrs_size;
	for (; cur < end; cur += next_off) {
		struct pkcs11_attribute_head pkcs11_ref;

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		if (pkcs11_ref.id != attribute)
			continue;

		found++;
		if (found > max_check) {
			DMSG("Too many attribute occurrences");
			return PKCS11_CKR_FUNCTION_FAILED;
		}

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		h->attrs_count--;
		h->attrs_size -= next_off;
		end -= next_off;
		next_off = 0;
	}

	/* sanity */
	if (cur != end) {
		EMSG("Bad end address");
		return PKCS11_CKR_GENERAL_ERROR;
	}

	if (!found)
		return PKCS11_RV_NOT_FOUND;

	return PKCS11_CKR_OK;
}

void get_attribute_ptrs(struct obj_attrs *head, uint32_t attribute,
			void **attr, uint32_t *attr_size, size_t *count)
{
	char *cur = (char *)head + sizeof(struct obj_attrs);
	char *end = cur + head->attrs_size;
	size_t next_off = 0;
	size_t max_found = *count;
	size_t found = 0;
	void **attr_ptr = attr;
	uint32_t *attr_size_ptr = attr_size;

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	/* Can't return a pointer to a boolprop attribute */
	if (head_contains_boolprops(head) && attribute_is_in_head(attribute)) {
		EMSG("Can't get pointer to an attribute in the head");
		TEE_Panic(0);
	}
#endif

	for (; cur < end; cur += next_off) {
		/* Structure aligned copy of the pkcs11_ref in the object */
		struct pkcs11_attribute_head pkcs11_ref = { };

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		if (pkcs11_ref.id != attribute)
			continue;

		found++;

		if (!max_found)
			continue;	/* only count matching attributes */

		if (attr) {
			if (pkcs11_ref.size)
				*attr_ptr++ = cur + sizeof(pkcs11_ref);
			else
				*attr_ptr++ = NULL;
		}

		if (attr_size)
			*attr_size_ptr++ = pkcs11_ref.size;

		if (found == max_found)
			break;
	}

	/* Sanity */
	if (cur > end) {
		DMSG("Exceeding serial object length");
		TEE_Panic(0);
	}

	*count = found;
}

enum pkcs11_rc get_attribute_ptr(struct obj_attrs *head, uint32_t attribute,
				 void **attr_ptr, uint32_t *attr_size)
{
	size_t count = 1;

#ifdef PKCS11_SHEAD_WITH_TYPE
	if (attribute == PKCS11_CKA_CLASS) {
		if (attr_size)
			*attr_size = sizeof(uint32_t);
		if (attr_ptr)
			*attr_ptr = &head->class;

		return PKCS11_CKR_OK;
	}
	if (attribute == PKCS11_CKA_KEY_TYPE) {
		if (attr_size)
			*attr_size = sizeof(uint32_t);
		if (attr_ptr)
			*attr_ptr = &head->type;

		return PKCS11_CKR_OK;
	}
#endif
#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	if (head_contains_boolprops(head) &&
	    pkcs11_attr2boolprop_shift(attribute) >= 0)
		TEE_Panic(0);
#endif

	get_attribute_ptrs(head, attribute, attr_ptr, attr_size, &count);

	if (!count)
		return PKCS11_RV_NOT_FOUND;

	if (count != 1)
		return PKCS11_CKR_GENERAL_ERROR;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc get_attribute(struct obj_attrs *head, uint32_t attribute,
			     void *attr, uint32_t *attr_size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	void *attr_ptr = NULL;
	uint32_t size = 0;
	uint8_t __maybe_unused bbool = 0;
	int __maybe_unused shift = 0;

#ifdef PKCS11_SHEAD_WITH_TYPE
	if (attribute == PKCS11_CKA_CLASS) {
		size = sizeof(uint32_t);
		attr_ptr = &head->class;
		goto found;
	}

	if (attribute == PKCS11_CKA_KEY_TYPE) {
		size = sizeof(uint32_t);
		attr_ptr = &head->type;
		goto found;
	}
#endif

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	shift = pkcs11_attr2boolprop_shift(attribute);
	if (head_contains_boolprops(head) && shift >= 0) {
		uint32_t *boolprop = NULL;

		boolprop = (shift < 32) ? &head->boolpropl : &head->boolproph;
		bbool = *boolprop & BIT(shift % 32);

		size = sizeof(uint8_t);
		attr_ptr = &bbool;
		goto found;
	}
#endif

	rc = get_attribute_ptr(head, attribute, &attr_ptr, &size);
	if (rc)
		return rc;

#if defined(PKCS11_SHEAD_WITH_TYPE) || defined(PKCS11_SHEAD_WITH_BOOLPROPS)
found:
#endif
	if (attr_size && *attr_size != size) {
		*attr_size = size;
		/* This reuses buffer-to-small for any bad size matching */
		return PKCS11_CKR_BUFFER_TOO_SMALL;
	}

	if (attr)
		TEE_MemMove(attr, attr_ptr, size);

	if (attr_size)
		*attr_size = size;

	return PKCS11_CKR_OK;
}

bool get_bool(struct obj_attrs *head, uint32_t attribute)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t bbool = 0;
	uint32_t size = sizeof(bbool);
	int __maybe_unused shift = 0;

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	shift = pkcs11_attr2boolprop_shift(attribute);
	if (shift < 0)
		TEE_Panic(PKCS11_RV_NOT_FOUND);

	if (head_contains_boolprops(head)) {
		if (shift > 31)
			return head->boolproph & BIT(shift - 32);
		else
			return head->boolpropl & BIT(shift);
	}
#endif

	rc = get_attribute(head, attribute, &bbool, &size);

	if (rc == PKCS11_RV_NOT_FOUND)
		return false;

	assert(rc == PKCS11_CKR_OK);
	return bbool;
}

bool attributes_match_reference(struct obj_attrs *candidate,
				struct obj_attrs *ref)
{
	size_t count = ref->attrs_count;
	unsigned char *ref_attr = ref->attrs;
	uint32_t rc = PKCS11_CKR_GENERAL_ERROR;

	if (!ref->attrs_count) {
		DMSG("Empty reference: no match");
		return false;
	}

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	/*
	 * All boolprops attributes must be explicitly defined
	 * as an attribute reference in the reference object.
	 */
	assert(!head_contains_boolprops(ref));
#endif

	for (count = 0; count < ref->attrs_count; count++) {
		struct pkcs11_attribute_head pkcs11_ref;
		void *found = NULL;
		uint32_t size = 0;
		int shift = 0;

		TEE_MemMove(&pkcs11_ref, ref_attr, sizeof(pkcs11_ref));

		shift = pkcs11_attr2boolprop_shift(pkcs11_ref.id);
		if (shift >= 0) {
			bool bb_ref = get_bool(ref, pkcs11_ref.id);
			bool bb_candidate = get_bool(candidate, pkcs11_ref.id);

			if (bb_ref != bb_candidate) {
				return false;
			}
		} else {
			rc = get_attribute_ptr(candidate, pkcs11_ref.id,
					       &found, &size);

			if (rc || !found || size != pkcs11_ref.size ||
			    TEE_MemCompare(ref_attr + sizeof(pkcs11_ref),
					   found, size)) {
				return false;
			}
		}

		ref_attr += sizeof(pkcs11_ref) + pkcs11_ref.size;
	}

	return true;
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/*
 * Debug: dump CK attribute array to output trace
 */
#define ATTR_TRACE_FMT	"%s attr %s / %s\t(0x%04"PRIx32" %"PRIu32"-byte"
#define ATTR_FMT_0BYTE	ATTR_TRACE_FMT ")"
#define ATTR_FMT_1BYTE	ATTR_TRACE_FMT ": %02x)"
#define ATTR_FMT_2BYTE	ATTR_TRACE_FMT ": %02x %02x)"
#define ATTR_FMT_3BYTE	ATTR_TRACE_FMT ": %02x %02x %02x)"
#define ATTR_FMT_4BYTE	ATTR_TRACE_FMT ": %02x %02x %02x %02x)"
#define ATTR_FMT_ARRAY	ATTR_TRACE_FMT ": %02x %02x %02x %02x ...)"

static void __trace_attributes(char *prefix, void *src, void *end)
{
	size_t next_off = 0;
	char *prefix2 = NULL;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix plus terminal '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next_off) {
		struct pkcs11_attribute_head pkcs11_ref = { };
		uint8_t data[4] = { 0 };

		TEE_MemMove(&pkcs11_ref, cur, sizeof(pkcs11_ref));
		TEE_MemMove(&data[0], cur + sizeof(pkcs11_ref),
			    MIN(pkcs11_ref.size, sizeof(data)));

		next_off = sizeof(pkcs11_ref) + pkcs11_ref.size;

		switch (pkcs11_ref.size) {
		case 0:
			IMSG_RAW(ATTR_FMT_0BYTE,
				 prefix, id2str_attr(pkcs11_ref.id), "*",
				 pkcs11_ref.id, pkcs11_ref.size);
			break;
		case 1:
			IMSG_RAW(ATTR_FMT_1BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size, data[0]);
			break;
		case 2:
			IMSG_RAW(ATTR_FMT_2BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size, data[0],
				 data[1]);
			break;
		case 3:
			IMSG_RAW(ATTR_FMT_3BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2]);
			break;
		case 4:
			IMSG_RAW(ATTR_FMT_4BYTE,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2], data[3]);
			break;
		default:
			IMSG_RAW(ATTR_FMT_ARRAY,
				 prefix, id2str_attr(pkcs11_ref.id),
				 id2str_attr_value(pkcs11_ref.id,
						   pkcs11_ref.size,
						   cur + sizeof(pkcs11_ref)),
				 pkcs11_ref.id, pkcs11_ref.size,
				 data[0], data[1], data[2], data[3]);
			break;
		}

		switch (pkcs11_ref.id) {
		case PKCS11_CKA_WRAP_TEMPLATE:
		case PKCS11_CKA_UNWRAP_TEMPLATE:
		case PKCS11_CKA_DERIVE_TEMPLATE:
			if (pkcs11_ref.size)
				trace_attributes(prefix2,
						 cur + sizeof(pkcs11_ref));
			break;
		default:
			break;
		}
	}

	/* Sanity */
	if (cur != end)
		EMSG("Warning: unexpected alignment in object attributes");

	TEE_Free(prefix2);
}

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
static void trace_boolprops(const char *prefix, struct obj_attrs *head)
{
	size_t __maybe_unused n = 0;

	for (n = 0; n <= PKCS11_BOOLPROPS_LAST; n++) {
		bool bp = n < 32 ? !!(head->boolpropl & BIT(n)) :
				 !!(head->boolproph & BIT(n - 32));

		IMSG_RAW("%s| attr %s / %s (0x%"PRIx32")",
			 prefix, id2str_attr(n), bp ? "TRUE" : "FALSE", n);
	}
}
#endif

void trace_attributes(const char *prefix, void *ref)
{
	struct obj_attrs head = { };
	char *pre = NULL;

	TEE_MemMove(&head, ref, sizeof(head));

	if (!head.attrs_count)
		return;

	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre) {
		EMSG("%s: out of memory", prefix);
		return;
	}

	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	IMSG_RAW("%s,--- (serial object) Attributes list --------", pre);
	IMSG_RAW("%s| %"PRIu32" item(s) - %"PRIu32" bytes",
		 pre, head.attrs_count, head.attrs_size);
#ifdef PKCS11_SHEAD_WITH_TYPE
	IMSG_RAW("%s| class (0x%"PRIx32") %s type (0x%"PRIx32") %s",
		 pre, head.class, id2str_class(head.class),
		 head.type, id2str_type(head.type, head.class));
#endif

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	if (head_contains_boolprops(&head))
		trace_boolprops(pre, &head);
#endif

	pre[prefix ? strlen(prefix) : 0] = '|';
	__trace_attributes(pre, (char *)ref + sizeof(head),
			   (char *)ref + sizeof(head) + head.attrs_size);

	IMSG_RAW("%s`-----------------------", prefix ? prefix : "");

	TEE_Free(pre);
}
#endif /*CFG_TEE_TA_LOG_LEVEL*/
