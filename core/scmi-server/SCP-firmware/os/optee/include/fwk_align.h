/*
 * Arm SCP/MCP Software
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *      Provides alignment support from OP-TEE Core resources.
 */

#ifndef FWK_ALIGN_H
#define FWK_ALIGN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __ARMCC_VERSION
#   define alignas _Alignas
#   define alignof _Alignof

#   define __alignas_is_defined 1
#   define __alignof_is_defined 1
#else
#    include <stdalign.h>
#endif

#ifndef _GCC_MAX_ALIGN_T
typedef uintmax_t max_align_t;
#endif

#endif /* FWK_ALIGN_H */
