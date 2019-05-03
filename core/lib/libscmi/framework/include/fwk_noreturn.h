/*
 * Arm SCP/MCP Software
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
*
 * Description:
 *      Provides <stdnoreturn.h> features missing in certain standard library
 *      implementations.
 */

#ifndef FWK_NORETURN_H
#define FWK_NORETURN_H

#ifndef BUILD_OPTEE // OP-TEE relies on noretrun as attribute
#ifdef __ARMCC_VERSION
#   define noreturn _Noreturn
#else
#   include <stdnoreturn.h>
#endif
#endif //BUILD_OPTEE

#endif /* FWK_NORETURN_H */
