/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_arch.h>
#include <fwk_errno.h>
#include <fwk_mm.h>
#include <fwk_noreturn.h>
#include <internal/fwk_module.h>
#include <internal/fwk_thread.h>
#include <kernel/panic.h>
#include <malloc.h>


void *fwk_mm_alloc(size_t num, size_t size)
{
    return malloc(num * size);
}
void *fwk_mm_calloc(size_t num, size_t size)
{
    return calloc(num, size);
}

void optee_init_scmi(void);
void optee_init_scmi(void)
{
	if (__fwk_module_init() != FWK_SUCCESS)
		panic();
}

void optee_process_scmi(void);
void optee_process_scmi(void)
{
	__fwk_run_event();
}
