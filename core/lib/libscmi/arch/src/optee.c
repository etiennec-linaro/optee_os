/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_arch.h>
#include <fwk_errno.h>
#include <fwk_noreturn.h>
#include <fwk_host.h>

#define HEAP_SIZE (1024*1024)
uint8_t scmi_local_heap[HEAP_SIZE];
int initialized = FWK_E_INIT;

extern int host_interrupt_init(struct fwk_arch_interrupt_driver **driver);
extern void __fwk_run_event(void);

static int mm_init(struct fwk_arch_mm_data *data)
{
    const size_t size = HEAP_SIZE;
	void *mem;

    mem = scmi_local_heap;
	if (mem == NULL)
        return FWK_E_NOMEM;

    data->start = (uintptr_t)mem;
    data->size = size;

    return FWK_SUCCESS;
}

static const struct fwk_arch_init_driver arch_init_driver = {
    .mm = mm_init,
    .interrupt = host_interrupt_init,
};

void optee_init_scmi(void)
{
	if (initialized)
		initialized = fwk_arch_init(&arch_init_driver);

	__fwk_run_event();
}

void optee_process_scmi(void)
{
	__fwk_run_event();
}

