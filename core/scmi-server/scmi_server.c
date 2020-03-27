/*
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * OPTEE product in SCP-firmware builds a SCMI server stack for the
 * OP-TEE core firmware. SCMI server comes with fwk and its embedded
 * modules into OP-TEE core.
 */
#include <fwk_host.h>
#include <fwk_macros.h>
#include <fwk_mm.h>
#include <initcall.h>
#include <internal/fwk_module.h>
#include <internal/fwk_thread.h>
#include <kernel/mutex.h>
#include <malloc.h>
#include <mod_optee_mhu.h>
#include <scmi/scmi_server.h>
#include <scmi_agents.h>

#if !defined(BUILD_HAS_MULTITHREADING)
static struct mutex entry_mu = MUTEX_INITIALIZER;
static struct condvar entry_cv = CONDVAR_INITIALIZER;
static bool server_busy;

static void thread_entry(void)
{
	mutex_lock(&entry_mu);
	while (server_busy)
		condvar_wait(&entry_cv, &entry_mu);
	server_busy = true;
	mutex_unlock(&entry_mu);
}

static void thread_exit(void)
{
	mutex_lock(&entry_mu);
	server_busy = false;
	condvar_signal(&entry_cv);
	mutex_unlock(&entry_mu);
}
#else
static void thread_exit(void)
{
}
static void thread_exit(void)
{
}
#endif

/*
 * Routines SCP-firmware request to the related OP-TEE function
 */

void *fwk_mm_alloc(size_t num, size_t size)
{
	return malloc(num * size);
}

void *fwk_mm_calloc(size_t num, size_t size)
{
	return calloc(num, size);
}

/*
 * SCMI server APIs exported to OP-TEE core
 */
void scmi_server_process_thread(unsigned int id)
{
	thread_entry();

	optee_mhu_signal_smt_message(SCMI_CHANNEL_DEVICE_IDX_NS, id);
	__fwk_run_event();

	thread_exit();
}

static TEE_Result scmi_server_initialize(void)
{
	int rc = __fwk_module_init();

	FWK_HOST_PRINT("SCMI server init: %s (%d)", fwk_err2str(rc), rc);
#ifdef BUILD_HAS_MULTITHREADING
	FWK_HOST_PRINT("SCMI server supports multithread");
#endif
#ifdef BUILD_HAS_NOTIFICATION
	FWK_HOST_PRINT("SCMI server supports agent notification");
#endif

	if (rc == FWK_SUCCESS)
		return TEE_SUCCESS;

	return TEE_ERROR_GENERIC;
}
driver_init(scmi_server_initialize);
