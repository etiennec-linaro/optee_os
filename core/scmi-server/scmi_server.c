/*
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * OPTEE product in SCP-firmware builds a SCMI server stack for the
 * OP-TEE core firmware. SCMI server comes with fwk and its embedded
 * modules into OP-TEE core.
 */
#include <config.h>
#include <fwk_macros.h>
#include <fwk_mm.h>
#include <fwk_arch.h>
#include <fwk_thread.h>
#include <initcall.h>
#include <internal/fwk_module.h>
#include <internal/fwk_thread.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <mod_optee_mhu.h>
#include <scmi/scmi_server.h>
#include <scmi_agents.h>

#if 0
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
int scmi_server_get_channels_count(void)
{
	return optee_mhu_get_devices_count();
}

int scmi_server_get_channel(unsigned int id, void* mem, unsigned int size)
{
	fwk_id_t device_id;

	device_id = optee_mhu_get_device(id, mem, size);

	if (fwk_id_is_type(device_id, FWK_ID_TYPE_NONE))
		return -1;

	return (int)device_id.value;
}

void scmi_server_process_thread(unsigned int id, void *memory)
{
	fwk_id_t device_id;

	device_id.value = id;

	DMSG("+++++ [SRV] enter %08x", device_id.value);

	fwk_set_thread_ctx(device_id);

	DMSG("[SRV] send message device %08x", device_id.value);
	optee_mhu_signal_smt_message(device_id, memory);

	DMSG("[SRV] process event %08x", device_id.value);
	__fwk_run_event();

	DMSG("----- [SRV] leave %08x", device_id.value);
}

static TEE_Result scmi_server_initialize(void)
{
	int rc = fwk_arch_init(NULL);

	DMSG("SCMI server init: %s (%d)", fwk_status_str(rc), rc);
	if (IS_ENABLED(BUILD_HAS_MULTITHREADING))
		DMSG("SCMI server supports multithread");
	if (IS_ENABLED(BUILD_HAS_NOTIFICATION))
		DMSG("SCMI server supports agent notification");

	if (rc != FWK_SUCCESS) {
		EMSG("SCMI server init failed: %d", rc);
		panic();
	}

	return TEE_SUCCESS;
}
driver_init(scmi_server_initialize);
