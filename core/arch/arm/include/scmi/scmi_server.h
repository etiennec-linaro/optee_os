/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */
#ifndef SCMI_SERVER_H
#define SCMI_SERVER_H

#include <tee_api_types.h>

#if defined(CFG_SCMI_SERVER)
/*
 * void scmi_server_process_thread(uint32_t id)
 *
 * Raise annd process incoming event in the SCMI server for a target MHU
 * Exported by scmi-server
 */
void scmi_server_process_thread(unsigned int id, void *memory);

int scmi_server_get_channel(unsigned int id, void* mem, unsigned int size);

int scmi_server_get_channels_count(void);

#else
static inline void scmi_server_process_thread(unsigned int id __unused, void *memory __unused)
{
}

static inline int scmi_server_get_channel(unsigned int id, void* mem __unused, unsigned int size __unused)
{
	return -1,
}

static inline int scmi_server_get_channels_count(void)
{
	return 0;
}

#endif

#endif /* SCMI_SERVER_H */
