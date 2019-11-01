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
void scmi_server_process_thread(unsigned int id);
#else
static inline void scmi_server_process_thread(unsigned int id __unused)
{
}
#endif

#endif /* SCMI_SERVER_H */
