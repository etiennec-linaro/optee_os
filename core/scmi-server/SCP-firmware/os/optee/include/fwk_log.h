/*
 * Arm SCP/MCP Software
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FWK_LOG_H
#define FWK_LOG_H

#include <trace.h>

#define FWK_LOG_LEVEL_TRACE	0
#define FWK_LOG_LEVEL_INFO	1
#define FWK_LOG_LEVEL_WARN	2
#define FWK_LOG_LEVEL_ERROR	3
#define FWK_LOG_LEVEL_CRIT	4

#define FWK_LOG_FLUSH()		do { } while (0)
#define FWK_LOG_TRACE(...)	DMSG(__VA_ARGS__)
#define FWK_LOG_INFO(...)	IMSG(__VA_ARGS__)
#define FWK_LOG_WARN(...)	IMSG(__VA_ARGS__)
#define FWK_LOG_ERR(...)	EMSG(__VA_ARGS__)
#define FWK_LOG_CRIT(...)	EMSG(__VA_ARGS__)

static inline void fwk_log_flush(void)
{
}

static inline int fwk_log_unbuffer(void)
{
	return 0;
}
#endif /* FWK_LOG_H */
