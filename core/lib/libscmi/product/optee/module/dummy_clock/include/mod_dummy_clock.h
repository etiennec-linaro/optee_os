/*
 * Arm SCP/MCP Software
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_DUMMY_CLOCK_H
#define MOD_DUMMY_CLOCK_H

#include <stdint.h>
#include <fwk_element.h>
#include <fwk_macros.h>

/*!
 * \brief Dummy clock: relates to an ID
 */
struct mod_dummy_clock_dev_config {
	unsigned long clock_id;
	int state;
	uint64_t rate;
};

#endif /* MOD_STM32_CLOCK_H */
