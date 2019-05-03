/*
 * Arm SCP/MCP Software
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_STM32_CLOCK_H
#define MOD_STM32_CLOCK_H

#include <stdint.h>
#include <fwk_element.h>
#include <fwk_macros.h>
/*!
 * \brief PLL device configuration.
 */
struct mod_stm32_clock_dev_config {
    const unsigned long clock_id;
};

#endif /* MOD_STM32_CLOCK_H */
