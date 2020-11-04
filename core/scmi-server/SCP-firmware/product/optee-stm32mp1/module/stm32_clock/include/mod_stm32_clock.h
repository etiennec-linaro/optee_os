/*
 * Copyright (c) 2019-2020, Linaro Limited
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_STM32_CLOCK_H
#define MOD_STM32_CLOCK_H

#include <fwk_element.h>
#include <fwk_macros.h>
#include <stdint.h>
#include <stm32_util.h>


/*!
 * \brief Platform clocks configuration.
 */
struct mod_stm32_clock_dev_config {
    const char *name;
    unsigned long rcc_clk_id;
    bool default_enabled;
};

#endif /* MOD_STM32_CLOCK_H */
