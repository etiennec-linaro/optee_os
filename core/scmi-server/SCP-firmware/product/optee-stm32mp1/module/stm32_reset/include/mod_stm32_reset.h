/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_STM32_RESET_H
#define MOD_STM32_RESET_H

/*!
 * \brief Platform reset domain configuration.
 */
struct mod_stm32_reset_dev_config {
    unsigned long rcc_rst_id;
    const char *name;
};

#endif /* MOD_STM32_RESET_H */
