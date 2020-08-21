/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_STM32_RESET_H
#define MOD_STM32_RESET_H

#include <stdint.h>
#include <dt-bindings/reset/stm32mp1-resets.h>

#define RESET_DEV_IDX_SPI6	RST_SCMI0_SPI6
#define RESET_DEV_IDX_I2C4	RST_SCMI0_I2C4
#define RESET_DEV_IDX_I2C6	RST_SCMI0_I2C6
#define RESET_DEV_IDX_USART1	RST_SCMI0_USART1
#define RESET_DEV_IDX_STGEN	RST_SCMI0_STGEN
#define RESET_DEV_IDX_GPIOZ	RST_SCMI0_GPIOZ
#define RESET_DEV_IDX_CRYP1	RST_SCMI0_CRYP1
#define RESET_DEV_IDX_HASH1	RST_SCMI0_HASH1
#define RESET_DEV_IDX_RNG1	RST_SCMI0_RNG1
#define RESET_DEV_IDX_MDMA	RST_SCMI0_MDMA
#define RESET_DEV_IDX_MCU	RST_SCMI0_MCU

/*!
 * \brief Platform clocks configuration.
 */
struct mod_stm32_reset_dev_config {
    const unsigned long reset_id;
};

#endif /* MOD_STM32_RESET_H */
