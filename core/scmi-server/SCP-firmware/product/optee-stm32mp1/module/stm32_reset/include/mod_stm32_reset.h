/*
 * Arm SCP/MCP Software
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_STM32_RESET_H
#define MOD_STM32_RESET_H

#include <stdint.h>
#include <dt-bindings/reset/stm32mp1-resets.h>

#define RESET_DEV_IDX_SPI6	RST_SCMI_SPI6
#define RESET_DEV_IDX_I2C4	RST_SCMI_I2C4
#define RESET_DEV_IDX_I2C6	RST_SCMI_I2C6
#define RESET_DEV_IDX_USART1	RST_SCMI_USART1
#define RESET_DEV_IDX_STGEN	RST_SCMI_STGEN
#define RESET_DEV_IDX_GPIOZ	RST_SCMI_GPIOZ
#define RESET_DEV_IDX_CRYP1	RST_SCMI_CRYP1
#define RESET_DEV_IDX_HASH1	RST_SCMI_HASH1
#define RESET_DEV_IDX_RNG1	RST_SCMI_RNG1
#define RESET_DEV_IDX_MDMA	RST_SCMI_MDMA
#define RESET_DEV_IDX_MCU	RST_SCMI_MCU

/*!
 * \brief Platform clocks configuration.
 */
struct mod_stm32_reset_dev_config {
    const unsigned long reset_id;
};

#endif /* MOD_STM32_RESET_H */
