/*
 * Arm SCP/MCP Software
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_STM32_CLOCK_H
#define MOD_STM32_CLOCK_H

#include <dt-bindings/clock/stm32mp1-clks.h>
#include <fwk_element.h>
#include <fwk_macros.h>
#include <stdint.h>
#include <stm32_util.h>

#define CLOCK_DEV_IDX_HSE	CK_SCMI_HSE
#define CLOCK_DEV_IDX_HSI	CK_SCMI_HSI
#define CLOCK_DEV_IDX_CSI	CK_SCMI_CSI
#define CLOCK_DEV_IDX_LSE	CK_SCMI_LSE
#define CLOCK_DEV_IDX_LSI	CK_SCMI_LSI
#define CLOCK_DEV_IDX_PLL1_P	CK_SCMI_PLL1_P
#define CLOCK_DEV_IDX_PLL1_Q	CK_SCMI_PLL1_Q
#define CLOCK_DEV_IDX_PLL1_R	CK_SCMI_PLL1_R
#define CLOCK_DEV_IDX_PLL2_P	CK_SCMI_PLL2_P
#define CLOCK_DEV_IDX_PLL2_Q	CK_SCMI_PLL2_Q
#define CLOCK_DEV_IDX_PLL2_R	CK_SCMI_PLL2_R
#define CLOCK_DEV_IDX_PLL3_P	CK_SCMI_PLL3_P
#define CLOCK_DEV_IDX_PLL3_Q	CK_SCMI_PLL3_Q
#define CLOCK_DEV_IDX_PLL3_R	CK_SCMI_PLL3_R
#define CLOCK_DEV_IDX_SPI6	CK_SCMI_SPI6
#define CLOCK_DEV_IDX_I2C4	CK_SCMI_I2C4
#define CLOCK_DEV_IDX_I2C6	CK_SCMI_I2C6
#define CLOCK_DEV_IDX_USART1	CK_SCMI_USART1
#define CLOCK_DEV_IDX_RTCAPB	CK_SCMI_RTCAPB
#define CLOCK_DEV_IDX_IWDG1	CK_SCMI_IWDG1
#define CLOCK_DEV_IDX_GPIOZ	CK_SCMI_GPIOZ
#define CLOCK_DEV_IDX_CRYP1	CK_SCMI_CRYP1
#define CLOCK_DEV_IDX_HASH1	CK_SCMI_HASH1
#define CLOCK_DEV_IDX_RNG1	CK_SCMI_RNG1
#define CLOCK_DEV_IDX_RTC	CK_SCMI_RTC

/*!
 * \brief Platform clocks configuration.
 */
struct mod_stm32_clock_dev_config {
    const unsigned long clock_id;
};

#endif /* MOD_STM32_CLOCK_H */
