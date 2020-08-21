/*
 * Copyright (c) 2019-2020, Linaro Limited
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

#define CLOCK_DEV_IDX_HSE	CK_SCMI0_HSE
#define CLOCK_DEV_IDX_HSI	CK_SCMI0_HSI
#define CLOCK_DEV_IDX_CSI	CK_SCMI0_CSI
#define CLOCK_DEV_IDX_LSE	CK_SCMI0_LSE
#define CLOCK_DEV_IDX_LSI	CK_SCMI0_LSI
#define CLOCK_DEV_IDX_PLL2_Q	CK_SCMI0_PLL2_Q
#define CLOCK_DEV_IDX_PLL2_R	CK_SCMI0_PLL2_R
#define CLOCK_DEV_IDX_MPU	CK_SCMI0_MPU
#define CLOCK_DEV_IDX_AXI	CK_SCMI0_AXI
#define CLOCK_DEV_IDX_BSEC	CK_SCMI0_BSEC
#define CLOCK_DEV_IDX_CRYP1	CK_SCMI0_CRYP1
#define CLOCK_DEV_IDX_GPIOZ	CK_SCMI0_GPIOZ
#define CLOCK_DEV_IDX_HASH1	CK_SCMI0_HASH1
#define CLOCK_DEV_IDX_I2C4	CK_SCMI0_I2C4
#define CLOCK_DEV_IDX_I2C6	CK_SCMI0_I2C6
#define CLOCK_DEV_IDX_IWDG1	CK_SCMI0_IWDG1
#define CLOCK_DEV_IDX_RNG1	CK_SCMI0_RNG1
#define CLOCK_DEV_IDX_RTC	CK_SCMI0_RTC
#define CLOCK_DEV_IDX_RTCAPB	CK_SCMI0_RTCAPB
#define CLOCK_DEV_IDX_SPI6	CK_SCMI0_SPI6
#define CLOCK_DEV_IDX_USART1	CK_SCMI0_USART1

/*!
 * \brief Platform clocks configuration.
 */
struct mod_stm32_clock_dev_config {
    const unsigned long clock_id;
};

#endif /* MOD_STM32_CLOCK_H */
