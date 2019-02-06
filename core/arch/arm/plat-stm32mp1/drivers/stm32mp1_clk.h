/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2018-2019, STMicroelectronics
 */

#ifndef __STM32MP1_CLK_H
#define __STM32MP1_CLK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum stm32mp_osc_id {
	_HSI = 0,
	_HSE,
	_CSI,
	_LSI,
	_LSE,
	_I2S_CKIN,
	_USB_PHY_48,
	NB_OSC,
	_UNKNOWN_OSC_ID = 0xffU
};

/*
 * Enable/disable clock from a secure or non-secure request
 * @id: Target clock from stm32mp1 clock bindings IDs
 * @secure_request: False if and only if non-secure world request clock enable
 *
 * The difference between secure/non-secure origin is related to the
 * reference counter used to track clock state.
 */
void __stm32mp1_clk_enable(unsigned long id, bool secure_request);

/*
 * Enable clock from a secure or non-secure request
 * @id: Target clock from stm32mp1 clock bindings IDs
 * @secure_request: False if and only if non-secure world request clock disable
 */
void __stm32mp1_clk_disable(unsigned long id, bool secure_request);

/*
 * Return whether target clock is enabled or not
 * @id: Target clock from stm32mp1 clock bindings IDs
 */
bool stm32mp1_clk_is_enabled(unsigned long id);

/*
 * Helpers for enabling/disabling clocks from secure and non-secure requests.
 * @id: Target clock from stm32mp1 clock bindings IDs
 */
static inline void stm32mp1_clk_enable_non_secure(unsigned long id)
{
	__stm32mp1_clk_enable(id, false);
}

static inline void stm32mp1_clk_enable_secure(unsigned long id)
{
	__stm32mp1_clk_enable(id, true);
}

static inline void stm32mp1_clk_disable_non_secure(unsigned long id)
{
	__stm32mp1_clk_disable(id, false);
}

static inline void stm32mp1_clk_disable_secure(unsigned long id)
{
	__stm32mp1_clk_disable(id, true);
}

#endif /*__STM32MP1_CLK_H*/
