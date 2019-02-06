/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2018-2019, STMicroelectronics
 */

#ifndef __STM32MP1_CLK_H
#define __STM32MP1_CLK_H

#include <stdbool.h>

/*
 * Enable clock from a secure or non-secure request
 * @id: Target clock from stm32mp1 clock bindings IDs
 * @secure_request: False if and only if non-secure world request clock enable
 *
 * The difference between secure/non-secure origin is related to the
 * reference counter used to track clock state.
 */
void __stm32mp1_clk_enable(unsigned long id, bool secure_request);

/*
 * Disable clock from a secure or non-secure request
 * @id: Target clock from stm32mp1 clock bindings IDs
 * @secure_request: False if and only if non-secure world request clock disable
 */
void __stm32mp1_clk_disable(unsigned long id, bool secure_request);

/*
 * Helpers for explicit clock enable/disable upon secure or non-secure requester
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
