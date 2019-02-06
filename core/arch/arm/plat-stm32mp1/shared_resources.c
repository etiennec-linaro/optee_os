// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <drivers/stm32mp1_clk.h>
#include <stm32_util.h>

void stm32_clock_enable(unsigned long id)
{
	stm32mp1_clk_enable_secure(id);
}

void stm32_clock_disable(unsigned long id)
{
	stm32mp1_clk_disable_secure(id);
}
