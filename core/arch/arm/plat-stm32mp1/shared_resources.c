// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <drivers/stm32mp1_clk.h>
#include <io.h>
#include <kernel/spinlock.h>
#include <stm32_util.h>

static unsigned int shregs_lock = SPINLOCK_UNLOCK;

uint32_t lock_stm32shregs(void)
{
	return may_spin_lock(&shregs_lock);
}

void unlock_stm32shregs(uint32_t exceptions)
{
	may_spin_unlock(&shregs_lock, exceptions);
}

void io_mask32_stm32shregs(uintptr_t addr, uint32_t value, uint32_t mask)
{
	uint32_t exceptions = lock_stm32shregs();

	io_mask32(addr, value, mask);

	unlock_stm32shregs(exceptions);
}

void stm32_clock_enable(unsigned long id)
{
	stm32mp1_clk_enable_secure(id);
}

void stm32_clock_disable(unsigned long id)
{
	stm32mp1_clk_disable_secure(id);
}
