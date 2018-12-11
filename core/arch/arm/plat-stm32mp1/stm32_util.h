/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <stdint.h>

/* Backup registers and RAM utils */
uintptr_t stm32mp_bkpreg(unsigned int idx);

/* Platform util for the GIC */
uintptr_t get_gicc_base(void);
uintptr_t get_gicd_base(void);

/* Power management service */
#ifdef CFG_PSCI_ARM32
void stm32mp_register_online_cpu(void);
#else
static inline void stm32mp_register_online_cpu(void)
{
}
#endif

/*
 * Generic spinlock function that bypass spinlock if MMU is disabled or
 * lock is NULL.
 */
uint32_t may_spin_lock(unsigned int *lock);
void may_spin_unlock(unsigned int *lock, uint32_t exceptions);

#define STM32MP1_SHRES_GPIOZ(i)		(STM32MP1_SHRES_GPIOZ_0 + i)

enum stm32mp_shres {
	STM32MP1_SHRES_GPIOZ_0 = 0,
	STM32MP1_SHRES_GPIOZ_1,
	STM32MP1_SHRES_GPIOZ_2,
	STM32MP1_SHRES_GPIOZ_3,
	STM32MP1_SHRES_GPIOZ_4,
	STM32MP1_SHRES_GPIOZ_5,
	STM32MP1_SHRES_GPIOZ_6,
	STM32MP1_SHRES_GPIOZ_7,
	STM32MP1_SHRES_IWDG1,
	STM32MP1_SHRES_USART1,
	STM32MP1_SHRES_SPI6,
	STM32MP1_SHRES_I2C4,
	STM32MP1_SHRES_RNG1,
	STM32MP1_SHRES_HASH1,
	STM32MP1_SHRES_CRYP1,
	STM32MP1_SHRES_I2C6,
	STM32MP1_SHRES_RTC,
	STM32MP1_SHRES_HSI,
	STM32MP1_SHRES_LSI,
	STM32MP1_SHRES_HSE,
	STM32MP1_SHRES_LSE,
	STM32MP1_SHRES_CSI,
	STM32MP1_SHRES_PLL1,
	STM32MP1_SHRES_PLL1_P,
	STM32MP1_SHRES_PLL1_Q,
	STM32MP1_SHRES_PLL1_R,
	STM32MP1_SHRES_PLL2,
	STM32MP1_SHRES_PLL2_P,
	STM32MP1_SHRES_PLL2_Q,
	STM32MP1_SHRES_PLL2_R,
	STM32MP1_SHRES_PLL3,
	STM32MP1_SHRES_PLL3_P,
	STM32MP1_SHRES_PLL3_Q,
	STM32MP1_SHRES_PLL3_R,
	STM32MP1_SHRES_PLL4,
	STM32MP1_SHRES_PLL4_P,
	STM32MP1_SHRES_PLL4_Q,
	STM32MP1_SHRES_PLL4_R,

	STM32MP1_SHRES_COUNT
};

void stm32mp_register_secure_periph(unsigned int id);
void stm32mp_register_shared_periph(unsigned int id);
void stm32mp_register_non_secure_periph(unsigned int id);
void stm32mp_register_secure_periph_iomem(uintptr_t base);
void stm32mp_register_non_secure_periph_iomem(uintptr_t base);
void stm32mp_register_secure_gpio(unsigned int bank, unsigned int pin);
void stm32mp_register_non_secure_gpio(unsigned int bank, unsigned int pin);

bool stm32mp_periph_is_shared(unsigned long id);
bool stm32mp_periph_is_non_secure(unsigned long id);
bool stm32mp_periph_is_secure(unsigned long id);
bool stm32mp_periph_is_unregistered(unsigned long id);

bool stm32mp_gpio_bank_is_shared(unsigned int bank);
bool stm32mp_gpio_bank_is_non_secure(unsigned int bank);
bool stm32mp_gpio_bank_is_secure(unsigned int bank);

#endif /*__STM32_UTIL_H__*/
