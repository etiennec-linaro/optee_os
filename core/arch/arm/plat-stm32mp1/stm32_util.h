/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <assert.h>
#include <drivers/stm32_bsec.h>
#include <kernel/panic.h>
#include <stdint.h>

/* Backup registers and RAM utils */
uintptr_t stm32mp_bkpreg(unsigned int idx);

/* Platform util for the GIC */
uintptr_t get_gicc_base(void);
uintptr_t get_gicd_base(void);

/*
 * Platform util functions for the GPIO driver
 * @bank: Target GPIO bank ID as per DT bindings
 *
 * Platform shall implement these functions to provide to stm32_gpio
 * driver the resource reference for a target GPIO bank. That are
 * memory mapped interface base address, interface offset (see below)
 * and clock identifier.
 *
 * stm32_get_gpio_bank_offset() returns a bank offset that is used to
 * check DT configuration matches platform implementation of the banks
 * description.
 */
vaddr_t stm32_get_gpio_bank_base(unsigned int bank);
unsigned int stm32_get_gpio_bank_offset(unsigned int bank);
unsigned int stm32_get_gpio_bank_clock(unsigned int bank);

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

/*
 * Util for clock gating and to get clock rate for stm32 and platform drivers
 * @id: Target clock ID, ID used in clock DT bindings
 */
void stm32_clock_enable(unsigned long id);
void stm32_clock_disable(unsigned long id);
unsigned long stm32_clock_get_rate(unsigned long id);
bool stm32_clock_is_enabled(unsigned long id);

/*
 * Util for reset signal assertion/desassertion for stm32 and platform drivers
 * @id: Target peripheral ID, ID used in reset DT bindings
 */
void stm32_reset_assert(unsigned int id);
void stm32_reset_deassert(unsigned int id);

/*
 * Structure and API function for BSEC driver to get some platform data.
 *
 * @base: BSEC interface registers physical base address
 * @upper_start: Base ID for the BSEC upper words in the platform
 * @max_id: Max value for BSEC word ID for the platform
 * @closed_device_id: BSEC word ID storing the "closed_device" OTP bit
 * @closed_device_position: Bit position of "closed_device" bit in the OTP word
 */
struct stm32_bsec_static_cfg {
	paddr_t base;
	unsigned int upper_start;
	unsigned int max_id;
	unsigned int closed_device_id;
	unsigned int closed_device_position;
};

void stm32mp_get_bsec_static_cfg(struct stm32_bsec_static_cfg *cfg);

/*
 * Shared peripherals and resources registration
 *
 * Resources listed in enum stm32mp_shres assigned at run-time to the
 * non-secure world, to the secure world or shared by both worlds.
 * In the later case, there must exist a secure service in OP-TEE
 * for the non-secure world to access the resource.
 *
 * Resources may be a peripheral, a bus, a clock or a memory.
 *
 * Shared resources driver API functions allows drivers to register the
 * resource as secure, non-secure or shared and to get the resource
 * assignation state.
 */
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
	STM32MP1_SHRES_MCU,
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
	STM32MP1_SHRES_COUNT
};

/* Register resource @id as a secure peripheral */
void stm32mp_register_secure_periph(enum stm32mp_shres id);

/* Register resource @id as a non-secure peripheral */
void stm32mp_register_non_secure_periph(enum stm32mp_shres id);

/*
 * Register resource identified by @base as a secure peripheral
 * @base: IOMEM physical base address of the resource
 */
void stm32mp_register_secure_periph_iomem(uintptr_t base);

/*
 * Register resource identified by @base as a non-secure peripheral
 * @base: IOMEM physical base address of the resource
 */
void stm32mp_register_non_secure_periph_iomem(uintptr_t base);

/*
 * Register GPIO resource as a secure peripheral
 * @bank: Bank of the target GPIO
 * @pin: Bit position of the target GPIO in the bank
 */
void stm32mp_register_secure_gpio(unsigned int bank, unsigned int pin);

/*
 * Register GPIO resource as a non-secure peripheral
 * @bank: Bank of the target GPIO
 * @pin: Bit position of the target GPIO in the bank
 */
void stm32mp_register_non_secure_gpio(unsigned int bank, unsigned int pin);

/* Return true if and only if resource @id is registered as secure */
bool stm32mp_periph_is_secure(enum stm32mp_shres id);

/* Return true if and only if the resource @id is registered as non-secure */
bool stm32mp_periph_is_non_secure(enum stm32mp_shres id);

/* Return true if and only if the resource @id is not registered */
bool stm32mp_periph_is_unregistered(enum stm32mp_shres id);

/* Return true if and only if GPIO bank @bank is registered as secure */
bool stm32mp_gpio_bank_is_secure(unsigned int bank);

/* Return true if and only if GPIO bank @bank is registered as shared */
bool stm32mp_gpio_bank_is_shared(unsigned int bank);

/* Return true if and only if GPIO bank @bank is registered as non-secure */
bool stm32mp_gpio_bank_is_non_secure(unsigned int bank);

/* Return true if and only if @clock_id is shareable */
bool stm32mp_clock_is_shareable(unsigned long clock_id);

/* Return true if and only if @clock_id is shared by secure and non-secure */
bool stm32mp_clock_is_shared(unsigned long clock_id);

/* Return true if and only if @clock_id is assigned to non-secure world */
bool stm32mp_clock_is_non_secure(unsigned long clock_id);

#endif /*__STM32_UTIL_H__*/
