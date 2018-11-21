/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <kernel/panic.h>
#include <sm/sm.h>
#include <stdint.h>

/* SiP & OEM platform services */
bool stm32_sip_service(struct sm_ctx *ctx,
		       uint32_t *a0, uint32_t *a1, uint32_t *a2, uint32_t *a3);
bool stm32_oem_service(struct sm_ctx *ctx,
		       uint32_t *a0, uint32_t *a1, uint32_t *a2, uint32_t *a3);

/* Backup registers and RAM utils */
uintptr_t stm32mp_bkpreg(unsigned int idx);

/* Platform util for the GIC */
uintptr_t get_gicc_base(void);
uintptr_t get_gicd_base(void);

/* Platform util for the BSEC driver */
uintptr_t stm32mp_get_bsec_base(void);
unsigned int stm32mp_get_otp_max(void);
unsigned int stm32mp_get_otp_upper_start(void);

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
 * Shared reference counter: increments by 2 on secure increment
 * request, decrements by 2 on secure decrement request. Bit #0
 * is set to 1 on non-secure increment request and reset to 0 on
 * non-secure decrement request. These counter initializes to
 * either 0, 1 or 2 upon their expect default state.
 * Increment refcount and return if incremented from 0.
 * Counters saturates once above UINT_MAX / 2.
 */
#define SHREFCNT_NONSECURE_FLAG		0x1ul
#define SHREFCNT_SECURE_STEP		0x2ul
#define SHREFCNT_MAX			(UINT_MAX / 2)

/* Return 1 if refcnt decrements to 0, else return 0 */
static inline int incr_shrefcnt(unsigned int *refcnt, bool secure)
{
	int rc = !*refcnt;

	if (secure) {
		if (*refcnt < SHREFCNT_MAX) {
			*refcnt += SHREFCNT_SECURE_STEP;
			assert(*refcnt < SHREFCNT_MAX);
		}
	} else {
		*refcnt |= SHREFCNT_NONSECURE_FLAG;
	}

	return rc;
}

/* Return 1 if refcnt decrements to 0, else return 0 */
static inline int decr_shrefcnt(unsigned int *refcnt, bool secure)
{
	int  rc = 0;

	if (secure) {
		if (*refcnt < SHREFCNT_MAX) {
			if (*refcnt < SHREFCNT_SECURE_STEP)
				panic();

			*refcnt -= SHREFCNT_SECURE_STEP;
			rc = !*refcnt;
		}
	} else {
		rc = (*refcnt == SHREFCNT_NONSECURE_FLAG);
		*refcnt &= ~SHREFCNT_NONSECURE_FLAG;
	}

	return rc;
}

static inline int incr_refcnt(unsigned int *refcnt)
{
	return incr_shrefcnt(refcnt, true);
}

static inline int decr_refcnt(unsigned int *refcnt)
{
	return decr_shrefcnt(refcnt, true);
}

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
