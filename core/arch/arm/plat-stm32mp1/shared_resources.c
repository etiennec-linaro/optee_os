// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <drivers/stm32mp1_rcc.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stm32_util.h>
#include <stdbool.h>
#include <string.h>

static bool registering_locked;

/*
 * Shared peripherals and resources.
 * Defines resource that may be non secure, secure or shared.
 * May be a device, a bus, a clock, a memory.
 *
 * State default to PERIPH_UNREGISTERED resource is not explicitly
 * set here.
 *
 * Resource driver not built (upon CFG_xxx), the resource defaults
 * to non secure ownership.
 *
 * Each IO of the GPIOZ IO can be secure or non secure.
 * When the GPIO driver is enabled, the GPIOZ bank is fully non secure
 * only if each IO is non secure and the GPIOZ bank is shared if it
 * includes secure and non secure IOs.
 *
 * BKPSRAM is assumed shared.
 * DDR control (DDRC and DDRPHY) is secure.
 * Inits will define the resource state according the device tree
 * and the driver initialization sequences.
 *
 * The platform initialization uses these information to set the ETZPC
 * configuration. Non secure services (as clocks or regulator accesses)
 * rely on these information to drive the related service execution.
 */
#define SHRES_NON_SECURE		3
#define SHRES_SHARED			2
#define SHRES_SECURE			1
#define SHRES_UNREGISTERED		0

static uint8_t shres_state[STM32MP1_SHRES_COUNT] = {
#if !defined(CFG_STM32_IWDG)
	[STM32MP1_SHRES_IWDG1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_UART)
	[STM32MP1_SHRES_USART1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_SPI)
	[STM32MP1_SHRES_SPI6] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_I2C)
	[STM32MP1_SHRES_I2C4] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_I2C6] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_GPIO)
	[STM32MP1_SHRES_GPIOZ(0)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(1)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(2)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(3)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(4)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(5)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(6)] = SHRES_NON_SECURE,
	[STM32MP1_SHRES_GPIOZ(7)] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_RNG)
	[STM32MP1_SHRES_RNG1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_HASH)
	[STM32MP1_SHRES_HASH1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_CRYP)
	[STM32MP1_SHRES_CRYP1] = SHRES_NON_SECURE,
#endif
#if !defined(CFG_STM32_RTC)
	[STM32MP1_SHRES_RTC] = SHRES_NON_SECURE,
#endif
};

#if CFG_TEE_CORE_LOG_LEVEL > 0
static const char *shres2str_id_tbl[STM32MP1_SHRES_COUNT] __maybe_unused = {
	[STM32MP1_SHRES_GPIOZ(0)] = "GPIOZ0",
	[STM32MP1_SHRES_GPIOZ(1)] = "GPIOZ1",
	[STM32MP1_SHRES_GPIOZ(2)] = "GPIOZ2",
	[STM32MP1_SHRES_GPIOZ(3)] = "GPIOZ3",
	[STM32MP1_SHRES_GPIOZ(4)] = "GPIOZ4",
	[STM32MP1_SHRES_GPIOZ(5)] = "GPIOZ5",
	[STM32MP1_SHRES_GPIOZ(6)] = "GPIOZ6",
	[STM32MP1_SHRES_GPIOZ(7)] = "GPIOZ7",
	[STM32MP1_SHRES_IWDG1] = "IWDG1",
	[STM32MP1_SHRES_USART1] = "USART1",
	[STM32MP1_SHRES_SPI6] = "SPI6",
	[STM32MP1_SHRES_I2C4] = "I2C4",
	[STM32MP1_SHRES_RNG1] = "RNG1",
	[STM32MP1_SHRES_HASH1] = "HASH1",
	[STM32MP1_SHRES_CRYP1] = "CRYP1",
	[STM32MP1_SHRES_I2C6] = "I2C6",
	[STM32MP1_SHRES_RTC] = "RTC",
	[STM32MP1_SHRES_HSI] = "HSI",
	[STM32MP1_SHRES_LSI] = "LSI",
	[STM32MP1_SHRES_HSE] = "HSE",
	[STM32MP1_SHRES_LSE] = "LSE",
	[STM32MP1_SHRES_CSI] = "CSI",
	[STM32MP1_SHRES_PLL1] = "PLL1",
	[STM32MP1_SHRES_PLL1_P] = "PLL1_P",
	[STM32MP1_SHRES_PLL1_Q] = "PLL1_Q",
	[STM32MP1_SHRES_PLL1_R] = "PLL1_R",
	[STM32MP1_SHRES_PLL2] = "PLL2",
	[STM32MP1_SHRES_PLL2_P] = "PLL2_P",
	[STM32MP1_SHRES_PLL2_Q] = "PLL2_Q",
	[STM32MP1_SHRES_PLL2_R] = "PLL2_R",
	[STM32MP1_SHRES_PLL3] = "PLL3",
	[STM32MP1_SHRES_PLL3_P] = "PLL3_P",
	[STM32MP1_SHRES_PLL3_Q] = "PLL3_Q",
	[STM32MP1_SHRES_PLL3_R] = "PLL3_R",
	[STM32MP1_SHRES_PLL4] = "PLL4",
	[STM32MP1_SHRES_PLL4_P] = "PLL4_P",
	[STM32MP1_SHRES_PLL4_Q] = "PLL4_Q",
	[STM32MP1_SHRES_PLL4_R] = "PLL4_R",
};

static __maybe_unused const char *shres2str_id(unsigned int id)
{
	return shres2str_id_tbl[id];
}

static const char *shres2str_state_tbl[4] __maybe_unused = {
	[SHRES_SHARED] = "shared",
	[SHRES_NON_SECURE] = "non secure",
	[SHRES_SECURE] = "secure",
	[SHRES_UNREGISTERED] = "unregistered",
};

static __maybe_unused const char *shres2str_state(unsigned int id)
{
	return shres2str_state_tbl[id];
}
#else
static __maybe_unused const char *shres2str_id(unsigned int __unused id)
{
	return NULL;
}

static __maybe_unused const char *shres2str_state(unsigned int __unused id)
{
	return NULL;
}
#endif


/* GPIOZ bank may have several number of pins */
static unsigned int get_gpioz_nbpin_unpg(void)
{
	return STM32MP1_GPIOZ_PIN_MAX_COUNT;
}

static unsigned int get_gpioz_nbpin(void)
{
	return get_gpioz_nbpin_unpg();
}

static bool shareable_resource(unsigned int id)
{
	switch (id) {
	default:
		/* Currently no shareable resource */
		return false;
	}
}

static void register_periph(unsigned int id, unsigned int state)
{
	assert(id < STM32MP1_SHRES_COUNT &&
	       state > SHRES_UNREGISTERED &&
	       state <= SHRES_NON_SECURE);

	if (registering_locked)
		panic();

	if ((state == SHRES_SHARED && !shareable_resource(id)) ||
	    ((shres_state[id] != SHRES_UNREGISTERED) &&
	     (shres_state[id] != state))) {
		DMSG("Cannot change %s from %s to %s",
		     shres2str_id(id),
		     shres2str_state(shres_state[id]),
		     shres2str_state(state));
		panic();
	}

	if (shres_state[id] == SHRES_UNREGISTERED)
		DMSG("Register %s as %s",
		     shres2str_id(id), shres2str_state(state));

	switch (id) {
	case STM32MP1_SHRES_GPIOZ(0):
	case STM32MP1_SHRES_GPIOZ(1):
	case STM32MP1_SHRES_GPIOZ(2):
	case STM32MP1_SHRES_GPIOZ(3):
	case STM32MP1_SHRES_GPIOZ(4):
	case STM32MP1_SHRES_GPIOZ(5):
	case STM32MP1_SHRES_GPIOZ(6):
	case STM32MP1_SHRES_GPIOZ(7):
		if ((id - STM32MP1_SHRES_GPIOZ(0)) >= get_gpioz_nbpin()) {
			EMSG("gpio %u >= %u",
			     id -  STM32MP1_SHRES_GPIOZ(0), get_gpioz_nbpin());
			panic();
		}
		break;
	default:
		break;
	}

	shres_state[id] = (uint8_t)state;
}

/* Register resource by ID */
void stm32mp_register_secure_periph(unsigned int id)
{
	register_periph(id, SHRES_SECURE);
}

void stm32mp_register_shared_periph(unsigned int id)
{
	register_periph(id, SHRES_SHARED);
}

void stm32mp_register_non_secure_periph(unsigned int id)
{
	register_periph(id, SHRES_NON_SECURE);
}

/* Register resource by IO memory base address */
static void register_periph_iomem(uintptr_t base, unsigned int state)
{
	unsigned int id;

	switch (base) {
	case IWDG1_BASE:
		id = STM32MP1_SHRES_IWDG1;
		break;
	case USART1_BASE:
		id = STM32MP1_SHRES_USART1;
		break;
	case SPI6_BASE:
		id = STM32MP1_SHRES_SPI6;
		break;
	case I2C4_BASE:
		id = STM32MP1_SHRES_I2C4;
		break;
	case I2C6_BASE:
		id = STM32MP1_SHRES_I2C6;
		break;
	case RTC_BASE:
		id = STM32MP1_SHRES_RTC;
		break;
	case RNG1_BASE:
		id = STM32MP1_SHRES_RNG1;
		break;
	case CRYP1_BASE:
		id = STM32MP1_SHRES_CRYP1;
		break;
	case HASH1_BASE:
		id = STM32MP1_SHRES_HASH1;
		break;

#ifdef CFG_WITH_NSEC_GPIOS
	case GPIOA_BASE:
	case GPIOB_BASE:
	case GPIOC_BASE:
	case GPIOD_BASE:
	case GPIOE_BASE:
	case GPIOF_BASE:
	case GPIOG_BASE:
	case GPIOH_BASE:
	case GPIOI_BASE:
	case GPIOJ_BASE:
	case GPIOK_BASE:
	/* FALLTHROUGH */
#endif
#ifdef CFG_WITH_NSEC_UARTS
	case USART2_BASE:
	case USART3_BASE:
	case UART4_BASE:
	case UART5_BASE:
	case USART6_BASE:
	case UART7_BASE:
	case UART8_BASE:
	/* FALLTHROUGH */
#endif
	case IWDG2_BASE:
		/* Allow drivers to register some non secure resources */
		DMSG("IO for non secure resource 0x%x", base);
		if (state != SHRES_NON_SECURE)
			panic();

		return;

	default:
		panic();
		break;
	}

	register_periph(id, state);
}

void stm32mp_register_secure_periph_iomem(uintptr_t base)
{
	register_periph_iomem(base, SHRES_SECURE);
}

void stm32mp_register_non_secure_periph_iomem(uintptr_t base)
{
	register_periph_iomem(base, SHRES_NON_SECURE);
}

/* Register GPIO resource */
void stm32mp_register_secure_gpio(unsigned int bank, unsigned int pin)
{
	switch (bank) {
	case GPIO_BANK_Z:
		register_periph(STM32MP1_SHRES_GPIOZ(pin), SHRES_SECURE);
		break;
	default:
		EMSG("GPIO bank %u cannot be secured", bank);
		panic();
	}
}

void stm32mp_register_non_secure_gpio(unsigned int bank, unsigned int pin)
{
	switch (bank) {
	case GPIO_BANK_Z:
		register_periph(STM32MP1_SHRES_GPIOZ(pin), SHRES_NON_SECURE);
		break;
	default:
		break;
	}
}

/* Get resource state: these accesses lock the registering support */
static void lock_registering(void)
{
	registering_locked = true;
}

bool stm32mp_periph_is_shared(unsigned long id)
{
	lock_registering();

	return shres_state[id] == SHRES_SHARED;
}

bool stm32mp_periph_is_non_secure(unsigned long id)
{
	lock_registering();

	return shres_state[id] == SHRES_NON_SECURE;
}

bool stm32mp_periph_is_secure(unsigned long id)
{
	lock_registering();

	return shres_state[id] == SHRES_SECURE;
}

bool stm32mp_periph_is_unregistered(unsigned long id)
{
	lock_registering();

	return shres_state[id] == SHRES_UNREGISTERED;
}

bool stm32mp_gpio_bank_is_shared(unsigned int bank)
{
	unsigned int non_secure = 0;
	unsigned int pin;

	lock_registering();

	if (bank != GPIO_BANK_Z)
		return false;

	for (pin = 0; pin < get_gpioz_nbpin_unpg(); pin++)
		if (stm32mp_periph_is_non_secure(STM32MP1_SHRES_GPIOZ(pin)) ||
		    stm32mp_periph_is_unregistered(STM32MP1_SHRES_GPIOZ(pin)))
			non_secure++;

	return (non_secure > 0) && (non_secure < get_gpioz_nbpin_unpg());
}

bool stm32mp_gpio_bank_is_non_secure(unsigned int bank)
{
	unsigned int non_secure = 0;
	unsigned int pin;

	lock_registering();

	if (bank != GPIO_BANK_Z)
		return true;

	for (pin = 0; pin < get_gpioz_nbpin_unpg(); pin++)
		if (stm32mp_periph_is_non_secure(STM32MP1_SHRES_GPIOZ(pin)) ||
		    stm32mp_periph_is_unregistered(STM32MP1_SHRES_GPIOZ(pin)))
			non_secure++;

	return non_secure == get_gpioz_nbpin_unpg();
}

bool stm32mp_gpio_bank_is_secure(unsigned int bank)
{
	unsigned int secure = 0;
	unsigned int pin;

	lock_registering();

	if (bank != GPIO_BANK_Z)
		return false;

	for (pin = 0; pin < get_gpioz_nbpin_unpg(); pin++)
		if (stm32mp_periph_is_secure(STM32MP1_SHRES_GPIOZ(pin)))
			secure++;

	return secure == get_gpioz_nbpin_unpg();
}

static TEE_Result stm32mp1_init_drivers(void)
{
	size_t id;

	registering_locked = true;

	for (id = 0; id < STM32MP1_SHRES_COUNT; id++) {
		uint8_t *state __maybe_unused = &shres_state[id];

#if TRACE_LEVEL == TRACE_INFO
		/* Display only the secure and shared resources */
		if ((*state == SHRES_NON_SECURE) ||
		    ((*state == SHRES_UNREGISTERED)))
			continue;
#endif

		IMSG("stm32mp %-8s (%2u): %-14s",
		     shres2str_id(id), id, shres2str_state(*state));
	}

	return TEE_SUCCESS;
}
driver_init_late(stm32mp1_init_drivers);
