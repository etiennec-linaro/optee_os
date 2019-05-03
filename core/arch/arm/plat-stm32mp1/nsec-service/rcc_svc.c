// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <drivers/stm32mp1_rcc.h>
#include <dt-bindings/clock/stm32mp1-clks.h>
#include <inttypes.h>
#include <kernel/panic.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stm32_util.h>
#include <trace.h>

#include "rcc_svc.h"
#include "stm32mp1_smc.h"

#define STD_REG			0
#define SET_REG			1
#define CLR_REG			2

static void shared_clk_request(uint32_t request,
			       uint32_t offset, uint32_t value)
{
	unsigned int id = 0;
	unsigned int bit = 0;
	uint32_t enable_bits = 0;
	int clr_std_set = STD_REG;

	switch (request) {
	case STM32_SIP_REG_WRITE:
	case STM32_SIP_REG_SET:
	case STM32_SIP_REG_CLEAR:
		break;
	default:
		return;
	}

	switch (offset) {
	case RCC_MP_APB5ENSETR:
		clr_std_set = SET_REG;
		/* Non secure backup registers requires RTCAPB clock */
		enable_bits |= RCC_MP_APB5ENSETR_RTCAPBEN;
		break;
	case RCC_MP_APB5ENCLRR:
		clr_std_set = CLR_REG;
		/* Non secure backup registers requires RTCAPB clock */
		enable_bits |= RCC_MP_APB5ENSETR_RTCAPBEN;
		break;
	case RCC_MP_AHB5ENSETR:
		clr_std_set = SET_REG;
		if (stm32mp_gpio_bank_is_shared(GPIO_BANK_Z))
			enable_bits |= RCC_MP_AHB5ENSETR_GPIOZEN;
		break;
	case RCC_MP_AHB5ENCLRR:
		clr_std_set = CLR_REG;
		if (stm32mp_gpio_bank_is_shared(GPIO_BANK_Z))
			enable_bits |= RCC_MP_AHB5ENSETR_GPIOZEN;
		break;
	default:
		return;
	}

	if (clr_std_set != STD_REG && request == STM32_SIP_REG_CLEAR)
		return;

	/*
	 * Parse bit that relate to a functional clock.
	 * Call stm32mp1_clk_enable/disable_non_secure() for that clock
	 * according to request (write/set/clear) and target register
	 * (write or set/clear).
	 */
	for (bit = 0; enable_bits && bit < 32; bit++) {

		if (!(BIT(bit) & enable_bits))
			continue;

		id = stm32mp1_clk_rcc2id(offset, bit);
		if (id == ~0U)
			panic();

		switch (clr_std_set) {
		case SET_REG:
			if (BIT(bit) & value) {
				DMSG("Enable non-secure clock %u", id);
				stm32_nsec_clock_enable(id);
			}
			break;
		case CLR_REG:
			if (BIT(bit) & value) {
				DMSG("Disable non-secure clock %u", id);
				stm32_nsec_clock_disable(id);
			}
			break;
		default:
			/* Standard registers case */
			switch (request) {
			case STM32_SIP_REG_WRITE:
				if (BIT(bit) & value) {
					DMSG("Enable non-secure clock %u", id);
					stm32_nsec_clock_enable(id);
				} else {
					DMSG("Disable non-secure clock %u", id);
					stm32_nsec_clock_disable(id);
				}
				break;
			case STM32_SIP_REG_SET:
				if (BIT(bit) & value) {
					DMSG("Enable non-secure clock %u", id);
					stm32_nsec_clock_enable(id);
				}
				break;
			case STM32_SIP_REG_CLEAR:
				if (BIT(bit) & value) {
					DMSG("Disable non-secure clock %u", id);
					stm32_nsec_clock_disable(id);
				}
				break;
			default:
				return;
			}
			break;
		}

		enable_bits &= ~BIT(bit);
	}
}

static bool offset_is_clear_register(uint32_t offset)
{
	switch (offset) {
	case RCC_OCENCLRR:
	case RCC_MP_SREQCLRR:
	case RCC_APB5RSTCLRR:
	case RCC_AHB5RSTCLRR:
	case RCC_MP_APB5ENCLRR:
	case RCC_MP_AHB5ENCLRR:
	case RCC_MP_APB5LPENCLRR:
	case RCC_MP_AHB5LPENCLRR:
	case RCC_MP_IWDGFZCLRR:
		return true;
	default:
		return false;
	}
}

static void access_allowed_mask(uint32_t request, uint32_t offset,
				uint32_t value, uint32_t allowed_mask)
{
	vaddr_t va = stm32_rcc_base() + offset;

	if (!allowed_mask)
		return;

	switch (request) {
	case STM32_SIP_REG_WRITE:
		if (offset_is_clear_register(offset)) {
			/* CLR registers show SET state, not CLR state */
			io_write32(va, value & allowed_mask);
		} else {
			io_mask32_stm32shregs(va, value, allowed_mask);
		}
		FMSG("wrt 0x%" PRIx32 "=0x%" PRIx32 " => 0x%" PRIx32,
			offset, value, io_read32(va));
		break;

	case STM32_SIP_REG_SET:
		if (offset_is_clear_register(offset)) {
			/* CLR registers show SET state, not CLR state */
			io_write32(va, value & allowed_mask);
		} else {
			io_setbits32_stm32shregs(va, value & allowed_mask);
		}
		FMSG("set 0x%" PRIx32 "=0x%" PRIx32 " => 0x%" PRIx32,
			offset, value, io_read32(va));
		break;

	case STM32_SIP_REG_CLEAR:
		/* Nothing to do on CLR registers */
		if (!offset_is_clear_register(offset))
			io_clrbits32_stm32shregs(va, value & allowed_mask);
		FMSG("clear 0x%" PRIx32 "=0x%" PRIx32 " => 0x%" PRIx32,
			offset, value, io_read32(va));
		break;

	default:
		break;
	}
}

static void raw_allowed_access_request(uint32_t request,
				       uint32_t offset, uint32_t value)
{
	uint32_t allowed_mask = 0;

	/* Use UINT32_MAX if no secure restriction on register access */
	switch (offset) {
	case RCC_OCENSETR:
	case RCC_OCENCLRR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_HSI))
			allowed_mask |= RCC_OCENR_HSION | RCC_OCENR_HSIKERON;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_CSI))
			allowed_mask |= RCC_OCENR_CSION | RCC_OCENR_CSIKERON;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_HSE))
			allowed_mask |= RCC_OCENR_HSEON | RCC_OCENR_HSEKERON |
					RCC_OCENR_HSEBYP | RCC_OCENR_HSECSSON |
					RCC_OCENR_DIGBYP;
		break;

	case RCC_HSICFGR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_HSI))
			allowed_mask = UINT32_MAX;
		break;

	case RCC_CSICFGR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_CSI))
			allowed_mask = UINT32_MAX;
		break;

	case RCC_MP_CIER:
	case RCC_MP_CIFR:
		/* RCC_MP_CIFR_xxxRDYF matches CIER and CIFR bit mapping */
		allowed_mask |= RCC_MP_CIFR_WKUPF | RCC_MP_CIFR_PLL4DYF;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_LSI))
			allowed_mask |= RCC_MP_CIFR_LSIRDYF;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_LSE))
			allowed_mask |= RCC_MP_CIFR_LSERDYF;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_HSI))
			allowed_mask |= RCC_MP_CIFR_HSIRDYF;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_HSE))
			allowed_mask |= RCC_MP_CIFR_HSERDYF;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_CSI))
			allowed_mask |= RCC_MP_CIFR_CSIRDYF;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL1))
			allowed_mask |= RCC_MP_CIFR_PLL1DYF;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL2))
			allowed_mask |= RCC_MP_CIFR_PLL2DYF;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL3))
			allowed_mask |= RCC_MP_CIFR_PLL3DYF;
		break;

	case RCC_PLL1CR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL1_P))
			allowed_mask |= RCC_PLLNCR_DIVPEN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL1_Q))
			allowed_mask |= RCC_PLLNCR_DIVQEN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL1_R))
			allowed_mask |= RCC_PLLNCR_DIVREN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL1))
			allowed_mask |= RCC_PLLNCR_PLLON | RCC_PLLNCR_PLLRDY |
					RCC_PLLNCR_SSCG_CTRL;
		break;

	case RCC_PLL2CR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL2_P))
			allowed_mask |= RCC_PLLNCR_DIVPEN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL2_Q))
			allowed_mask |= RCC_PLLNCR_DIVQEN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL2_R))
			allowed_mask |= RCC_PLLNCR_DIVREN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL2))
			allowed_mask |= RCC_PLLNCR_PLLON | RCC_PLLNCR_PLLRDY |
					RCC_PLLNCR_SSCG_CTRL;
		break;

	case RCC_PLL3CR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL3_P))
			allowed_mask |= RCC_PLLNCR_DIVPEN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL3_Q))
			allowed_mask |= RCC_PLLNCR_DIVQEN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL3_R))
			allowed_mask |= RCC_PLLNCR_DIVREN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_PLL3))
			allowed_mask |= RCC_PLLNCR_PLLON | RCC_PLLNCR_PLLRDY |
					RCC_PLLNCR_SSCG_CTRL;
		break;

	case RCC_MP_BOOTCR:		/* Allowed MPU/MCU reboot cfg */
	case RCC_MP_GCR:		/* Allowed MPU/MCU reboot cfg */
	case RCC_MP_GRSTCSETR:		/* Allowed MCU and system reset */
	case RCC_BR_RSTSCLRR:		/* Allowed system reset status */
	case RCC_MC_RSTSCLRR:		/* Allowed system reset status */
	case RCC_MP_RSTSCLRR:		/* Allowed system reset status */
		allowed_mask = UINT32_MAX;
		break;
	case RCC_APB5RSTSETR:
	case RCC_APB5RSTCLRR:
	case RCC_MP_APB5ENSETR:
	case RCC_MP_APB5ENCLRR:
	case RCC_MP_APB5LPENSETR:
	case RCC_MP_APB5LPENCLRR:
		/*
		 * SPI6/I2C4/I2C6/USART1/RTC/IWDG1 resources may be non secure.
		 * TZPC/TZC/BSEC/STGEN resources are secure only.
		 * Bit mask RCC_MP_APB5ENSETR_xxxEN fits EN, RST and LPEN.
		 */
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_SPI6))
			allowed_mask |= RCC_MP_APB5ENSETR_SPI6EN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_I2C4))
			allowed_mask |= RCC_MP_APB5ENSETR_I2C4EN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_I2C6))
			allowed_mask |= RCC_MP_APB5ENSETR_I2C6EN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_USART1))
			allowed_mask |= RCC_MP_APB5ENSETR_USART1EN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_IWDG1))
			allowed_mask |= RCC_MP_APB5ENSETR_IWDG1APBEN;
		break;
	case RCC_AHB5RSTSETR:
	case RCC_AHB5RSTCLRR:
	case RCC_MP_AHB5ENSETR:
	case RCC_MP_AHB5ENCLRR:
	case RCC_MP_AHB5LPENSETR:
	case RCC_MP_AHB5LPENCLRR:
		/*
		 * RNG1/HASH1/CRYP1/GPIOZ/AXIMC resources are accessible if
		 * related BKPSRAM resources are reserved to secure services.
		 * Bit mask RCC_MP_AHB5ENSETR_xxxEN fits EN, RST and LPEN.
		 */
		if (stm32mp_gpio_bank_is_non_secure(GPIO_BANK_Z))
			allowed_mask |= RCC_MP_AHB5ENSETR_GPIOZEN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_CRYP1))
			allowed_mask |= RCC_MP_AHB5ENSETR_CRYP1EN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_HASH1))
			allowed_mask |= RCC_MP_AHB5ENSETR_HASH1EN;

		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_RNG1))
			allowed_mask |= RCC_MP_AHB5ENSETR_RNG1EN;
		break;
	case RCC_RTCDIVR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_RTC))
			allowed_mask = UINT32_MAX;
		break;
	case RCC_I2C46CKSELR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_I2C4) &&
		    !stm32mp_periph_is_secure(STM32MP1_SHRES_I2C6))
			allowed_mask = UINT32_MAX;
		break;
	case RCC_SPI6CKSELR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_SPI6))
			allowed_mask = UINT32_MAX;
		break;
	case RCC_UART1CKSELR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_USART1))
			allowed_mask = UINT32_MAX;
		break;
	case RCC_RNG1CKSELR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_RNG1))
			allowed_mask = UINT32_MAX;
		break;
	case RCC_MP_IWDGFZSETR:
	case RCC_MP_IWDGFZCLRR:
		if (!stm32mp_periph_is_secure(STM32MP1_SHRES_IWDG1))
			allowed_mask |= RCC_MP_IWDGFZSETR_IWDG1;

		allowed_mask |= RCC_MP_IWDGFZSETR_IWDG2;
		break;
	default:
		return;
	}

	access_allowed_mask(request, offset, value, allowed_mask);
}

uint32_t rcc_scv_handler(uint32_t x1, uint32_t x2, uint32_t x3)
{
	uint32_t request = x1;
	uint32_t offset = x2;
	uint32_t value = x3;

	/*
	 * Argument x2 can be either the register physical address of the
	 * register offset toward RCC_BASE.
	 */
	if (offset & ~RCC_OFFSET_MASK) {
		if ((offset & ~RCC_OFFSET_MASK) != RCC_BASE)
			return STM32_SIP_INVALID_PARAMS;

		offset &= RCC_OFFSET_MASK;
	}

	DMSG_RAW("RCC service: %s 0x%" PRIx32 " at offset 0x%" PRIx32,
		request == STM32_SIP_REG_WRITE ? "write" :
		request == STM32_SIP_REG_SET ? "set" : "clear",
		value, offset);

	/* Some clocks may be managed by some secure services */
	shared_clk_request(request, offset, value);

	/* RCC controls for non secure resource may be accessed straight */
	raw_allowed_access_request(request, offset, value);

	return STM32_SIP_OK;
}
