// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <assert.h>
#include <dt-bindings/clock/stm32mp1-clks.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_clock.h>
#include <mod_scmi_clock.h>
#include <mod_stm32_clock.h>
#include <scmi_agents.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

/*
 * Indices of clock elements exposed through a SCMI agent.
 * As all exposed SCMI clocks relate to a single backend dirver
 * these indices are used as indices for fwk elements for modules
 * CLOCK and STM32_CLOCK. Note these are not the clock ID values
 * exposed through SCMI.
 */
enum clock_elt_idx {
	/* Clocks exposed to agent SCMI0 */
	CLK_IDX_SCMI0_HSE,
	CLK_IDX_SCMI0_HSI,
	CLK_IDX_SCMI0_CSI,
	CLK_IDX_SCMI0_LSE,
	CLK_IDX_SCMI0_LSI,
	CLK_IDX_SCMI0_PLL2_Q,
	CLK_IDX_SCMI0_PLL2_R,
	CLK_IDX_SCMI0_MPU,
	CLK_IDX_SCMI0_AXI,
	CLK_IDX_SCMI0_BSEC,
	CLK_IDX_SCMI0_CRYP1,
	CLK_IDX_SCMI0_GPIOZ,
	CLK_IDX_SCMI0_HASH1,
	CLK_IDX_SCMI0_I2C4,
	CLK_IDX_SCMI0_I2C6,
	CLK_IDX_SCMI0_IWDG1,
	CLK_IDX_SCMI0_RNG1,
	CLK_IDX_SCMI0_RTC,
	CLK_IDX_SCMI0_RTCAPB,
	CLK_IDX_SCMI0_SPI6,
	CLK_IDX_SCMI0_USART1,
	/* Clocks exposed to agent SCMI1 */
	CLK_IDX_SCMI1_PLL3_Q,
	CLK_IDX_SCMI1_PLL3_R,
	CLK_IDX_SCMI1_MCU,
	/* Count indices */
	CLK_IDX_COUNT
};

/*
 * stm32_clock_cfg - Common configuration for exposed SCMI clocks
 *
 * Clock name defined here is used for all CLOCK and STM32_CLOCK
 * fwk elements names.
 */
#define STM32_CLOCK_CFG(_idx, _rcc_clk_id, _name, _default_enabled) \
	[(_idx)] = { \
		.rcc_clk_id = (_rcc_clk_id), \
		.name = (_name), \
		.default_enabled = (_default_enabled), \
	  }

static const struct mod_stm32_clock_dev_config stm32_clock_cfg[] = {
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_HSE, CK_HSE, "ck_hse", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_HSI, CK_HSI, "ck_hsi", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_CSI, CK_CSI, "ck_csi", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_LSE, CK_LSE, "ck_lse", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_LSI, CK_LSI, "ck_lsi", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_PLL2_Q, PLL2_Q, "pll2_q", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_PLL2_R, PLL2_R, "pll2_r", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_MPU, CK_MCU, "ck_mpu", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_AXI, CK_AXI, "ck_axi", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_BSEC, BSEC, "bsec", false),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_CRYP1, CRYP1, "cryp1", false),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_GPIOZ, GPIOZ, "gpioz", false),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_HASH1, HASH1, "hash1", false),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_I2C4, I2C4_K, "i2c4_k", false),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_I2C6, I2C6_K, "i2c6_k", false),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_IWDG1, IWDG1, "iwdg1", false),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_RNG1, RNG1_K, "rng1_k", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_RTC, RTC, "ck_rtc", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_RTCAPB, RTCAPB, "rtcapb", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_SPI6, SPI6_K, "spi6_k", false),
	STM32_CLOCK_CFG(CLK_IDX_SCMI0_USART1, USART1_K, "usart1_k", false),
	/* Clocks exposed to agent SCMI1 */
	STM32_CLOCK_CFG(CLK_IDX_SCMI1_PLL3_Q, PLL3_Q, "pll3_q", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI1_PLL3_R, PLL3_R, "pll3_r", true),
	STM32_CLOCK_CFG(CLK_IDX_SCMI1_MCU, CK_MCU, "ck_mcu", false),
};

/*
 * Bindgins between SCMI clock_id value and clock module element in fwk
 *
 * scmi0_clock_device[clock_id] = reference to clock exposed to agent SCMI0
 * scmi1_clock_device[clock_id] = reference to clock exposed to agent SCMI1
 */
#define SCMI_CLOCK_ELT_ID(_idx) { \
		.element_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, \
						  (_idx)), \
	}

static struct mod_scmi_clock_device scmi0_clock_device[] = {
	[CK_SCMI0_HSE] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_HSE),
	[CK_SCMI0_HSI] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_HSI),
	[CK_SCMI0_CSI] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_CSI),
	[CK_SCMI0_LSE] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_LSE),
	[CK_SCMI0_LSI] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_LSI),
	[CK_SCMI0_PLL2_Q] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_PLL2_Q),
	[CK_SCMI0_PLL2_R] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_PLL2_R),
	[CK_SCMI0_MPU]    = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_MPU),
	[CK_SCMI0_AXI]    = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_AXI),
	[CK_SCMI0_BSEC]   = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_BSEC),
	[CK_SCMI0_CRYP1]  = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_CRYP1),
	[CK_SCMI0_GPIOZ]  = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_GPIOZ),
	[CK_SCMI0_HASH1]  = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_HASH1),
	[CK_SCMI0_I2C4]   = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_I2C4),
	[CK_SCMI0_I2C6]   = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_I2C6),
	[CK_SCMI0_IWDG1]  = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_IWDG1),
	[CK_SCMI0_RNG1]   = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_RNG1),
	[CK_SCMI0_RTC]    = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_RTC),
	[CK_SCMI0_RTCAPB] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_RTCAPB),
	[CK_SCMI0_SPI6]   = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_SPI6),
	[CK_SCMI0_USART1] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI0_USART1),
};

static struct mod_scmi_clock_device scmi1_clock_device[] = {
	[CK_SCMI1_PLL3_Q] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI1_PLL3_Q),
	[CK_SCMI1_PLL3_R] = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI1_PLL3_R),
	[CK_SCMI1_MCU]    = SCMI_CLOCK_ELT_ID(CLK_IDX_SCMI1_MCU),
};

/* Agents and clocks references */
static const struct mod_scmi_clock_agent clock_agent_table[SCMI_AGENT_ID_COUNT] = {
	[SCMI_AGENT_ID_NSEC0] = {
		.device_table = (void *)scmi0_clock_device,
		.device_count = FWK_ARRAY_SIZE(scmi0_clock_device),
	},
	[SCMI_AGENT_ID_NSEC1] = {
		.device_table = (void *)scmi1_clock_device,
		.device_count = FWK_ARRAY_SIZE(scmi1_clock_device),
	},
};

/* Exported configuration data for module SCMI_CLOCK */
struct fwk_module_config config_scmi_clock = {
	.data = &((struct mod_scmi_clock_config){
		.agent_table = clock_agent_table,
		.agent_count = FWK_ARRAY_SIZE(clock_agent_table),
	}),
};

/*
 * Clock backend driver configuration
 * STM32_CLOCK element index is the related CLOCK element index.
 */

#define CLOCK_DATA(_idx) ((struct mod_clock_dev_config){ \
		.driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_STM32_CLOCK, \
						 (_idx)), \
		.api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_CLOCK, 0), \
	})

#define CLOCK_ELT(_idx) [(_idx)] = { \
		.name = stm32_clock_cfg[(_idx)].name, \
		.data = &CLOCK_DATA((_idx)), \
	}

/* Element names are the clock names exposed by the SCMI service */
static struct fwk_element clock_elt[] = {
	/* Clocks exposed to agent SCMI0 */
	CLOCK_ELT(CLK_IDX_SCMI0_HSE),
	CLOCK_ELT(CLK_IDX_SCMI0_HSI),
	CLOCK_ELT(CLK_IDX_SCMI0_CSI),
	CLOCK_ELT(CLK_IDX_SCMI0_LSE),
	CLOCK_ELT(CLK_IDX_SCMI0_LSI),
	CLOCK_ELT(CLK_IDX_SCMI0_PLL2_Q),
	CLOCK_ELT(CLK_IDX_SCMI0_PLL2_R),
	CLOCK_ELT(CLK_IDX_SCMI0_MPU),
	CLOCK_ELT(CLK_IDX_SCMI0_AXI),
	CLOCK_ELT(CLK_IDX_SCMI0_BSEC),
	CLOCK_ELT(CLK_IDX_SCMI0_CRYP1),
	CLOCK_ELT(CLK_IDX_SCMI0_GPIOZ),
	CLOCK_ELT(CLK_IDX_SCMI0_HASH1),
	CLOCK_ELT(CLK_IDX_SCMI0_I2C4),
	CLOCK_ELT(CLK_IDX_SCMI0_I2C6),
	CLOCK_ELT(CLK_IDX_SCMI0_IWDG1),
	CLOCK_ELT(CLK_IDX_SCMI0_RNG1),
	CLOCK_ELT(CLK_IDX_SCMI0_RTC),
	CLOCK_ELT(CLK_IDX_SCMI0_RTCAPB),
	CLOCK_ELT(CLK_IDX_SCMI0_SPI6),
	CLOCK_ELT(CLK_IDX_SCMI0_USART1),
	/* Clocks exposed to agent SCMI1 */
	CLOCK_ELT(CLK_IDX_SCMI1_PLL3_Q),
	CLOCK_ELT(CLK_IDX_SCMI1_PLL3_R),
	CLOCK_ELT(CLK_IDX_SCMI1_MCU),
	/* Termination entry */
	[CLK_IDX_COUNT] = { 0 }
};

static_assert(FWK_ARRAY_SIZE(clock_elt) == CLK_IDX_COUNT + 1,
	      "Invalid range for CLOCK and STM32_CLOCK indices");

/* Exported configuration data for module VOLTAGE_DOMAIN */
const struct fwk_module_config config_clock = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(clock_elt),
};

/*
 * Configuration for module STM32_CLOCK
 */
#define STM32_CLOCK_ELT(_idx) [(_idx)] = { \
		.name = stm32_clock_cfg[(_idx)].name, \
		.data = &stm32_clock_cfg[(_idx)], \
	}

static const struct fwk_element stm32_clock_elt[] = {
	/* Clocks exposed to agent SCMI0 */
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_HSE),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_HSI),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_CSI),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_LSE),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_LSI),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_PLL2_Q),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_PLL2_R),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_MPU),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_AXI),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_BSEC),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_CRYP1),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_GPIOZ),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_HASH1),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_I2C4),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_I2C6),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_IWDG1),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_RNG1),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_RTC),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_RTCAPB),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_SPI6),
	STM32_CLOCK_ELT(CLK_IDX_SCMI0_USART1),
	/* Clocks exposed to agent SCMI1 */
	STM32_CLOCK_ELT(CLK_IDX_SCMI1_PLL3_Q),
	STM32_CLOCK_ELT(CLK_IDX_SCMI1_PLL3_R),
	STM32_CLOCK_ELT(CLK_IDX_SCMI1_MCU),
	/* Termination entry */
	[CLK_IDX_COUNT] = { 0 }
};

static_assert(FWK_ARRAY_SIZE(stm32_clock_elt) == CLK_IDX_COUNT + 1,
	      "Invalid range for CLOCK and STM32_CLOCK indices");

/* Exported configuration data for module STM32_PWR_REGU */
const struct fwk_module_config config_stm32_clock = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(stm32_clock_elt),
};
