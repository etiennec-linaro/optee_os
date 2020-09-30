/*
 * Copyright (c) 2019-2020, Linaro Limited
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <dt-bindings/reset/stm32mp1-resets.h>
#include <fwk_macros.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_reset_domain.h>
#include <mod_scmi_reset_domain.h>
#include <mod_stm32_reset.h>
#include <scmi_agents.h>
#include <util.h>

/*
 * Indices of reset domain elements exposed through a SCMI agent.
 * As all exposed SCMI reset domains relate to a single backend dirver
 * these indices are used as indices for fwk elements for modules
 * RESET_DOMAIN and STM32_RESET.
 * As only agent SCMI0 exposes reset domains, it currently happens
 * that the index values are also the domain IDs exposed through SCMI.
 */
enum resetd_elt_idx {
	/* Reset domain exposed to agent SCMI0 */
	RESETD_IDX_SCMI0_SPI6,
	RESETD_IDX_SCMI0_I2C4,
	RESETD_IDX_SCMI0_I2C6,
	RESETD_IDX_SCMI0_USART1,
	RESETD_IDX_SCMI0_STGEN,
	RESETD_IDX_SCMI0_GPIOZ,
	RESETD_IDX_SCMI0_CRYP1,
	RESETD_IDX_SCMI0_HASH1,
	RESETD_IDX_SCMI0_RNG1,
	RESETD_IDX_SCMI0_MDMA,
	RESETD_IDX_SCMI0_MCU,
	RESETD_IDX_COUNT
};

/*
 * stm32_reset_cfg - Common configuration for exposed SCMI reset domains
 *
 * Domain names defined here are used for all RESET_DOMAIN and STM32_RESET
 * fwk elements names.
 */
#define STM32_RESET_CFG(_idx, _rcc_rst_id, _name) \
	[(_idx)] = { \
		.rcc_rst_id = (_rcc_rst_id), \
		.name = (_name), \
	  }

static const struct mod_stm32_reset_dev_config stm32_resetd_cfg[] = {
	STM32_RESET_CFG(RESETD_IDX_SCMI0_SPI6, SPI6_R, "spi6"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_I2C4, I2C4_R, "i2c4"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_I2C6, I2C6_R, "i2c6"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_USART1, USART1_R, "usart1"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_STGEN, STGEN_R, "stgen"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_GPIOZ, GPIOZ_R, "gpioz"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_CRYP1, CRYP1_R, "cryp1"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_HASH1, HASH1_R, "hash1"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_RNG1, RNG1_R, "rng1"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_MDMA, MDMA_R, "mdma"),
	STM32_RESET_CFG(RESETD_IDX_SCMI0_MCU, MCU_R, "mcu"),
};

/*
 * Bindgins between SCMI domain_id value and reset domain module element in fwk
 *
 * scmi0_resetd_device[domain_id] = reference to domains exposed to agent SCMI0
 */
#define SCMI_RESETD_ELT_ID(_idx) { \
		.element_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_RESET_DOMAIN, \
						  (_idx)), \
	}

static const struct mod_scmi_reset_domain_device scmi0_resetd_device[] = {
	[RST_SCMI0_SPI6]   = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_SPI6),
	[RST_SCMI0_I2C4]   = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_I2C4),
	[RST_SCMI0_I2C6]   = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_I2C6),
	[RST_SCMI0_USART1] = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_USART1),
	[RST_SCMI0_STGEN]  = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_STGEN),
	[RST_SCMI0_GPIOZ]  = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_GPIOZ),
	[RST_SCMI0_CRYP1]  = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_CRYP1),
	[RST_SCMI0_HASH1]  = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_HASH1),
	[RST_SCMI0_RNG1]   = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_RNG1),
	[RST_SCMI0_MDMA]   = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_MDMA),
	[RST_SCMI0_MCU]    = SCMI_RESETD_ELT_ID(RESETD_IDX_SCMI0_MCU),
};

/* Agents andreset domains references */
static const struct mod_scmi_reset_domain_agent resetd_agent_table[SCMI_AGENT_ID_COUNT] = {
	[SCMI_AGENT_ID_NSEC0] = {
		.device_table = (void *)scmi0_resetd_device,
		.agent_domain_count = FWK_ARRAY_SIZE(scmi0_resetd_device),
	},
};

/* Exported configuration data for module SCMI_RESET_DOMAIN */
struct fwk_module_config config_scmi_reset_domain = {
	.data = &((struct mod_scmi_reset_domain_config){
		.agent_table = resetd_agent_table,
		.agent_count = FWK_ARRAY_SIZE(resetd_agent_table),
	}),
};

/*
 * Reset controller backend driver configuration
 * STM32_RESET element index is the related RESET_DOMAIN element index.
 */

#define RESETD_DATA(_idx) ((struct mod_reset_domain_dev_config){ \
		.driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_STM32_RESET, \
						 (_idx)), \
		.driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_RESET, 0), \
		.modes = MOD_RESET_DOMAIN_AUTO_RESET | \
			 MOD_RESET_DOMAIN_MODE_EXPLICIT_ASSERT | \
			 MOD_RESET_DOMAIN_MODE_EXPLICIT_DEASSERT, \
		.capabilities = 0, /* No notif, no async */ \
	})

#define RESETD_ELT(_idx) [(_idx)] = { \
		.name = stm32_resetd_cfg[(_idx)].name, \
		.data = &RESETD_DATA((_idx)), \
	}

/* Element names are the reset domain names exposed by the SCMI service */
static const struct fwk_element resetd_elt[] = {
	/* Reset domains exposed to agent SCMI0 */
	RESETD_ELT(RESETD_IDX_SCMI0_SPI6),
	RESETD_ELT(RESETD_IDX_SCMI0_I2C4),
	RESETD_ELT(RESETD_IDX_SCMI0_I2C6),
	RESETD_ELT(RESETD_IDX_SCMI0_USART1),
	RESETD_ELT(RESETD_IDX_SCMI0_STGEN),
	RESETD_ELT(RESETD_IDX_SCMI0_GPIOZ),
	RESETD_ELT(RESETD_IDX_SCMI0_CRYP1),
	RESETD_ELT(RESETD_IDX_SCMI0_HASH1),
	RESETD_ELT(RESETD_IDX_SCMI0_RNG1),
	RESETD_ELT(RESETD_IDX_SCMI0_MDMA),
	RESETD_ELT(RESETD_IDX_SCMI0_MCU),
	/* Termination entry */
	[RESETD_IDX_COUNT] = { 0 }
};

static_assert(FWK_ARRAY_SIZE(resetd_elt) == RESETD_IDX_COUNT + 1,
	      "Invalid range for RESET_DOMAIN and STM32_RESET indices");

/* Exported configuration data for module VOLTAGE_DOMAIN */
const struct fwk_module_config config_reset_domain = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(resetd_elt),
};

/*
 * Configuration for module STM32_RESET
 */
#define STM32_RESET_ELT(_idx) [(_idx)] = { \
		.name = stm32_resetd_cfg[(_idx)].name, \
		.data = &stm32_resetd_cfg[(_idx)], \
	}

static const struct fwk_element stm32_reset_elt[] = {
	/* Reset domains exposed to agent SCMI0 */
	STM32_RESET_ELT(RESETD_IDX_SCMI0_SPI6),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_I2C4),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_I2C6),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_USART1),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_STGEN),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_GPIOZ),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_CRYP1),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_HASH1),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_RNG1),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_MDMA),
	STM32_RESET_ELT(RESETD_IDX_SCMI0_MCU),
	/* Termination entry */
	[RESETD_IDX_COUNT] = { 0 }
};

static_assert(FWK_ARRAY_SIZE(stm32_reset_elt) == RESETD_IDX_COUNT + 1,
	      "Invalid range for RESET_DOMAIN and STM32_RESET indices");

/* Exported configuration data for module STM32_PWR_REGU */
const struct fwk_module_config config_stm32_reset = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(stm32_reset_elt),
};
