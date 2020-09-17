/*
 * Copyright (c) 2019-2020, Linaro Limited
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <fwk_macros.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_reset_domain.h>
#include <mod_scmi_reset_domain.h>
#include <mod_stm32_reset.h>
#include <scmi_agents.h>
#include <util.h>

/*
 * Exported API in DT bindings
 * Macro RESET_LIST defines the several SCMI/fwk tables used at module
 * binding to describe and register SCMI reset domains and related shim
 * to backend platform driver.
 */
#define RESET_LIST \
	RESET_CELL(RESET_DEV_IDX_SPI6, SPI6_R, "spi6"), \
	RESET_CELL(RESET_DEV_IDX_I2C4, I2C4_R, "i2c4"), \
	RESET_CELL(RESET_DEV_IDX_I2C6, I2C6_R, "i2c6"), \
	RESET_CELL(RESET_DEV_IDX_USART1, USART1_R, "usart1"), \
	RESET_CELL(RESET_DEV_IDX_STGEN, STGEN_R, "stgen"), \
	RESET_CELL(RESET_DEV_IDX_GPIOZ, GPIOZ_R, "gpioz"), \
	RESET_CELL(RESET_DEV_IDX_CRYP1, CRYP1_R, "cryp1"), \
	RESET_CELL(RESET_DEV_IDX_HASH1, HASH1_R, "hash1"), \
	RESET_CELL(RESET_DEV_IDX_RNG1, RNG1_R, "rng1"), \
	RESET_CELL(RESET_DEV_IDX_MDMA, MDMA_R, "mdma"), \
	RESET_CELL(RESET_DEV_IDX_MCU, MCU_R, "mcu"), \
	/* End of RESET_LIST */

/*
 * The static way for storing the elements and module configuration data
 */

/*
 * Reset domains from stm32 platform are identified with a platform interger
 * ID value.
 */
#define STM32_RESET(_idx, _id)	[(_idx)] = {	\
                    .reset_id = (_id),		\
		}

/* Module Reset gets stm32_reset (FWK_MODULE_IDX_STM32_RESET) elements */
#define RESET(_idx, _id)	[(_idx)] = {				\
		.driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_STM32_RESET, \
						 (_idx) /* same index */), \
		.driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_RESET, \
						 0 /* API type */), \
		.modes = MOD_RESET_DOMAIN_AUTO_RESET | \
			 MOD_RESET_DOMAIN_MODE_EXPLICIT_ASSERT | \
			 MOD_RESET_DOMAIN_MODE_EXPLICIT_DEASSERT, \
		.capabilities = 0, /* No notif, no async */ \
	}

/*
 * SCMI reset binds to reset module (FWK_MODULE_IDX_RESET).
 * Export all reset domains with same permissions: only attribs & reset
 */
#define SCMI_RESET(_idx, _id)	[(_idx)] =  {				\
		.element_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_RESET_DOMAIN, \
						  (_idx) /* same index */), \
	}

/*
 * Framwork expects 1 element per module per reset domain:
 * - stm32_reset elements data configuration provided by stm32_reset_cfg[]
 * - reset elements data configuration provided by reset_cfg[]
 * - scmi_reset elements data configuration provided by scmi_reset_cfg[]
 */
#define STM32_RESET_ELT(_idx, _id, _name)	[_idx] = {	\
			.name = #_id,				\
			.data = &stm32_reset_cfg[(_idx)],	\
		}

#define RESET_ELT(_idx, _id, _name)		[(_idx)] = {	\
			.name = _name,				\
			.data = &reset_cfg[(_idx)],		\
		}

#define SCMI_RESET_ELT(_idx, _id, _name)	[(_idx)] = {	\
			.name = #_id,				\
			.data = &scmi_reset_cfg[(_idx)],	\
		}

/*
 * Elements for reset module: use a function to provide data:
 * FWK_ID_NONE type mandates being initialized at runtime.
 */
#undef RESET_CELL
#define RESET_CELL(a, b, c)	RESET(a, b)
static struct mod_reset_domain_dev_config reset_cfg[] = {
	RESET_LIST
};

#undef RESET_CELL
#define RESET_CELL(a, b, c)	RESET_ELT(a, b, c)
static const struct fwk_element reset_elts[] = {
	RESET_LIST
	{ } /* Terminal tag */
};

static const struct fwk_element *reset_config_desc_table(fwk_id_t module_id)
{
	return reset_elts;
}

const struct fwk_module_config config_reset_domain = {
    .elements = FWK_MODULE_DYNAMIC_ELEMENTS(reset_config_desc_table),
};

/*
 * Elements for stm32_reset module: define elements from data table
 */
#undef RESET_CELL
#define RESET_CELL(a, b, c)	STM32_RESET(a, b)
static const struct mod_stm32_reset_dev_config stm32_reset_cfg[] = {
	RESET_LIST
};

#undef RESET_CELL
#define RESET_CELL(a, b, c)	STM32_RESET_ELT(a, b, c)
static const struct fwk_element stm32_reset_elt[] = {
	RESET_LIST
	{ } /* Terminal tag */
};

static const struct fwk_element *stm32_reset_desc_table(fwk_id_t module_id)
{
	return stm32_reset_elt;
}

const struct fwk_module_config config_stm32_reset = {
    .elements = FWK_MODULE_DYNAMIC_ELEMENTS(stm32_reset_desc_table),
};

/*
 * Elements for SCMI Reset Domain module: define scmi_agent OSPM
 */
#undef RESET_CELL
#define RESET_CELL(a, b, c)	SCMI_RESET(a, b)
static const struct mod_scmi_reset_domain_device scmi_reset_cfg[] = {
	RESET_LIST
};

#undef RESET_CELL
#define RESET_CELL(a, b, c)	SCMI_RESET_ELT(a, b, c)
static const struct fwk_element scmi_reset_elt[] = {
	RESET_LIST
	{ } /* Terminal tag */
};

static const struct mod_scmi_reset_domain_agent reset_agents[SCMI_AGENT_ID_COUNT] = {
    [SCMI_AGENT_ID_NSEC0] = {
        .device_table = scmi_reset_cfg,
        .agent_domain_count = FWK_ARRAY_SIZE(scmi_reset_cfg),
    },
};

static const struct mod_scmi_reset_domain_config scmi_reset_agents = {
        .agent_table = reset_agents,
        .agent_count = FWK_ARRAY_SIZE(reset_agents),
};

const struct fwk_module_config config_scmi_reset_domain = {
	/* Register module elements straight from data table */
	.data = (void *)&scmi_reset_agents,
};
