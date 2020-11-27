// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/stm32mp1_pwr.h>
#include <dt-bindings/regulator/st,stm32mp15-regulator.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_voltage_domain.h>
#include <mod_scmi_voltage_domain.h>
#include <mod_stm32_pmic_regu.h>
#include <mod_stm32_pwr_regu.h>
#include <scmi_agents.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

/*
 * stm32_pwr_cfg - Configuration data for PWR regulators exposed thru SCMI
 *
 * These configation data are referenced in the fwk config data of
 * fwk modules VOLTAGE_DOMAIN and STM32_PMIC_REGU.
 */
static const struct mod_stm32_pwr_regu_dev_config stm32_pwr_cfg[] = {
	[VOLTD_SCMI0_REG11] = { .pwr_id = PWR_REG11, .regu_name = "reg11" },
	[VOLTD_SCMI0_REG18] = { .pwr_id = PWR_REG18, .regu_name = "reg18" },
	[VOLTD_SCMI0_USB33] = { .pwr_id = PWR_USB33, .regu_name = "usb33" },
};

/*
 * stm32_pmic_cfg - Configuration data for PMIC regulators exposed thru SCMI
 *
 * These configation data are referenced in the fwk config data of
 * fwk modules VOLTAGE_DOMAIN and STM32_PMIC_REGU.
 * @regu_name is used both in PMIC regulator driver API and as SCMI
 * voltage domain name.
 */
static const struct mod_stm32_pmic_regu_dev_config __maybe_unused stm32_pmic_cfg[] = {
	[VOLTD_SCMI2_BUCK1] = { .regu_name = "buck1" },
	[VOLTD_SCMI2_BUCK2] = { .regu_name = "buck2" },
	[VOLTD_SCMI2_BUCK3] = { .regu_name = "buck3" },
	[VOLTD_SCMI2_BUCK4] = { .regu_name = "buck4" },
	[VOLTD_SCMI2_LDO1]  = { .regu_name = "ldo1" },
	[VOLTD_SCMI2_LDO2]  = { .regu_name = "ldo2" },
	[VOLTD_SCMI2_LDO3]  = { .regu_name = "ldo3" },
	[VOLTD_SCMI2_LDO4]  = { .regu_name = "ldo4" },
	[VOLTD_SCMI2_LDO5]  = { .regu_name = "ldo5" },
	[VOLTD_SCMI2_LDO6]  = { .regu_name = "ldo6" },
	[VOLTD_SCMI2_VREFDDR] = { .regu_name = "vref_ddr" },
	[VOLTD_SCMI2_BOOST]   = { .regu_name = "boost" },
	[VOLTD_SCMI2_PWR_SW1] = { .regu_name = "pwr_sw1" },
	[VOLTD_SCMI2_PWR_SW2] = { .regu_name = "pwr_sw2" },
};

/*
 * Indices of voltage domain module elements exposed through a SCMI agent.
 */
enum voltd_elt_idx {
	/* Voltage domains exposed to agent SCMI0 */
	VOLTD_IDX_SCMI0_REG11,
	VOLTD_IDX_SCMI0_REG18,
	VOLTD_IDX_SCMI0_USB33,
	/* Voltage domains exposed to agent SCMI2 */
	VOLTD_IDX_SCMI2_BUCK1,
	VOLTD_IDX_SCMI2_BUCK2,
	VOLTD_IDX_SCMI2_BUCK3,
	VOLTD_IDX_SCMI2_BUCK4,
	VOLTD_IDX_SCMI2_LDO1,
	VOLTD_IDX_SCMI2_LDO2,
	VOLTD_IDX_SCMI2_LDO3,
	VOLTD_IDX_SCMI2_LDO4,
	VOLTD_IDX_SCMI2_LDO5,
	VOLTD_IDX_SCMI2_LDO6,
	VOLTD_IDX_SCMI2_VREFDDR,
	VOLTD_IDX_SCMI2_BOOST,
	VOLTD_IDX_SCMI2_PWR_SW1,
	VOLTD_IDX_SCMI2_PWR_SW2,
	VOLTD_IDX_COUNT
};

/*
 * SCMI Voltage Domain driver configuration
 */
#define SCMI_VOLTD_ELT_ID(_idx) { \
		.element_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_VOLTAGE_DOMAIN, (_idx)), \
	}

static struct mod_scmi_voltd_device scmi0_voltd_device[] = {
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI0_REG11),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI0_REG18),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI0_USB33),
};

static struct mod_scmi_voltd_device __maybe_unused scmi2_voltd_device[] = {
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_BUCK1),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_BUCK2),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_BUCK3),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_BUCK4),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_LDO1),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_LDO2),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_LDO3),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_LDO4),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_LDO5),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_LDO6),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_VREFDDR),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_BOOST),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_PWR_SW1),
	SCMI_VOLTD_ELT_ID(VOLTD_IDX_SCMI2_PWR_SW2),
};

static const struct mod_scmi_voltd_agent voltd_agent_table[SCMI_AGENT_ID_COUNT] = {
	[SCMI_AGENT_ID_NSEC0] = {
		.device_table = scmi0_voltd_device,
		.device_count = FWK_ARRAY_SIZE(scmi0_voltd_device),
	},
#ifdef CFG_STPMIC1
	[SCMI_AGENT_ID_NSEC2] = {
		.device_table = scmi2_voltd_device,
		.device_count = FWK_ARRAY_SIZE(scmi2_voltd_device),
	},
#endif
};

/* Exported configuration data for module SCMI_VOLTAGE_DOMAIN */
const struct fwk_module_config config_scmi_voltage_domain = {
	.data = &((struct mod_scmi_voltd_config){
		.agent_table = voltd_agent_table,
		.agent_count = FWK_ARRAY_SIZE(voltd_agent_table),
	}),
};

/*
 * Voltage Domain driver configuration descripbes STM32_PWR_REGU elements
 * and STM32_PMIC_REGU elements.
 */
#define VOLTD_STM32_PWR_DATA(_idx) \
	((struct mod_voltd_dev_config){ \
		.driver_id = \
			FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_STM32_PWR_REGU, \
					    (_idx)), \
		.api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_PWR_REGU, 0), \
	})

#define VOLTD_STM32_PWR_ELT_ID(_idx) \
	{ \
		.name = stm32_pwr_cfg[(_idx)].regu_name, \
		.data = &VOLTD_STM32_PWR_DATA(_idx), \
	}

#define VOLTD_STM32_PMIC_DATA(_idx) \
	((struct mod_voltd_dev_config){ \
		.driver_id = \
			FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_STM32_PMIC_REGU, \
					    (_idx)), \
		.api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_PMIC_REGU, 0), \
	})

#define VOLTD_STM32_PMIC_ELT_ID(_scmi_domain_id) \
	{ \
		.name = stm32_pmic_cfg[(_scmi_domain_id)].regu_name, \
		.data = &VOLTD_STM32_PMIC_DATA(_scmi_domain_id), \
	}

/* Elements names are the voltage domain names exposed by the SCMI service */
static const struct fwk_element voltd_elt[] = {
	[VOLTD_IDX_SCMI0_REG11] = VOLTD_STM32_PWR_ELT_ID(VOLTD_SCMI0_REG11),
	[VOLTD_IDX_SCMI0_REG18] = VOLTD_STM32_PWR_ELT_ID(VOLTD_SCMI0_REG18),
	[VOLTD_IDX_SCMI0_USB33] = VOLTD_STM32_PWR_ELT_ID(VOLTD_SCMI0_USB33),
#ifdef CFG_STPMIC1
	[VOLTD_IDX_SCMI2_BUCK1] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_BUCK1),
	[VOLTD_IDX_SCMI2_BUCK2] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_BUCK2),
	[VOLTD_IDX_SCMI2_BUCK3] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_BUCK3),
	[VOLTD_IDX_SCMI2_BUCK4] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_BUCK4),
	[VOLTD_IDX_SCMI2_LDO1] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_LDO1),
	[VOLTD_IDX_SCMI2_LDO2] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_LDO2),
	[VOLTD_IDX_SCMI2_LDO3] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_LDO3),
	[VOLTD_IDX_SCMI2_LDO4] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_LDO4),
	[VOLTD_IDX_SCMI2_LDO5] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_LDO5),
	[VOLTD_IDX_SCMI2_LDO6] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_LDO6),
	[VOLTD_IDX_SCMI2_VREFDDR] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_VREFDDR),
	[VOLTD_IDX_SCMI2_BOOST]   = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_BOOST),
	[VOLTD_IDX_SCMI2_PWR_SW1] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_PWR_SW1),
	[VOLTD_IDX_SCMI2_PWR_SW2] = VOLTD_STM32_PMIC_ELT_ID(VOLTD_SCMI2_PWR_SW2),
#endif /*CFG_STPMIC1*/
	[VOLTD_IDX_COUNT] = { 0 } /* Termination entry */
};

/* Exported configuration data for module VOLTAGE_DOMAIN */
const struct fwk_module_config config_voltage_domain = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(voltd_elt),
};

/*
 * STM32 PWR driver configuration
 */
#define STM32_PWR_ELT(_scmi_domain_id) \
	[(_scmi_domain_id)] = { \
		.name = stm32_pwr_cfg[(_scmi_domain_id)].regu_name, \
		.data = &stm32_pwr_cfg[(_scmi_domain_id)], \
	}

static const struct fwk_element stm32_pwr_elt[] = {
	STM32_PWR_ELT(VOLTD_SCMI0_REG11),
	STM32_PWR_ELT(VOLTD_SCMI0_REG18),
	STM32_PWR_ELT(VOLTD_SCMI0_USB33),
	{ 0 } /* Termination entry */
};

/* Exported configuration data for module STM32_PWR_REGU */
const struct fwk_module_config config_stm32_pwr_regu = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(stm32_pwr_elt),
};

#ifdef CFG_STPMIC1
/*
 * STM32 PMIC regulator driver configuration
 *
 * FIXME: field @name seems usless, can be set to NULL?
 * Note: @internal_name is theID used by the backend driver
 */
#define STM32_PMIC_ELT(_scmi_domain_id) \
	[(_scmi_domain_id)] = { \
		.name = stm32_pmic_cfg[(_scmi_domain_id)].regu_name, \
		.data = &stm32_pmic_cfg[(_scmi_domain_id)], \
	}

static const struct fwk_element stm32_pmic_elt[] = {
	STM32_PMIC_ELT(VOLTD_SCMI2_BUCK1),
	STM32_PMIC_ELT(VOLTD_SCMI2_BUCK2),
	STM32_PMIC_ELT(VOLTD_SCMI2_BUCK3),
	STM32_PMIC_ELT(VOLTD_SCMI2_BUCK4),
	STM32_PMIC_ELT(VOLTD_SCMI2_LDO1),
	STM32_PMIC_ELT(VOLTD_SCMI2_LDO2),
	STM32_PMIC_ELT(VOLTD_SCMI2_LDO3),
	STM32_PMIC_ELT(VOLTD_SCMI2_LDO4),
	STM32_PMIC_ELT(VOLTD_SCMI2_LDO5),
	STM32_PMIC_ELT(VOLTD_SCMI2_LDO6),
	STM32_PMIC_ELT(VOLTD_SCMI2_VREFDDR),
	STM32_PMIC_ELT(VOLTD_SCMI2_BOOST),
	STM32_PMIC_ELT(VOLTD_SCMI2_PWR_SW1),
	STM32_PMIC_ELT(VOLTD_SCMI2_PWR_SW2),
	{ 0 } /* Termination entry */
};

/* Exported configuration data for module STM32_PMIC_REGU */
const struct fwk_module_config config_stm32_pmic_regu = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(stm32_pmic_elt),
};

static_assert(FWK_ARRAY_SIZE(scmi2_voltd_device) ==
	      FWK_ARRAY_SIZE(stm32_pmic_elt) - 1,
	      "STM32 PMIC regulators and exposed SCMI2 VOLTAGE mismatch");
#endif /*CFG_STPMIC1*/

