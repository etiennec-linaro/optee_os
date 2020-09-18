// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 */

#include <assert.h>
#include <dt-bindings/regulator/st,stm32mp15-regulator.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_voltage_domain.h>
#include <mod_scmi_voltage_domain.h>
#include <mod_stm32_pmic_regu.h>
#include <scmi_agents.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

/*
 * Exported API in DT bindings
 * Macro VOLTD_LIST defines the several SCMI/fwk tables used at module
 * binding to describe and register SCMI voltage domaines and related
 * shim to backend platform driver.
  */
#define VOLTD_LIST \
	VOLTD_CELL(VOLTD_SCMI2_BUCK1, "buck1", "vddcore"), \
	VOLTD_CELL(VOLTD_SCMI2_BUCK2, "buck2", "vdd_ddr"), \
	VOLTD_CELL(VOLTD_SCMI2_BUCK3, "buck3", "vdd"), \
	VOLTD_CELL(VOLTD_SCMI2_BUCK4, "buck4", "v3v3"), \
	VOLTD_CELL(VOLTD_SCMI2_LDO1, "ldo1", "v1v8_audio"), \
	VOLTD_CELL(VOLTD_SCMI2_LDO2, "ldo2", "v3v3_hdmi"), \
	VOLTD_CELL(VOLTD_SCMI2_LDO3, "ldo3", "vtt_ddr"), \
	VOLTD_CELL(VOLTD_SCMI2_LDO4, "ldo4", "vdd_usb"), \
	VOLTD_CELL(VOLTD_SCMI2_LDO5, "ldo5", "vdda"), \
	VOLTD_CELL(VOLTD_SCMI2_LDO6, "ldo6", "v1v2_hdmi"), \
	VOLTD_CELL(VOLTD_SCMI2_VREFDDR, "vref_ddr", "vref_ddr"), \
	VOLTD_CELL(VOLTD_SCMI2_BOOTST, "boost", "bst_out"), \
	VOLTD_CELL(VOLTD_SCMI2_PWR_SW1, "pwr_sw1", "vbus_otg"), \
	VOLTD_CELL(VOLTD_SCMI2_PWR_SW2, "pwr_sw2", "vbus_sw"), \
	/* End of VOLTD_LIST */

/*
 * The static way for storing the elements and module configuration data
 */

/* Regulator ID (enum pwr_regulator) in stm32mp PWR regulator driver */
#define STM32_VOLTD(_idx, _id)		[(_idx)] = {			\
			.name = (_id),					\
			.internal_name = (_id),					\
		}

/* Module voltd gets stm32_voltd (FWK_MODULE_IDX_STM32_VOLTD) elements */
#define VOLTD(_idx, _id)		[(_idx)] = {			\
		.driver_id = FWK_ID_ELEMENT_INIT(			\
					FWK_MODULE_IDX_STM32_PMIC_REGU,	\
					(_idx) /* same index */),	\
		.api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_PMIC_REGU,\
					  0 /* API type */),		\
	}

/*
 * SCMI voltd binds to voltd module (FWK_MODULE_IDX_VOLTAGE_DOMAIN).
 * Common permissions for exposed voltds. All have same permissions.
 */
#define SCMI_VOLTD(_idx)			[(_idx)] =  {	\
		.element_id = FWK_ID_ELEMENT_INIT(		\
				FWK_MODULE_IDX_VOLTAGE_DOMAIN,	\
				(_idx) /* same index */),	\
	}

/*
 * Framwork expects 1 element for each voltage domain of each module.
 * - stm32_pwr_regu elements data configuration provided by stm32_voltd_cfg[]
 * - voltage domain elements data configuration provided by voltd_cfg[]
 * - SCMI voltage domain elements data configuration provided by
 *   stpmic1_regu_cfg_scmi_voltd_elts[]
 */
#define STM32_VOLTD_ELT(_idx, _id, _name)	[(_idx)] = {	\
			.name = _name,				\
			.data = &stm32_voltd_cfg[(_idx)],	\
		}

#define VOLTD_ELT(_idx, _id, _name)		[(_idx)] = {	\
			.name = _name,				\
			.data = &voltd_cfg[(_idx)],		\
		}

/*
 * Elements for voltage domain module: use a function to provide data:
 * FWK_ID_NONE type mandates being initialized at runtime.
 */
#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	VOLTD((a), (b))
static struct mod_voltd_dev_config voltd_cfg[] = {
	VOLTD_LIST
};

#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	VOLTD_ELT((a), (b), (c))
/* Exported to config_vold.c */
const struct fwk_element stpmic1_regu_cfg_voltd_elts[] = {
	VOLTD_LIST
	{ } /* Terminal tag */
};

/*
 * Elements for stm32_voltd module: define elements from data table
 */
#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	STM32_VOLTD((a), (b))
static struct mod_stm32_pmic_regu_dev_config stm32_voltd_cfg[] = {
	VOLTD_LIST
};

#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	STM32_VOLTD_ELT((a), (b), (c))
static const struct fwk_element stm32_voltd_elt[] = {
	VOLTD_LIST
	{ } /* Terminal tag */
};

const struct fwk_module_config config_stm32_pmic_regu = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(stm32_voltd_elt),
};

/*
 * Elements for SCMI Voltage Domain module
 */
#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	SCMI_VOLTD(a)
/* Exported to config_vold.c */
struct mod_scmi_voltd_device stpmic1_regu_cfg_scmi_voltd[] = {
	VOLTD_LIST
};

static_assert(FWK_ARRAY_SIZE(stpmic1_regu_cfg_scmi_voltd) ==
	      VOLTD_DEV_IDX_STPMIC1_REGU_COUNT,
	      "SCMI voltage domain config mismatch");
