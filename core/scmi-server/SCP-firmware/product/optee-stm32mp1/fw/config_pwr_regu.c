// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 */

#include <assert.h>
#include <drivers/stm32mp1_pwr.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_voltage_domain.h>
#include <mod_scmi_voltage_domain.h>
#include <mod_stm32_pwr_regu.h>
#include <scmi_agents.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

/*
 * Exported API in DT bindings
 * Macro VOLTD_LIST defines the several SCMI/fwk tables used at module
 * binding to describe and register SCMI voltds and related shim to
 * backend platform driver.
 *
 * VOLTD_SCMI0_REG11
 */
#define VOLTD_LIST \
	VOLTD_CELL(VOLTD_SCMI0_REG11, PWR_REG11, "reg11"), \
	VOLTD_CELL(VOLTD_SCMI0_REG18, PWR_REG18, "reg18"), \
	VOLTD_CELL(VOLTD_SCMI0_USB33, PWR_USB33, "usb33"), \
	/* End of VOLTD_LIST */

/*
 * The static way for storing the elements and module configuration data
 */

/* Regulator ID (enum pwr_regulator) in stm32mp PWR regulator driver */
#define STM32_VOLTD(_idx, _id)		[(_idx)] = {			\
			.pwr_id = (_id),				\
		}

/* Module voltd gets stm32_voltd (FWK_MODULE_IDX_STM32_VOLTD) elements */
#define VOLTD(_idx, _id)		[(_idx)] = {			\
		.driver_id = FWK_ID_ELEMENT_INIT(			\
					FWK_MODULE_IDX_STM32_PWR_REGU,	\
					(_idx) /* same index */),	\
		.api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_PWR_REGU,\
					  0 /* API type */),		\
	}

/*
 * SCMI voltd binds to voltd module (FWK_MODULE_IDX_VOLTAGE_DOMAIN).
 * Common permissions for exposed voltds. All have same permissions.
 */
#define SCMI_VOLTD(_idx, _id)			[(_idx)] =  {	\
		.element_id = FWK_ID_ELEMENT_INIT(		\
				FWK_MODULE_IDX_VOLTAGE_DOMAIN,	\
				(_idx) /* same index */),	\
	}

/*
 * Framwork expects 1 element per module per voltd:
 * - stm32_pwr_regu elements data configuration provided by stm32_voltd_cfg[]
 * - voltage domain elements data configuration provided by voltd_cfg[]
 * - SCMI voltage domain elements data configuration provided by
 *   stm32_pwr_regu_cfg_scmi_voltd[] used as input data entry point.
 */
#define STM32_VOLTD_ELT(_idx, _id, _name)	[_idx] = {	\
			.name = _name,		\
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
#define VOLTD_CELL(a, b, c)	VOLTD(a, b)
static struct mod_voltd_dev_config voltd_cfg[] = {
	VOLTD_LIST
};

#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	VOLTD_ELT(a, b, c)
/* Exported to config_vold.c */
const struct fwk_element stm32_pwr_regu_cfg_voltd_elts[] = {
	VOLTD_LIST
	{ } /* Terminal tag */
};

/*
 * Elements for stm32_voltd module: define elements from data table
 */
#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	STM32_VOLTD(a, b)
static struct mod_stm32_pwr_regu_dev_config stm32_voltd_cfg[] = {
	VOLTD_LIST
};

#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	STM32_VOLTD_ELT(a, b, c)
static const struct fwk_element stm32_voltd_elt[] = {
	VOLTD_LIST
	{ } /* Terminal tag */
};

/* Configuration data for module stm32_pwr_regu */
const struct fwk_module_config config_stm32_pwr_regu = {
	.elements = FWK_MODULE_STATIC_ELEMENTS_PTR(stm32_voltd_elt),
};

/*
 * Elements for SCMI Voltage Domain module assembled in config_voltd.c
 */
#undef VOLTD_CELL
#define VOLTD_CELL(a, b, c)	SCMI_VOLTD(a, b)
/* Exported to config_vold.c */
struct mod_scmi_voltd_device stm32_pwr_regu_cfg_scmi_voltd[] = {
	VOLTD_LIST
};

static_assert(FWK_ARRAY_SIZE(stm32_pwr_regu_cfg_scmi_voltd) ==
	      VOLTD_DEV_IDX_STM32_PWR_COUNT,
	      "SCMI voltage domain config mismatch");
