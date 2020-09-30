/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_STPMIC1_REGU_H
#define MOD_STPMIC1_REGU_H

#include <dt-bindings/regulator/st,stm32mp15-regulator.h>
#include <fwk_element.h>
#include <fwk_macros.h>
#include <stdint.h>
#include <stm32_util.h>

#define VOLTD_DEV_IDX_BUCK1		VOLTD_SCMI2_BUCK1
#define VOLTD_DEV_IDX_BUCK2             VOLTD_SCMI2_BUCK2
#define VOLTD_DEV_IDX_BUCK3             VOLTD_SCMI2_BUCK3
#define VOLTD_DEV_IDX_BUCK4             VOLTD_SCMI2_BUCK4
#define VOLTD_DEV_IDX_LDO1              VOLTD_SCMI2_LDO1
#define VOLTD_DEV_IDX_LDO2              VOLTD_SCMI2_LDO2
#define VOLTD_DEV_IDX_LDO3              VOLTD_SCMI2_LDO3
#define VOLTD_DEV_IDX_LDO4              VOLTD_SCMI2_LDO4
#define VOLTD_DEV_IDX_LDO5              VOLTD_SCMI2_LDO5
#define VOLTD_DEV_IDX_LDO6              VOLTD_SCMI2_LDO6
#define VOLTD_DEV_IDX_VREFDDR           VOLTD_SCMI2_VREFDDR
#define VOLTD_DEV_IDX_BOOST             VOLTD_SCMI2_BOOST
#define VOLTD_DEV_IDX_PWR_SW1           VOLTD_SCMI2_PWR_SW1
#define VOLTD_DEV_IDX_PWR_SW2           VOLTD_SCMI2_PWR_SW2

#define VOLTD_DEV_IDX_STPMIC1_REGU_COUNT    14

/*!
 * \brief Platform clocks configuration.
 */
struct mod_stm32_pmic_regu_dev_config {
    const char *name;
    const char *internal_name;
};

#endif /* MOD_STPMIC1_REGU_H */
