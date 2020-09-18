// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef CONFIG_STPMIC1_REGU_H
#define CONFIG_STPMIC1_REGU_H

#include <mod_stm32_pmic_regu.h>
#include <mod_voltage_domain.h>

extern struct mod_scmi_voltd_device stpmic1_regu_cfg_scmi_voltd[VOLTD_DEV_IDX_STPMIC1_REGU_COUNT];
extern const struct fwk_element stpmic1_regu_cfg_voltd_elts[];

#endif /* CONFIG_STPMIC1_REGU_H */

