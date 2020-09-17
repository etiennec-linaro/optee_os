// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef CONFIG_PWR_REGU_H
#define CONFIG_PWR_REGU_H

#include <mod_stm32_pwr_regu.h>
#include <mod_voltage_domain.h>

extern struct mod_scmi_voltd_device stm32_pwr_regu_cfg_scmi_voltd[VOLTD_DEV_IDX_STM32_PWR_COUNT];
extern const struct fwk_element stm32_pwr_regu_cfg_voltd_elts[];

#endif /* CONFIG_PWR_REGU_H */

