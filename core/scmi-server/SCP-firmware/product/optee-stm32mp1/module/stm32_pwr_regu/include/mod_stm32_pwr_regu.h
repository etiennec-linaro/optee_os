/*
 * Copyright (c) 2020, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOD_STM32_PWR_REGU_H
#define MOD_STM32_PWR_REGU_H

#include <dt-bindings/regulator/st,stm32mp15-regulator.h>
#include <fwk_element.h>
#include <fwk_macros.h>
#include <stdint.h>
#include <stm32_util.h>

/* Bind SCP-firmware VOLTD_DEV_IDX_* to platform DT bindings */
#define VOLTD_DEV_IDX_REG11             VOLTD_SCMI0_REG11
#define VOLTD_DEV_IDX_REG18             VOLTD_SCMI0_REG18
#define VOLTD_DEV_IDX_USB33             VOLTD_SCMI0_USB33

#define VOLTD_DEV_IDX_STM32_PWR_COUNT   3

/*!
 * \brief Platform clocks configuration.
 */
struct mod_stm32_pwr_regu_dev_config {
    const unsigned long pwr_id;
    const char *name;
};

#endif /* MOD_STM32_PWR_REGU_H */
