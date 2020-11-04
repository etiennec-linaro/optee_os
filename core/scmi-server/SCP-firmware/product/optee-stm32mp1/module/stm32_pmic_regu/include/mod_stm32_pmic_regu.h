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

/*!
 * \brief Platform regulator configuration.
 */
struct mod_stm32_pmic_regu_dev_config {
    const char *regu_name;
};

#endif /* MOD_STPMIC1_REGU_H */
