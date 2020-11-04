/*
 * Arm SCP/MCP Software
 * Copyright (c) 2018-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CONFIG_POWER_DOMAIN_H
#define CONFIG_POWER_DOMAIN_H

enum systop_child_index {
    CONFIG_POWER_DOMAIN_SYSTOP_CHILD_CLUSTER0,
    CONFIG_POWER_DOMAIN_SYSTOP_CHILD_DBGTOP,
    CONFIG_POWER_DOMAIN_SYSTOP_CHILD_DPU0TOP,
    CONFIG_POWER_DOMAIN_SYSTOP_CHILD_DPU1TOP,
    CONFIG_POWER_DOMAIN_SYSTOP_CHILD_GPUTOP,
    CONFIG_POWER_DOMAIN_SYSTOP_CHILD_VPUTOP,
    CONFIG_POWER_DOMAIN_SYSTOP_CHILD_COUNT
};

#endif /* CONFIG_POWER_DOMAIN_H */
