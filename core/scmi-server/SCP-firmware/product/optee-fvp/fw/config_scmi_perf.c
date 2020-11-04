/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>

#include <fwk_element.h>
#include <fwk_host.h>
#include <fwk_module.h>
#include <mod_scmi_perf.h>
#include <scmi_agents.h>

#include "config_dvfs.h"

static const struct mod_scmi_perf_domain_config domains[] = {
    [DVFS_ELEMENT_IDX_LITTLE] = {
        .permissions = &(const uint32_t[]) {
           [SCMI_AGENT_ID_OSPM] = MOD_SCMI_PERF_PERMS_NONE,
           [SCMI_AGENT_ID_PSCI] = MOD_SCMI_PERF_PERMS_NONE,
           [SCMI_AGENT_ID_PERF] = MOD_SCMI_PERF_PERMS_SET_LEVEL  |
                                   MOD_SCMI_PERF_PERMS_SET_LIMITS,
     }
    },
    [DVFS_ELEMENT_IDX_BIG] = {
        .permissions = &(const uint32_t[]) {
           [SCMI_AGENT_ID_OSPM] = MOD_SCMI_PERF_PERMS_NONE,
           [SCMI_AGENT_ID_PSCI] = MOD_SCMI_PERF_PERMS_NONE,
           [SCMI_AGENT_ID_PERF] = MOD_SCMI_PERF_PERMS_SET_LEVEL  |
                                   MOD_SCMI_PERF_PERMS_SET_LIMITS,
        }
    },
    [DVFS_ELEMENT_IDX_GPU] = {
        .permissions = &(const uint32_t[]) {
           [SCMI_AGENT_ID_OSPM] = MOD_SCMI_PERF_PERMS_NONE,
           [SCMI_AGENT_ID_PSCI] = MOD_SCMI_PERF_PERMS_NONE,
           [SCMI_AGENT_ID_PERF] = MOD_SCMI_PERF_PERMS_SET_LEVEL  |
                                   MOD_SCMI_PERF_PERMS_SET_LIMITS,
        }
    },
};

struct fwk_module_config config_scmi_perf = {
    .get_element_table = NULL,
    .data = &((struct mod_scmi_perf_config) {
        .domains = &domains,
    }),
};
