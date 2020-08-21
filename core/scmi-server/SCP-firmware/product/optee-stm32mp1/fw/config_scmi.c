/*
 * Copyright (c) 2019-2020, Linaro Limited
 * Copyright (c) 2015-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_macros.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <internal/scmi.h>
#include <mod_optee_smt.h>
#include <mod_scmi.h>
#include <scmi_agents.h>

static const struct fwk_element service_table[] = {
    [SCMI_SERVICE_IDX_NS_CHANNEL] = {
        .name = "SERVICE1",
        .data = &((struct mod_scmi_service_config) {
            .transport_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_SMT,
                                                SCMI_SERVICE_IDX_NS_CHANNEL),
            .transport_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_SMT,
                                                MOD_OPTEE_SMT_API_IDX_SCMI_TRANSPORT),
            .scmi_agent_id = SCMI_AGENT_ID_NSEC,
        }),
    },
    [SCMI_SERVICE_IDX_COUNT] = { 0 }
};

static const struct fwk_element *get_scmi_service_table(fwk_id_t module_id)
{
    return service_table;
}

static const struct mod_scmi_agent agent_table[] = {
    [SCMI_AGENT_ID_NSEC] = {
        .type = SCMI_AGENT_TYPE_OSPM,
        .name = "OSPM",
    },
};

struct fwk_module_config config_scmi = {
    .elements = FWK_MODULE_DYNAMIC_ELEMENTS(get_scmi_service_table),
    .data = &((struct mod_scmi_config) {
        .protocol_count_max = 9,
        .agent_count = FWK_ARRAY_SIZE(agent_table) - 1,
        .agent_table = agent_table,
        .vendor_identifier = "Linaro",
        .sub_vendor_identifier = "PMWG",
    }),
};
