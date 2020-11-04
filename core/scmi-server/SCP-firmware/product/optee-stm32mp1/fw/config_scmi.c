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
    [SCMI_SERVICE_IDX_NS_CHANNEL0] = {
        .name = "service-0",
        .data = &((struct mod_scmi_service_config) {
            .transport_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_SMT,
                                                SCMI_SERVICE_IDX_NS_CHANNEL0),
            .transport_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_SMT,
                                                MOD_OPTEE_SMT_API_IDX_SCMI_TRANSPORT),
            .scmi_agent_id = SCMI_AGENT_ID_NSEC0,
        }),
    },
    [SCMI_SERVICE_IDX_NS_CHANNEL1] = {
        .name = "service-1",
        .data = &((struct mod_scmi_service_config) {
            .transport_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_SMT,
                                                SCMI_SERVICE_IDX_NS_CHANNEL1),
            .transport_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_SMT,
                                                MOD_OPTEE_SMT_API_IDX_SCMI_TRANSPORT),
            .scmi_agent_id = SCMI_AGENT_ID_NSEC1,
        }),
    },
    [SCMI_SERVICE_IDX_NS_CHANNEL2] = {
        .name = "service-2",
        .data = &((struct mod_scmi_service_config) {
            .transport_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_SMT,
                                                SCMI_SERVICE_IDX_NS_CHANNEL2),
            .transport_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_SMT,
                                                MOD_OPTEE_SMT_API_IDX_SCMI_TRANSPORT),
            .scmi_agent_id = SCMI_AGENT_ID_NSEC2,
        }),
    },
    [SCMI_SERVICE_IDX_COUNT] = { 0 }
};

static const struct fwk_element *get_scmi_service_table(fwk_id_t module_id)
{
    return service_table;
}

static const struct mod_scmi_agent agent_table[] = {
    [SCMI_AGENT_ID_NSEC0] = {
        .type = SCMI_AGENT_TYPE_OSPM,
        .name = "OSPM0",
    },
    [SCMI_AGENT_ID_NSEC1] = {
        .type = SCMI_AGENT_TYPE_OSPM,
        .name = "OSPM1",
    },
    [SCMI_AGENT_ID_NSEC2] = {
        .type = SCMI_AGENT_TYPE_OSPM,
        .name = "OSPM2",
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
