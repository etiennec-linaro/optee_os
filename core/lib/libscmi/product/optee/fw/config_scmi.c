/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_macros.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <spci_scmi.h>
#include <mod_scmi.h>
#include <internal/scmi.h>
#include <mod_host_mailbox.h>

static const struct fwk_element service_table[] = {
    [SPCI_SCMI_SERVICE_IDX_PSCI] = {
        .name = "SERVICE0",
        .data = &((struct mod_scmi_service_config) {
            .transport_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_HMBX,
                                                SPCI_SCMI_SERVICE_IDX_PSCI),
            .transport_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_HMBX,
                                                MOD_SMT_API_IDX_SCMI_TRANSPORT),
            .scmi_agent_id = SCMI_AGENT_ID_PSCI,
        }),
    },
    [SPCI_SCMI_SERVICE_IDX_OSPM_0] = {
        .name = "SERVICE1",
        .data = &((struct mod_scmi_service_config) {
            .transport_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_HMBX,
                                                SPCI_SCMI_SERVICE_IDX_OSPM_0),
            .transport_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_HMBX,
                                                MOD_SMT_API_IDX_SCMI_TRANSPORT),
            .scmi_agent_id = SCMI_AGENT_ID_OSPM,
        }),
    },
    [SPCI_SCMI_SERVICE_IDX_OSPM_1] = {
        .name = "SERVICE2",
        .data = &((struct mod_scmi_service_config) {
            .transport_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_HMBX,
                                                SPCI_SCMI_SERVICE_IDX_OSPM_1),
            .transport_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_HMBX,
                                                MOD_SMT_API_IDX_SCMI_TRANSPORT),
            .scmi_agent_id = SCMI_AGENT_ID_OSPM,
        }),
    },
    [SPCI_SCMI_SERVICE_IDX_COUNT] = { 0 }
};

static const struct fwk_element *get_service_table(fwk_id_t module_id)
{
    return service_table;
}

static const struct mod_scmi_agent agent_table[] = {
    [SCMI_AGENT_ID_OSPM] = {
        .type = SCMI_AGENT_TYPE_OSPM,
        .name = "OSPM",
    },
    [SCMI_AGENT_ID_PSCI] = {
        .type = SCMI_AGENT_TYPE_PSCI,
        .name = "PSCI",
    },
};

struct fwk_module_config config_scmi = {
    .get_element_table = get_service_table,
    .data = &((struct mod_scmi_config) {
        .protocol_count_max = 9,
        .agent_count = FWK_ARRAY_SIZE(agent_table) - 1,
        .agent_table = agent_table,
        .vendor_identifier = "Linaro",
        .sub_vendor_identifier = "PMWG",
    }),
};
