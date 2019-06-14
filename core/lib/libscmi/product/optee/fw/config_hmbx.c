/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_host_mailbox.h>
#include <spci_scmi.h>

#define SCMI_PAYLOAD_SIZE       (128)

uint8_t scmi_psci_mb[SCMI_PAYLOAD_SIZE];
uint8_t scmi_ospm0_mb[SCMI_PAYLOAD_SIZE];
uint8_t scmi_ospm1_mb[SCMI_PAYLOAD_SIZE];

static const struct fwk_element hmbx_element_table[] = {
    [SPCI_SCMI_SERVICE_IDX_PSCI] = {
        .name = "PSCI",
        .data = &((struct mod_smt_channel_config) {
            .policies = MOD_SMT_POLICY_INIT_MAILBOX | MOD_SMT_POLICY_SECURE,
            .mailbox_address = (uintptr_t)scmi_psci_mb,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_SPCI,
                SPCI_DEVICE_IDX_S, 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_SPCI, 0),
        })
    },
    [SPCI_SCMI_SERVICE_IDX_OSPM_0] = {
        .name = "OSPM0",
        .data = &((struct mod_smt_channel_config) {
            .policies = MOD_SMT_POLICY_INIT_MAILBOX,
            .mailbox_address = (uintptr_t)scmi_ospm0_mb,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_SPCI,
                 SPCI_DEVICE_IDX_NS_L, 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_SPCI, 0),
        })
    },
    [SPCI_SCMI_SERVICE_IDX_OSPM_1] = {
        .name = "OSPM1",
        .data = &((struct mod_smt_channel_config) {
            .policies = MOD_SMT_POLICY_INIT_MAILBOX,
            .mailbox_address = (uintptr_t)scmi_ospm1_mb,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_SPCI,
                 SPCI_DEVICE_IDX_NS_H, 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_SPCI, 0),
        })
    },
    [SPCI_SCMI_SERVICE_IDX_COUNT] = { 0 },
};

static const struct fwk_element *hmbx_get_element_table(fwk_id_t module_id)
{
	return hmbx_element_table;
}

struct fwk_module_config config_hmbx = {
    .get_element_table = hmbx_get_element_table,
};
