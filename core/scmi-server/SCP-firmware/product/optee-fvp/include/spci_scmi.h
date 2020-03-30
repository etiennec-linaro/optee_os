/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *     Definitions for SCMI and SMT module configurations.
 */

#ifndef SPCI_SCMI_H
#define SPCI_SCMI_H

/* SCMI agent identifiers */
enum spci_scmi_agent_id {
    /* 0 is reserved for the platform */
    SCMI_AGENT_ID_OSPM = 1,
    SCMI_AGENT_ID_PSCI,
    SCMI_AGENT_ID_COUNT,
};

/* SCMI service indexes */
enum spci_scmi_service_idx {
    SPCI_SCMI_SERVICE_IDX_PSCI,
    SPCI_SCMI_SERVICE_IDX_OSPM_0,
    SPCI_SCMI_SERVICE_IDX_OSPM_1,
    SPCI_SCMI_SERVICE_IDX_COUNT,
};

enum spci_device_idx {
    SPCI_DEVICE_IDX_S,
    SPCI_DEVICE_IDX_NS_H,
    SPCI_DEVICE_IDX_NS_L,
    SPCI_DEVICE_IDX_COUNT
};
#endif /* SGM775_SCMI_H */
