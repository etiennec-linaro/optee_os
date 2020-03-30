/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SCMI_AGENTS_H
#define SCMI_AGENTS_H

enum scmi_agent_id {
    /* 0 is reserved for the platform */
    SCMI_AGENT_ID_OSPM = 1,
    SCMI_AGENT_ID_PSCI,
    SCMI_AGENT_ID_COUNT,
};

enum scmi_service_idx {
    SCMI_SERVICE_IDX_PSCI,
    SCMI_SERVICE_IDX_OSPM_0,
    SCMI_SERVICE_IDX_OSPM_1,
    SCMI_SERVICE_IDX_COUNT,
};

enum scmi_channel_device_idx {
    SCMI_CHANNEL_DEVICE_IDX_PSCI,
    SCMI_CHANNEL_DEVICE_IDX_OSPM_0,
    SCMI_CHANNEL_DEVICE_IDX_OSPM_1,
    SCMI_CHANNEL_DEVICE_IDX_COUNT
};

#endif /* SCMI_AGENTS_H */
