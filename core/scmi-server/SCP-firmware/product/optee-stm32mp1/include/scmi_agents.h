/*
 * Arm SCP/MCP Software
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SCMI_AGENTS_H
#define SCMI_AGENTS_H

enum scmi_agent_id {
    SCMI_AGENT_ID_RSV = 0,	/* 0 is reserved for the platform */
    SCMI_AGENT_ID_NSEC0,
    SCMI_AGENT_ID_NSEC1,
    SCMI_AGENT_ID_NSEC2,
    SCMI_AGENT_ID_COUNT
};

enum scmi_service_idx {
    SCMI_SERVICE_IDX_NS_CHANNEL0 = 0,
    SCMI_SERVICE_IDX_NS_CHANNEL1,
    SCMI_SERVICE_IDX_NS_CHANNEL2,
    SCMI_SERVICE_IDX_COUNT
};

enum scmi_channel_device_idx {
    SCMI_CHANNEL_DEVICE_IDX_NS0 = 0,
    SCMI_CHANNEL_DEVICE_IDX_NS1,
    SCMI_CHANNEL_DEVICE_IDX_NS2,
    SCMI_CHANNEL_DEVICE_IDX_COUNT
};

#endif /* SCMI_AGENTS_H */
