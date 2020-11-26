/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */
#ifndef SCMI_PTA_SCMI_CLIENT_H
#define SCMI_PTA_SCMI_CLIENT_H

#define PTA_SCMI_UUID { 0xa8cfe406, 0xd4f5, 0x4a2e, \
                { 0x9f, 0x8d, 0xa2, 0x5d, 0xc7, 0x54, 0xc0, 0x99 } }

#define PTA_SCMI_NAME "SCMI server"

/*
 * PTA_SCMI_CMD_CHANNEL_COUNT - Get number of channels supported
 *
 * param[0] (out value) - value.a: Number of communication channels
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_SCMI_CMD_CHANNEL_COUNT			0x0

/*
 * PTA_SCMI_CMD_GET_CHANNEL - Get channel identifer for a buffer pool
 *
 * SCMI shm information are 0 if agent expects to use OP-TEE regular SHM
 *
 * [in]         value[0].a - SCMI agent identifier
 * [out]        value[0].a - SCMI channel identifier
 * [in]         value[1].a - SCMI shm physical start address (32 MSBytes) or 0
 * [in]         value[1].b - SCMI shm physical start address (32 LSBytes) or 0
 * [in]         value[2].a - SCMI shm byte size or 0
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_SCMI_CMD_GET_CHANNEL		0x1

/*
 * PTA_SCMI_CMD_PROCESS_CHANNEL - Process message in SCMI channel
 *
 * [in]         value[0].a      SCMI channel identifier
 * [in/out]     memref[1]       SCMI message
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_SCMI_CMD_PROCESS_CHANNEL		0x2

#endif /*SCMI_PTA_SCMI_CLIENT_H*/
