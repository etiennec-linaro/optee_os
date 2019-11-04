// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */
#include <compiler.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <scmi/pta_scmi_client.h>
#include <scmi/scmi_server.h>
#include <string.h>
#include <tee_api.h>

static TEE_Result cmd_channel_count(void *sess __unused,
				    uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t expect_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != expect_types)
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].value.a = 1;

	return TEE_SUCCESS;
}

static TEE_Result cmd_get_channel(void *sess __unused,
				  uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t expect_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	if (param_types != expect_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("SCMI pool: %"PRIu32"@0x%"PRIx64" (unchecked)", params[1].value.a,
	     reg_pair_to_64(params[0].value.a, params[0].value.b));

	params[2].value.a = 0;

	return TEE_SUCCESS;
}

static TEE_Result cmd_process_channel(void *sess __unused,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t expect_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (param_types != expect_types)
		return TEE_ERROR_BAD_PARAMETERS;

	scmi_server_process_thread(params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess, uint32_t cmd,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_SCMI_CMD_CHANNEL_COUNT:
		return cmd_channel_count(sess, param_types, params);
	case PTA_SCMI_CMD_GET_CHANNEL:
		return cmd_get_channel(sess, param_types, params);

	case PTA_SCMI_CMD_PROCESS_CHANNEL:
		return cmd_process_channel(sess, param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SCMI_UUID, .name = PTA_SCMI_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
