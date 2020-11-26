// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2020, Linaro Limited
 */
#include <confine_array_index.h>
#include <compiler.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <scmi/pta_scmi_client.h>
#include <scmi/scmi_server.h>
#include <string.h>
#include <tee_api.h>

#define INVALID_SCMI_CHANNEL_ID		UINT32_MAX

/*
 * Abstract SCP-fmw channel ID (it is a MHU element fwk_id) to the
 * SCMI (non-secure) agent using a index in known SCP-fmw channel
 * IDs.
 */
static unsigned int scmi_channel_cnt;
static uint32_t *scmi_channel_hdl;

static TEE_Result channel_id_from_agent(unsigned int *out, unsigned int in)
{
	unsigned int channel_id = 0;

	if (in > scmi_channel_cnt)
		return TEE_ERROR_BAD_PARAMETERS;
	channel_id = confine_array_index(in, scmi_channel_cnt);
	channel_id = scmi_channel_hdl[channel_id];
	if (channel_id == INVALID_SCMI_CHANNEL_ID)
		return TEE_ERROR_BAD_PARAMETERS;

	*out = channel_id;

	return TEE_SUCCESS;
}

static TEE_Result channel_id_to_agent(unsigned int *out, unsigned int in)
{
	unsigned int n = 0;

	if (in == INVALID_SCMI_CHANNEL_ID)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Find an already matching reference */
	for (n = 0; n < scmi_channel_cnt; n++) {
		if (scmi_channel_hdl[n] == in) {
			*out = n;

			return TEE_SUCCESS;
		}
	}

	/* Store the new reference */
	for (n = 0; n < scmi_channel_cnt; n++) {
		if (scmi_channel_hdl[n] == INVALID_SCMI_CHANNEL_ID) {
			scmi_channel_hdl[n] = in;
			*out = n;

			return TEE_SUCCESS;
		}
	}

	EMSG("SCMI channel IDs list unexpectedly hexausted");
	assert(0);
	return TEE_ERROR_BAD_PARAMETERS;
}
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

	params[0].value.a = scmi_channel_cnt;

	return TEE_SUCCESS;
}

static TEE_Result cmd_get_channel(void *sess __unused,
				  uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *shm = NULL;
	unsigned int size = 0;
	uint32_t agent_id = 0;
	unsigned int channel_id = 0;
	int server_id = 0;
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);
	const uint32_t old_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						    TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_NONE);

	// Note: FVP config uses this agent_id as channel_id
	agent_id = (int)params[0].value.a;

	/* Old deprecated ABI */
	if (param_types == old_ptypes) {
		paddr_t mem = (paddr_t)reg_pair_to_64(params[1].value.a,
						      params[1].value.b);

		size = params[2].value.a;
		shm = phys_to_virt(mem, MEM_AREA_IO_NSEC);

		DMSG("SCMI deprecated GET_CHANNEL ABI shm: %zu@0x%"PRIxPA" (%p)",
		     size, mem, shm);

	} else if (param_types != exp_ptypes) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	server_id = scmi_server_get_channel(agent_id, shm, size);
	if (server_id < 0)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("SCMI server: channel ID %#x", (unsigned int)server_id);

	res = channel_id_to_agent(&channel_id, (unsigned int)server_id);
	if (res)
		return res;

	params[0].value.a = (uint32_t)channel_id;

	return TEE_SUCCESS;
}

static TEE_Result cmd_process_channel(void *sess __unused,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t ptypes_chan = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);
	const uint32_t ptypes_shm = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_MEMREF_INOUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int channel_id = 0;
	unsigned int server_id = 0;
	void *msg_buf = NULL;

	if (param_types == ptypes_chan) {
		FMSG("SCMI process type 1 : %"PRIx32" ", params[0].value.a);
		channel_id = params[0].value.a;
	} else if (param_types == ptypes_shm) {
		FMSG("SCMI process type 2 : %"PRIu32"@%p",
		     params[0].value.a, params[1].memref.buffer);

		channel_id = params[0].value.a;
		msg_buf = params[1].memref.buffer;
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = channel_id_from_agent(&server_id, channel_id);
	if (res)
		return res;

	scmi_server_process_thread(server_id, msg_buf);

	return TEE_SUCCESS;



}

static TEE_Result invoke_command(void *sess, uint32_t cmd,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG("SCMI command %"PRIx32" ptypes %"PRIx32, cmd, param_types);

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
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT |
			    TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);

static TEE_Result scmi_pta_init(void)
{
	unsigned int n = 0;

	scmi_channel_cnt = scmi_server_get_channels_count();
	if (!scmi_channel_cnt)
		return TEE_SUCCESS;

	scmi_channel_hdl = malloc(scmi_channel_cnt * sizeof(*scmi_channel_hdl));
	if (!scmi_channel_hdl)
		panic();

	for (n = 0; n < scmi_channel_cnt; n++)
		scmi_channel_hdl[n] = INVALID_SCMI_CHANNEL_ID;

	return TEE_SUCCESS;
}

driver_init_late(scmi_pta_init);
