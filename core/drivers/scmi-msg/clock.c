// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2019, Linaro Limited
 */
#include <assert.h>
#include <confine_array_index.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <string.h>
#include <util.h>

#include "clock.h"
#include "common.h"

static void report_version(struct scmi_msg *msg)
{
	struct scmi_protocol_version_p2a return_values = {
		.status = SCMI_SUCCESS,
		.version = SCMI_PROTOCOL_VERSION_CLOCK,
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void report_attributes(struct scmi_msg *msg)
{
	size_t agent_count = plat_scmi_clock_count(msg->agent_id);
	struct scmi_protocol_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
		.attributes = SCMI_CLOCK_PROTOCOL_ATTRIBUTES(1, agent_count),
	};

	if (msg->in_size) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void report_message_attributes(struct scmi_msg *msg)
{
	struct scmi_protocol_message_attributes_a2p *in_args = (void *)msg->in;
	struct scmi_protocol_message_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
		.attributes = 0,
	};

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void scmi_clock_attributes(struct scmi_msg *msg)
{
	const struct scmi_clock_attributes_a2p *in_args = (void *)msg->in;
	struct scmi_clock_attributes_p2a return_values = {
		.status = SCMI_SUCCESS,
	};
	const char *name = NULL;
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->agent_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->agent_id));

	name = plat_scmi_clock_get_name(msg->agent_id, clock_id);
	if (!name) {
		scmi_status_response(msg, SCMI_NOT_FOUND);
		return;
	}
	assert(strlen(name) < SCMI_CLOCK_NAME_LENGTH_MAX);

	return_values.attributes = plat_scmi_clock_get_state(msg->agent_id,
							     clock_id);

	memcpy(return_values.clock_name, name,
	       strnlen(name, sizeof(return_values.clock_name)));

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void scmi_clock_rate_get(struct scmi_msg *msg)
{
	const struct scmi_clock_rate_get_a2p *in_args = (void *)msg->in;
	unsigned long rate = 0;
	struct scmi_clock_rate_get_p2a return_values = { };
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->agent_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->agent_id));

	rate = plat_scmi_clock_get_current_rate(msg->agent_id, clock_id);

	reg_pair_from_64(rate, return_values.rate + 1, return_values.rate);

	scmi_write_response(msg, &return_values, sizeof(return_values));
}

static void scmi_clock_rate_set(struct scmi_msg *msg)
{
	const struct scmi_clock_rate_set_a2p *in_args = (void *)msg->in;
	uint64_t rate_64 = 0;
	unsigned long rate = 0;
	int32_t status = 0;
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->agent_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->agent_id));

	rate_64 = reg_pair_to_64(in_args->rate[1], in_args->rate[0]);
	rate = rate_64;

	status = plat_scmi_clock_set_current_rate(msg->agent_id, clock_id,
						  rate);

	scmi_status_response(msg, status);
}

static void scmi_clock_config_set(struct scmi_msg *msg)
{
	const struct scmi_clock_config_set_a2p *in_args = (void *)msg->in;
	int32_t status = SCMI_GENERIC_ERROR;
	bool enable = false;
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->agent_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->agent_id));

	enable = in_args->attributes & SCMI_CLOCK_CONFIG_SET_ENABLE_MASK;

	status = plat_scmi_clock_set_state(msg->agent_id, clock_id, enable);

	scmi_status_response(msg, status);
}

#define RATES_ARRAY_SIZE_MAX	(SCMI_PLAYLOAD_MAX - \
				 sizeof(struct scmi_clock_describe_rates_p2a))

#define SCMI_RATES_BY_ARRAY(_nb_rates, _rem_rates) \
	SCMI_CLOCK_DESCRIBE_RATES_NUM_RATES_FLAGS((_nb_rates), \
						SCMI_CLOCK_RATE_FORMAT_LIST, \
						(_rem_rates))
#define SCMI_RATES_BY_STEP \
	SCMI_CLOCK_DESCRIBE_RATES_NUM_RATES_FLAGS(3, \
						SCMI_CLOCK_RATE_FORMAT_RANGE, \
						0)

#define RATE_DESC_SIZE		sizeof(struct scmi_clock_rate)

static void write_rate_desc_in_buffer(char *dest, unsigned long rate)
{
	uint32_t value = 0;

	value = (uint32_t)rate;
	memcpy(dest, &value, sizeof(uint32_t));

	value = (uint32_t)((uint64_t)rate >> 32);
	memcpy(dest + sizeof(uint32_t), &value, sizeof(uint32_t));
}

static void write_rate_desc_array_in_buffer(char *dest, unsigned long *rates,
					    size_t nb_elt)
{
	size_t n = 0;

	for (n = 0; n < nb_elt; n++) {
		write_rate_desc_in_buffer(dest, rates[n]);
		dest += RATE_DESC_SIZE;
	}
}

static void scmi_clock_describe_rates(struct scmi_msg *msg)
{
	const struct scmi_clock_describe_rates_a2p *in_args = (void *)msg->in;
	struct scmi_clock_describe_rates_p2a p2a = { };
	size_t nb_rates = 0;
	int32_t status = SCMI_GENERIC_ERROR;
	unsigned int clock_id = 0;

	if (msg->in_size != sizeof(*in_args)) {
		scmi_status_response(msg, SCMI_PROTOCOL_ERROR);
		return;
	}

	if (in_args->clock_id >= plat_scmi_clock_count(msg->agent_id)) {
		scmi_status_response(msg, SCMI_INVALID_PARAMETERS);
		return;
	}

	clock_id = confine_array_index(in_args->clock_id,
				       plat_scmi_clock_count(msg->agent_id));

	/* Platform may support array rate description */
	status = plat_scmi_clock_rates_array(msg->agent_id, clock_id, NULL,
					     &nb_rates);
	if (status == SCMI_SUCCESS) {
		/* Currently 12 cells mex, so it's affordable for the stack */
		unsigned long plat_rates[RATES_ARRAY_SIZE_MAX / RATE_DESC_SIZE];
		size_t max_nb = RATES_ARRAY_SIZE_MAX / RATE_DESC_SIZE;
		size_t ret_nb = MIN(nb_rates - in_args->rate_index, max_nb);
		size_t rem_nb = nb_rates - in_args->rate_index - ret_nb;

		status =  plat_scmi_clock_rates_array(msg->agent_id, clock_id,
						      plat_rates, &ret_nb);
		if (status == SCMI_SUCCESS) {
			write_rate_desc_array_in_buffer(msg->out + sizeof(p2a),
							plat_rates, ret_nb);

			p2a.num_rates_flags = SCMI_RATES_BY_ARRAY(ret_nb,
								  rem_nb);
			p2a.status = SCMI_SUCCESS;

			memcpy(msg->out, &p2a, sizeof(p2a));
			msg->out_size_out = sizeof(p2a) +
					    ret_nb * RATE_DESC_SIZE;
		}
	} else if (status == SCMI_NOT_SUPPORTED) {
		unsigned long triplet[3] = { 0, 0, 0 };

		/* Platform may support min§max/step triplet description */
		status =  plat_scmi_clock_rates_by_step(msg->agent_id, clock_id,
							triplet);
		if (status == SCMI_SUCCESS) {
			write_rate_desc_array_in_buffer(msg->out + sizeof(p2a),
							triplet, 3);

			p2a.num_rates_flags = SCMI_RATES_BY_STEP;
			p2a.status = SCMI_SUCCESS;

			memcpy(msg->out, &p2a, sizeof(p2a));
			msg->out_size_out = sizeof(p2a) + (3 * RATE_DESC_SIZE);
		}
	}

	if (status) {
		scmi_status_response(msg, status);
	} else {
		/*
		 * Message payload is already writen to msg->out, and
		 * msg->out_size_out updated.
		 */
	}
}

const scmi_msg_handler_t scmi_clock_handler_table[] = {
	[SCMI_PROTOCOL_VERSION] = report_version,
	[SCMI_PROTOCOL_ATTRIBUTES] = report_attributes,
	[SCMI_PROTOCOL_MESSAGE_ATTRIBUTES] = report_message_attributes,
	[SCMI_CLOCK_ATTRIBUTES] = scmi_clock_attributes,
	[SCMI_CLOCK_DESCRIBE_RATES] = scmi_clock_describe_rates,
	[SCMI_CLOCK_RATE_SET] = scmi_clock_rate_set,
	[SCMI_CLOCK_RATE_GET] = scmi_clock_rate_get,
	[SCMI_CLOCK_CONFIG_SET] = scmi_clock_config_set,
};

scmi_msg_handler_t scmi_msg_get_clock_handler(struct scmi_msg *msg)
{
	const size_t array_size = ARRAY_SIZE(scmi_clock_handler_table);

	if (msg->message_id >= array_size) {
		DMSG("Clock handle not found %zu", msg->message_id);
		return NULL;
	}

	msg->message_id = confine_array_index(msg->message_id, array_size);

	return scmi_clock_handler_table[msg->message_id];
}
