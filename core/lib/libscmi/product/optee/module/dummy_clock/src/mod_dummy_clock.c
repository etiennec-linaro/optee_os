/*
 * Arm SCP/MCP Software
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_element.h>
#include <fwk_errno.h>
#include <fwk_macros.h>
#include <fwk_mm.h>
#include <fwk_module.h>
#include <fwk_host.h>
#include <mod_clock.h>
#include <mod_dummy_clock.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef BUILD_OPTEE
#include <trace.h>
#endif

/* Device context */
struct dummy_clock_dev_ctx {
	unsigned long clock_id;
	uint64_t rate;
	int state;
};

/* Module context */
struct dummy_clock_ctx {
    struct dummy_clock_dev_ctx *dev_ctx_table;
    unsigned int dev_count;
};

static struct dummy_clock_ctx module_ctx;

/*
 * Clock driver API functions
 */
static int get_rate(fwk_id_t dev_id, uint64_t *rate)
{
    struct dummy_clock_dev_ctx *ctx = NULL;


    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;
    if (rate == NULL)
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    *rate = ctx->rate;

MSG_RAW("SCMI clk %u (id %lu): rate = %" PRIu64,
	fwk_id_get_element_idx(dev_id), ctx->clock_id, ctx->rate);

    return FWK_SUCCESS;
}

static int set_state(fwk_id_t dev_id, enum mod_clock_state state)
{
	struct dummy_clock_dev_ctx *ctx;

	switch (state) {
	case MOD_CLOCK_STATE_STOPPED:
	case MOD_CLOCK_STATE_RUNNING:
		break;
	default:
	        return FWK_E_PARAM;
	}

	ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

	ctx->state = state;

MSG_RAW("SCMI clk %u (clock_id %lu): set state %s",
	 fwk_id_get_element_idx(dev_id), ctx->clock_id,
	 state == MOD_CLOCK_STATE_STOPPED ? "off" : "on");

	return FWK_SUCCESS;
}

static int get_state(fwk_id_t dev_id, enum mod_clock_state *state)
{
    struct dummy_clock_dev_ctx *ctx;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;
    if (state == NULL)
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    *state = ctx->state;

MSG_RAW("SCMI clk %u (clock_id %lu): get state %s",
	 fwk_id_get_element_idx(dev_id), ctx->clock_id,
	 ctx->state == MOD_CLOCK_STATE_STOPPED ? "Off" : "On");

    return FWK_SUCCESS;
}

static int get_range(fwk_id_t dev_id, struct mod_clock_range *range)
{
    struct dummy_clock_dev_ctx *ctx = NULL;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;
    if (range == NULL)
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    range->rate_type = MOD_CLOCK_RATE_TYPE_DISCRETE;
    range->min = ctx->rate;
    range->max = ctx->rate;
    range->rate_count = 1;

MSG_RAW("SCMI clk %u (clock_id %lu): get range %" PRIu64,
	 fwk_id_get_element_idx(dev_id), ctx->clock_id, ctx->rate);

    return FWK_SUCCESS;
}

static int set_rate(fwk_id_t dev_id, uint64_t rate,
                          enum mod_clock_round_mode round_mode __unused)
{
    struct dummy_clock_dev_ctx *ctx = NULL;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    ctx->rate = rate;

MSG_RAW("SCMI clk %u (clock_id %lu): get range %" PRIu64,
	 fwk_id_get_element_idx(dev_id), ctx->clock_id, ctx->rate);

    return FWK_SUCCESS;
}

static int stub_get_rate_from_index(fwk_id_t dev_id,
                                          unsigned int rate_index,
                                          uint64_t *rate)
{
    return FWK_E_SUPPORT;
}

static int stub_process_power_transition(fwk_id_t dev_id, unsigned int state)
{
    return FWK_E_SUPPORT;
}

static int stub_pending_power_transition(fwk_id_t dev_id,
					 unsigned int current_state,
					 unsigned int next_state)
{
    return FWK_E_SUPPORT;
}

static const struct mod_clock_drv_api api_dummy_clock = {
    .set_rate = set_rate,
    .get_rate = get_rate,
    .set_state = set_state,
    .get_state = get_state,
    .get_range = get_range,
    /* Not supported */
    .get_rate_from_index = stub_get_rate_from_index,
    .process_power_transition = stub_process_power_transition,
    .process_pending_power_transition = stub_pending_power_transition,
};

/*
 * Framework handler functions
 */

static int dummy_clock_init(fwk_id_t module_id, unsigned int element_count,
                            const void *data)
{
    module_ctx.dev_count = element_count;

    if (element_count == 0)
        return FWK_SUCCESS;

    module_ctx.dev_ctx_table = fwk_mm_calloc(element_count,
                                             sizeof(struct dummy_clock_dev_ctx));
    if (module_ctx.dev_ctx_table == NULL)
        return FWK_E_NOMEM;

    return FWK_SUCCESS;
}

static int dummy_clock_element_init(fwk_id_t element_id, unsigned int unused,
                                  const void *data)
{
    struct dummy_clock_dev_ctx *ctx = NULL;
    const struct mod_dummy_clock_dev_config *dev_config = data;

    if (!fwk_module_is_valid_element_id(element_id))
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(element_id);

    ctx->clock_id = dev_config->clock_id;
    ctx->state = dev_config->state;
    ctx->rate = dev_config->rate;

    return FWK_SUCCESS;
}

static int dummy_clock_process_bind_request(fwk_id_t requester_id, fwk_id_t id,
                                        fwk_id_t api_type, const void **api)
{
    *api = &api_dummy_clock;
    return FWK_SUCCESS;
}

const struct fwk_module module_dummy_clock = {
    .name = "Dummy clock driver for SCMI",
    .type = FWK_MODULE_TYPE_DRIVER,
    .api_count = 1,
    .event_count = 0,
    .init = dummy_clock_init,
    .element_init = dummy_clock_element_init,
    .process_bind_request = dummy_clock_process_bind_request,
};
