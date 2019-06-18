/*
 * Arm SCP/MCP Software
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <dt-bindings/clock/stm32mp1-clks.h>
#include <fwk_element.h>
#include <fwk_errno.h>
#include <fwk_macros.h>
#include <fwk_mm.h>
#include <fwk_module.h>
#include <fwk_host.h>
#include <mod_clock.h>
#include <mod_stm32_clock.h>
#include <stdint.h>
#include <stdlib.h>
#include <stm32_util.h>

/* Device context */
struct stm32_clock_dev_ctx {
	unsigned long clock_id;
};

/* Module context */
struct stm32_clock_ctx {
    struct stm32_clock_dev_ctx *dev_ctx_table;
    unsigned int dev_count;
};

static struct stm32_clock_ctx module_ctx;

/*
 * Clock driver API functions
 */
static int get_rate(fwk_id_t dev_id, uint64_t *rate)
{
    struct stm32_clock_dev_ctx *ctx;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;
    if (rate == NULL)
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    *rate = stm32_clock_get_rate(ctx->clock_id);
    DMSG("SCMI clk %lu: rate = %" PRIu64, ctx->clock_id, *rate);

    return FWK_SUCCESS;
}

static int set_state(fwk_id_t dev_id, enum mod_clock_state state)
{
	struct stm32_clock_dev_ctx *ctx;

	switch (state) {
	case MOD_CLOCK_STATE_STOPPED:
	case MOD_CLOCK_STATE_RUNNING:
		break;
	default:
	        return FWK_E_PARAM;
	}

	ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

	DMSG("SCMI clk %u (clock_id %lu): set state %s",
	 fwk_id_get_element_idx(dev_id), ctx->clock_id,
	 state == MOD_CLOCK_STATE_STOPPED ? "off" : "on");

	if (state == MOD_CLOCK_STATE_STOPPED)
		stm32_nsec_clock_disable(ctx->clock_id);
	else
		stm32_nsec_clock_enable(ctx->clock_id);

	return FWK_SUCCESS;
}

static int get_state(fwk_id_t dev_id, enum mod_clock_state *state)
{
    struct stm32_clock_dev_ctx *ctx;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;
    if (state == NULL)
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (stm32_clock_is_enabled(ctx->clock_id))
	*state = MOD_CLOCK_STATE_RUNNING;
    else
	*state = MOD_CLOCK_STATE_STOPPED;

MSG_RAW("SCMI clk %lu: get state is %s", ctx->clock_id,
	 state == MOD_CLOCK_STATE_STOPPED ? "off" : "on");

    return FWK_SUCCESS;
}

static int get_range(fwk_id_t dev_id, struct mod_clock_range *range)
{
    struct stm32_clock_dev_ctx *ctx = NULL;
    unsigned long rate = 0;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;
    if (range == NULL)
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    rate = stm32_clock_get_rate(ctx->clock_id);
MSG_RAW("SCMI clk %lu: get range is single %lu", ctx->clock_id, rate);

    range->rate_type = MOD_CLOCK_RATE_TYPE_DISCRETE;
    range->min = rate;
    range->max = rate;
    range->rate_count = 1;

    return FWK_SUCCESS;
}

static int stub_set_rate(fwk_id_t dev_id, uint64_t rate,
                              enum mod_clock_round_mode round_mode)
{
    return FWK_E_SUPPORT;
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

static const struct mod_clock_drv_api api_stm32_clock = {
    .get_rate = get_rate,
    .set_state = set_state,
    .get_state = get_state,
    .get_range = get_range,
    /* Not supported */
    .set_rate = stub_set_rate,
    .get_rate_from_index = stub_get_rate_from_index,
    .process_power_transition = stub_process_power_transition,
    .process_pending_power_transition = stub_pending_power_transition,
};

/*
 * Framework handler functions
 */

static int stm32_clock_init(fwk_id_t module_id, unsigned int element_count,
                            const void *data)
{
    module_ctx.dev_count = element_count;

    if (element_count == 0)
        return FWK_SUCCESS;

    module_ctx.dev_ctx_table = fwk_mm_calloc(element_count,
                                             sizeof(struct stm32_clock_dev_ctx));
    if (module_ctx.dev_ctx_table == NULL)
        return FWK_E_NOMEM;

    return FWK_SUCCESS;
}

static int stm32_clock_element_init(fwk_id_t element_id, unsigned int unused,
                                  const void *data)
{
    struct stm32_clock_dev_ctx *ctx = NULL;
    const struct mod_stm32_clock_dev_config *dev_config = data;

    if (!fwk_module_is_valid_element_id(element_id))
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(element_id);

    ctx->clock_id = dev_config->clock_id;

    return FWK_SUCCESS;
}

static int stm32_clock_process_bind_request(fwk_id_t requester_id, fwk_id_t id,
                                        fwk_id_t api_type, const void **api)
{
    *api = &api_stm32_clock;
    return FWK_SUCCESS;
}

const struct fwk_module module_stm32_clock = {
    .name = "STM32MP1 clock driver for SCMI",
    .type = FWK_MODULE_TYPE_DRIVER,
    .api_count = 1,
    .event_count = 0,
    .init = stm32_clock_init,
    .element_init = stm32_clock_element_init,
    .process_bind_request = stm32_clock_process_bind_request,
};
