/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_macros.h>
#include <fwk_mm.h>
#include <fwk_module.h>
#include <mod_clock.h>
#include <mod_stm32_clock.h>
#include <stm32_util.h>

/* Device context */
struct stm32_clock_dev_ctx {
	unsigned long clock_id;
	bool enabled;
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
    struct stm32_clock_dev_ctx *ctx = NULL;
    unsigned long clock_rate = 0;
    int rc;

    if (!fwk_module_is_valid_element_id(dev_id) || (rate == NULL))
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!stm32mp_nsec_can_access_clock(ctx->clock_id))
        return FWK_E_ACCESS;

    *rate = stm32_clock_get_rate(ctx->clock_id);

    IMSG("SCMI clk %u: stm32_clock_get_rate(%lu) = %"PRIu64,
	 fwk_id_get_element_idx(dev_id), ctx->clock_id, *rate);

    return FWK_SUCCESS;
}

static int set_state(fwk_id_t dev_id, enum mod_clock_state state)
{
    struct stm32_clock_dev_ctx *ctx = NULL;
    int rc = 0;

    switch (state) {
    case MOD_CLOCK_STATE_STOPPED:
    case MOD_CLOCK_STATE_RUNNING:
        break;
    default:
        return FWK_E_PARAM;
    }

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!stm32mp_nsec_can_access_clock(ctx->clock_id))
        return FWK_E_ACCESS;

    if (state == MOD_CLOCK_STATE_STOPPED) {
        if (ctx->enabled) {
            stm32_clock_disable(ctx->clock_id);
	    ctx->enabled = false;
	}
    } else {
        if (!ctx->enabled) {
            stm32_clock_enable(ctx->clock_id);
	    ctx->enabled = true;
	}
    }

    IMSG("SCMI clk %u: stm32_clock_set_state(%lu, %s)",
         fwk_id_get_element_idx(dev_id), ctx->clock_id,
	 state == MOD_CLOCK_STATE_STOPPED ? "off" : "on");

    return FWK_SUCCESS;
}

static int get_state(fwk_id_t dev_id, enum mod_clock_state *state)
{
    struct stm32_clock_dev_ctx *ctx;
    int rc = 0;
    bool enabled = false;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;
    if (state == NULL)
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!stm32mp_nsec_can_access_clock(ctx->clock_id))
        return FWK_E_ACCESS;

    if (ctx->enabled)
        *state = MOD_CLOCK_STATE_RUNNING;
    else
        *state = MOD_CLOCK_STATE_STOPPED;

    IMSG("SCMI clk %u: stm32_clock_get_state(%lu) => %s",
	 fwk_id_get_element_idx(dev_id), ctx->clock_id,
         *state == MOD_CLOCK_STATE_STOPPED ? "off" : "on");

    return FWK_SUCCESS;
}

static int get_range(fwk_id_t dev_id, struct mod_clock_range *range)
{
    struct stm32_clock_dev_ctx *ctx = NULL;
    unsigned long rate = 0;
    int rc = 0;

    if (!fwk_module_is_valid_element_id(dev_id) || (range == NULL))
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!stm32mp_nsec_can_access_clock(ctx->clock_id))
        return FWK_E_ACCESS;

    rate = stm32_clock_get_rate(ctx->clock_id);

    IMSG("SCMI clk %u: stm32_clock_get_range(%lu) = %lu",
         fwk_id_get_element_idx(dev_id), ctx->clock_id, rate);

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

static int get_rate_from_index(fwk_id_t dev_id,
                               unsigned int rate_index, uint64_t *rate)
{
    struct stm32_clock_dev_ctx *ctx = NULL;
    unsigned long clock_rate = 0;
    int rc = 0;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;
    if (rate == NULL || rate_index > 0)
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!stm32mp_nsec_can_access_clock(ctx->clock_id))
        return FWK_E_ACCESS;

    *rate = stm32_clock_get_rate(ctx->clock_id);

    IMSG("SCMI clk %u: stm32_clock_get_rate(%lu) = %"PRIu64,
	 fwk_id_get_element_idx(dev_id), ctx->clock_id, *rate);

    return FWK_SUCCESS;
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
    .get_rate_from_index = get_rate_from_index,
    /* Not supported */
    .set_rate = stub_set_rate,
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

void stm32_scmi_clock_late_init(void)
{
    unsigned int i = 0;

    for (i = 0; i < module_ctx.dev_count; i++) {
        struct stm32_clock_dev_ctx *ctx = &module_ctx.dev_ctx_table[i];

        if (stm32mp_nsec_can_access_clock(ctx->clock_id)) {
            if (stm32_clock_is_enabled(ctx->clock_id)) {
                ctx->enabled = true;
                stm32_clock_enable(ctx->clock_id);
            } else {
                ctx->enabled = false;
            }
        }
    }
}
