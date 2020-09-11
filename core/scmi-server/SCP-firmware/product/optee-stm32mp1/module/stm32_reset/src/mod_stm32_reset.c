/*
 * Arm SCP/MCP Software
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <compiler.h>
#include <fwk_macros.h>
#include <fwk_mm.h>
#include <fwk_module.h>
#include <mod_reset_domain.h>
#include <mod_stm32_reset.h>
#include <stm32_util.h>

#define TIMEOUT_US_1MS		1000

/* Device context */
struct stm32_reset_dev_ctx {
	unsigned long reset_id;
};

/* Module context */
struct stm32_reset_ctx {
    struct stm32_reset_dev_ctx *dev_ctx_table;
    unsigned int dev_count;
};

static struct stm32_reset_ctx module_ctx;

/*
 * Driver API functions
 */

static int reset_set_state(fwk_id_t dev_id, enum mod_reset_domain_mode mode,
			   uint32_t reset_state, uintptr_t cookie)
{
    struct stm32_reset_dev_ctx *ctx = NULL;
    int status = FWK_SUCCESS;

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;

    ctx = &module_ctx.dev_ctx_table[fwk_id_get_element_idx(dev_id)];

    if (!stm32mp_nsec_can_access_reset(ctx->reset_id))
        return FWK_E_ACCESS;

    /* Whatever the reset_state set, we consider a unique context loss mode */
    if (reset_state)
        DMSG("Override requested SCMI reset state %#"PRIx32, reset_state);

    switch (mode) {
    case MOD_RESET_DOMAIN_MODE_EXPLICIT_ASSERT:
	IMSG("SCMI reset %u: assert", fwk_id_get_element_idx(dev_id));
        (void)stm32_reset_assert(ctx->reset_id, 0);
        break;
    case MOD_RESET_DOMAIN_MODE_EXPLICIT_DEASSERT:
	IMSG("SCMI reset %u: deassert", fwk_id_get_element_idx(dev_id));
        (void)stm32_reset_assert(ctx->reset_id, 0);
        break;
    case MOD_RESET_DOMAIN_AUTO_RESET:
	IMSG("SCMI reset %u: cycle", fwk_id_get_element_idx(dev_id));
        if (stm32_reset_assert(ctx->reset_id, TIMEOUT_US_1MS)) {
            status = FWK_E_TIMEOUT;
	}
        if (stm32_reset_deassert(ctx->reset_id, TIMEOUT_US_1MS)) {
            status = FWK_E_TIMEOUT;
	}
        break;
    default:
        return FWK_E_PARAM;
    }

    return status;
}

static const struct mod_reset_domain_drv_api api_stm32_reset = {
    .set_reset_state = reset_set_state,
};

/*
 * Framework handler functions
 */

static int stm32_reset_init(fwk_id_t module_id, unsigned int element_count,
                            const void *data)
{
    module_ctx.dev_count = element_count;

    if (element_count == 0)
        return FWK_SUCCESS;

    module_ctx.dev_ctx_table = fwk_mm_calloc(element_count,
                                             sizeof(struct stm32_reset_dev_ctx));
    if (module_ctx.dev_ctx_table == NULL)
        return FWK_E_NOMEM;

    return FWK_SUCCESS;
}

static int stm32_reset_element_init(fwk_id_t element_id,
				    unsigned int unused __unused,
                                    const void *data)
{
    struct stm32_reset_dev_ctx *ctx = NULL;
    const struct mod_stm32_reset_dev_config *dev_config = NULL;

    if (!fwk_module_is_valid_element_id(element_id))
        return FWK_E_PARAM;

    ctx = &module_ctx.dev_ctx_table[fwk_id_get_element_idx(element_id)];
    dev_config = (const struct mod_stm32_reset_dev_config *)data;

    ctx->reset_id = dev_config->reset_id;

    return FWK_SUCCESS;
}

static int stm32_reset_process_bind_request(fwk_id_t requester_id, fwk_id_t id,
                                            fwk_id_t api_type, const void **api)
{
    *api = &api_stm32_reset;

    return FWK_SUCCESS;
}

const struct fwk_module module_stm32_reset = {
    .name = "STM32 reset driver for SCMI",
    .type = FWK_MODULE_TYPE_DRIVER,
    .api_count = 1,
    .init = stm32_reset_init,
    .element_init = stm32_reset_element_init,
    .process_bind_request = stm32_reset_process_bind_request,
};
