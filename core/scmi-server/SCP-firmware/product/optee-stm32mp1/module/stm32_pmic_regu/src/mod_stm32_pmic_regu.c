/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <drivers/stm32mp1_pmic.h>
#include <drivers/stpmic1.h>
#include <fwk_macros.h>
#include <fwk_mm.h>
#include <fwk_module.h>
#include <mod_voltage_domain.h>
#include <mod_scmi_std.h>
#include <mod_stm32_pmic_regu.h>
#include <stm32_util.h>

/* Device context */
struct stm32_pmic_regu_dev_ctx {
	const char *regu_id;		/* ID internal to regulator */
	const char *name;		/* Name exposed through SCMI */
};

/* Module context */
struct stm32_pmic_regu_ctx {
    struct stm32_pmic_regu_dev_ctx *dev_ctx_table;
    unsigned int dev_count;
};

static struct stm32_pmic_regu_ctx module_ctx;

static bool nsec_can_access_pmic_regu(const char *regu_name)
{
	/* Currently allow non-secure world to access all PMIC regulators */
	return true;
}

static int32_t get_regu_voltage(const char *regu_name)
{
	unsigned long level_uv = 0;

	stm32mp_get_pmic();
	level_uv = stpmic1_regulator_voltage_get(regu_name) * 1000;
	stm32mp_put_pmic();

	return (int32_t)level_uv;
}

static int32_t set_regu_voltage(const char *regu_name, int32_t level_uv)
{
	int rc = 0;
	unsigned int level_mv = level_uv / 1000;

	DMSG("Set STPMIC1 regulator %s level to %dmV", regu_name,
	     level_uv / 1000);

	fwk_assert(level_mv < UINT16_MAX);

	stm32mp_get_pmic();
	rc = stpmic1_regulator_voltage_set(regu_name, level_mv);
	stm32mp_put_pmic();

	return rc ? SCMI_GENERIC_ERROR : SCMI_SUCCESS;
}

static bool regu_is_enable(const char *regu_name)
{
	bool rc = false;

	stm32mp_get_pmic();
	rc = stpmic1_is_regulator_enabled(regu_name);
	stm32mp_put_pmic();

	return rc;
}

static int32_t set_regu_state(const char *regu_name, bool enable)
{
	int rc = 0;

	stm32mp_get_pmic();

	DMSG("%sable STPMIC1 %s (was %s)", enable ? "En" : "Dis", regu_name,
	     stpmic1_is_regulator_enabled(regu_name) ? "on" : "off");

	if (enable)
		rc = stpmic1_regulator_enable(regu_name);
	else
		rc = stpmic1_regulator_disable(regu_name);

	stm32mp_put_pmic();

	return rc ? SCMI_GENERIC_ERROR : SCMI_SUCCESS;
}

/*
 * Voltage domain driver API functions
 */
static int pmic_regu_get_config(fwk_id_t dev_id, uint32_t *config)
{
    struct stm32_pmic_regu_dev_ctx *ctx;
    int rc = 0;
    bool enabled = false;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;

    if (!nsec_can_access_pmic_regu(ctx->regu_id))
        return FWK_E_ACCESS;

    if (regu_is_enable(ctx->regu_id))
        *config = MOD_VOLTD_MODE_ON | MOD_VOLTD_MODE_TYPE_ARCH;
    else
        *config = MOD_VOLTD_MODE_OFF | MOD_VOLTD_MODE_TYPE_ARCH;

    IMSG("SCMI voltd %u: get config PMIC %s = %#"PRIx32,
	 fwk_id_get_element_idx(dev_id), ctx->regu_id, *config);

    return FWK_SUCCESS;
}

static int pmic_regu_set_config(fwk_id_t dev_id, uint32_t config)
{
    struct stm32_pmic_regu_dev_ctx *ctx = NULL;
    int rc = 0;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;

    if (!nsec_can_access_pmic_regu(ctx->regu_id))
        return FWK_E_ACCESS;

    if (set_regu_state(ctx->regu_id, config != 0))
        return FWK_E_DEVICE;

    IMSG("SCMI voltd %u: set config PMIC %s to %#"PRIx32,
         fwk_id_get_element_idx(dev_id), ctx->regu_id, config);

    return FWK_SUCCESS;
}

static int pmic_regu_get_level(fwk_id_t dev_id, int *level_uv)
{
    struct stm32_pmic_regu_dev_ctx *ctx = NULL;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;

    if (!nsec_can_access_pmic_regu(ctx->regu_id))
        return FWK_E_ACCESS;

    *level_uv = get_regu_voltage(ctx->regu_id);

    IMSG("SCMI voltd %u: get level PMIC %s = %d",
	 fwk_id_get_element_idx(dev_id), ctx->regu_id, *level_uv);

    return FWK_SUCCESS;
}

static int pmic_regu_set_level(fwk_id_t dev_id, int level_uv)
{
    struct stm32_pmic_regu_dev_ctx *ctx = NULL;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;

    if (!nsec_can_access_pmic_regu(ctx->regu_id))
        return FWK_E_ACCESS;

    IMSG("SCMI voltd %u: set level PMIC %s to %d",
	 fwk_id_get_element_idx(dev_id), ctx->regu_id, level_uv);

    if (set_regu_voltage(ctx->regu_id, level_uv))
        return FWK_E_DEVICE;

    return FWK_SUCCESS;
}

static void find_bound_uv(const uint16_t *levels, size_t count,
			  int32_t *min, int32_t *max)
{
	size_t n = 0;

	*min = INT32_MAX;
	*max = INT32_MIN;

	for (n = 0; n < count; n++) {
		if (*min > levels[n])
			*min = levels[n];
		if (*max < levels[n])
			*max = levels[n];
	}
}

static int pmic_regu_get_info(fwk_id_t dev_id, struct mod_voltd_info *info)
{
    struct stm32_pmic_regu_dev_ctx *ctx = NULL;
    const uint16_t *levels = NULL;
    size_t full_count = 0;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;

    if (!nsec_can_access_pmic_regu(ctx->regu_id))
        return FWK_E_ACCESS;

    stpmic1_regulator_levels_mv(ctx->regu_id, &levels, &full_count);

    memset(info, 0, sizeof(*info));
    info->name = ctx->name;
    info->level_range.level_type = MOD_VOLTD_VOLTAGE_LEVEL_DISCRETE;
    info->level_range.level_count = full_count;
    find_bound_uv(levels, full_count,
		  &info->level_range.min_uv, &info->level_range.max_uv);

    DMSG("SCMI voltd %u: get_info PMIC %s",
	 fwk_id_get_element_idx(dev_id), ctx->regu_id);

    return FWK_SUCCESS;
}

static int pmic_regu_level_from_index(fwk_id_t dev_id, unsigned int index,
                                     int32_t *level_uv)
{
    struct stm32_pmic_regu_dev_ctx *ctx = NULL;
    const uint16_t *levels = NULL;
    size_t full_count = 0;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(dev_id);

    if (!fwk_module_is_valid_element_id(dev_id))
        return FWK_E_PARAM;

    if (!nsec_can_access_pmic_regu(ctx->regu_id))
        return FWK_E_ACCESS;

    stpmic1_regulator_levels_mv(ctx->regu_id, &levels, &full_count);
    if (index >= full_count)
        return FWK_E_RANGE;

    *level_uv = (int32_t)levels[index] * 1000;

    DMSG("SCMI voltd %u: get level PMIC %s = %d",
	 fwk_id_get_element_idx(dev_id), ctx->regu_id, *level_uv);

    return FWK_SUCCESS;
}

static const struct mod_voltd_drv_api api_stm32_pmic_regu = {
    .get_level = pmic_regu_get_level,
    .set_level = pmic_regu_set_level,
    .set_config = pmic_regu_set_config,
    .get_config = pmic_regu_get_config,
    .get_info = pmic_regu_get_info,
    .get_level_from_index = pmic_regu_level_from_index,
    /* Not supported */
};

/*
 * Framework handler functions
 */

static int stm32_pmic_regu_init(fwk_id_t module_id, unsigned int element_count,
                               const void *data)
{
    module_ctx.dev_count = element_count;

MSG("%s", __func__);

    if (element_count)
        module_ctx.dev_ctx_table = fwk_mm_calloc(element_count,
            sizeof(*module_ctx.dev_ctx_table));

    return FWK_SUCCESS;
}

static int stm32_pmic_regu_element_init(fwk_id_t element_id,
                                        unsigned int unused,
                                        const void *data)
{
    struct stm32_pmic_regu_dev_ctx *ctx = NULL;
    const struct mod_stm32_pmic_regu_dev_config *dev_config = data;

MSG("%s", __func__);

    if (!fwk_module_is_valid_element_id(element_id))
        return FWK_E_PARAM;

    ctx = module_ctx.dev_ctx_table + fwk_id_get_element_idx(element_id);

    ctx->regu_id = dev_config->internal_name;
    ctx->name = dev_config->name;

    return FWK_SUCCESS;
}

static int stm32_pmic_regu_process_bind_request(fwk_id_t requester_id,
						fwk_id_t target_id,
						fwk_id_t api_type,
						const void **api)
{
    *api = &api_stm32_pmic_regu;

    return FWK_SUCCESS;
}

const struct fwk_module module_stm32_pmic_regu = {
    .name = "STM32MP1 PMIC regulator driver for SCMI",
    .type = FWK_MODULE_TYPE_DRIVER,
    .api_count = 1,
    .init = stm32_pmic_regu_init,
    .element_init = stm32_pmic_regu_element_init,
    .process_bind_request = stm32_pmic_regu_process_bind_request,
};
