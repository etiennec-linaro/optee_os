/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_id.h>
#include <fwk_mm.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_scmi_voltage_domain.h>
#include <scmi_agents.h>
#include <util.h>

#include "config_pwr_regu.h"

/*
 * Configuration data for module voltage_domain.
 * Aggregate the several voltage domain channels.
 */
static const struct fwk_element *get_voltd_elts(fwk_id_t module_id)
{
	const size_t count = VOLTD_DEV_IDX_STM32_PWR_COUNT + 1;
	struct fwk_element *elts = fwk_mm_alloc(count, sizeof(*elts));
	size_t offset = 0;
	size_t size = 0;

	size = VOLTD_DEV_IDX_STM32_PWR_COUNT * sizeof(*elts);
	memcpy(elts, stm32_pwr_regu_cfg_voltd_elts, size);

	offset += size;
	memset((char *)elts + offset, 0, sizeof(*elts));

	return (const struct fwk_element *)elts;
}

const struct fwk_module_config config_voltage_domain = {
	.elements = FWK_MODULE_DYNAMIC_ELEMENTS(get_voltd_elts),
};

/*
 * Confgiuration data for SCMI modules.
 * Aggregate the several voltage domain channels per agent.
 */
static const struct mod_scmi_voltd_agent scmi_voltd_agents[SCMI_AGENT_ID_COUNT] = {
	[SCMI_AGENT_ID_NSEC0] = {
		.device_table = stm32_pwr_regu_cfg_scmi_voltd,
		.device_count = VOLTD_DEV_IDX_STM32_PWR_COUNT,
	},
};

static const struct mod_scmi_voltd_config scmi_voltd_agents_config = {
	.agent_table = scmi_voltd_agents,
	.agent_count = FWK_ARRAY_SIZE(scmi_voltd_agents),
};

/* Exported in libscmi */
const struct fwk_module_config config_scmi_voltage_domain = {
	/* Register module elements straight from data table */
	.data = (void *)&scmi_voltd_agents_config,
};
