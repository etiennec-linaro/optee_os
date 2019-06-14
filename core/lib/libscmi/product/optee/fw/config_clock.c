/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <fwk_element.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_clock.h>
#include <mod_css_clock.h>
#include <mod_system_pll.h>
#include <mod_power_domain.h>

#include "config_power_domain.h"
#include "clock_devices.h"

static struct fwk_element clock_dev_desc_table[] = {
    [CLOCK_DEV_IDX_BIG] = {
        .name = "CPU_GROUP_BIG",
        .data = &((struct mod_clock_dev_config) {
            .driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_VPLL, 0),
            .api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_VPLL,
                                       MOD_CSS_CLOCK_API_TYPE_CLOCK),
        }),
    },
    [CLOCK_DEV_IDX_LITTLE] = {
        .name = "CPU_GROUP_LITTLE",
        .data = &((struct mod_clock_dev_config) {
            .driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_VPLL, 1),
            .api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_VPLL,
                                       MOD_CSS_CLOCK_API_TYPE_CLOCK),
        }),
    },
    [CLOCK_DEV_IDX_GPU] = {
        .name = "GPU",
        .data = &((struct mod_clock_dev_config) {
            .driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_VPLL, 2),
            .api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_VPLL,
                                       MOD_CSS_CLOCK_API_TYPE_CLOCK),
        }),
    },
    [CLOCK_DEV_IDX_VPU] = {
        .name = "VPU",
        .data = &((struct mod_clock_dev_config) {
            .driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_VPLL, 3),
            .api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_VPLL,
                                       MOD_CSS_CLOCK_API_TYPE_CLOCK),
        }),
    },
    [CLOCK_DEV_IDX_DPU] = {
        .name = "DPU",
        .data = &((struct mod_clock_dev_config) {
            .driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_VPLL, 4),
            .api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_VPLL,
                                       MOD_CSS_CLOCK_API_TYPE_CLOCK),
        }),
    },
    [CLOCK_DEV_IDX_PIXEL_0] = {
        .name = "PIXEL_0",
        .data = &((struct mod_clock_dev_config) {
            .driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_VPLL, 5),
            .api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_VPLL,
                                       MOD_SYSTEM_PLL_API_TYPE_DEFAULT),
        }),
    },
    [CLOCK_DEV_IDX_PIXEL_1] = {
        .name = "PIXEL_1",
        .data = &((struct mod_clock_dev_config) {
            .driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_VPLL, 6),
            .api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_VPLL,
                                       MOD_SYSTEM_PLL_API_TYPE_DEFAULT),
        }),
    },
    [CLOCK_DEV_IDX_COUNT] = { 0 }, /* Termination description. */
};

static const struct fwk_element *clock_get_dev_desc_table(fwk_id_t module_id)
{
    unsigned int i;
    struct mod_clock_dev_config *dev_config;

    /* Configure all clocks to respond to changes in SYSTOP power state */
    for (i = 0; i < CLOCK_DEV_IDX_COUNT; i++) {
        dev_config =
            (struct mod_clock_dev_config *)clock_dev_desc_table[i].data;
        dev_config->pd_source_id = FWK_ID_NONE;
    }
    return clock_dev_desc_table;
}

struct fwk_module_config config_clock = {
    .get_element_table = clock_get_dev_desc_table,
    .data = NULL,
};
