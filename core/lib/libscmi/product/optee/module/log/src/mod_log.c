/*
 * Arm SCP/MCP Software
 * Copyright (c) 2017-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_element.h>
#include <fwk_errno.h>
#include <fwk_module.h>
#include <mod_log.h>

static int log_init(fwk_id_t id, unsigned int elt_count, const void *data)
{
    return FWK_SUCCESS;
}

static int log_bind(fwk_id_t id, unsigned int round)
{
    return FWK_SUCCESS;
}

static int log_process_bind_request(fwk_id_t requester_id, fwk_id_t id,
				    fwk_id_t api_id, const void **api)
{
    /* Framwork expects a non null value */
    *api = (void *)1;

    return FWK_SUCCESS;
}

/* Module descriptor */
const struct fwk_module module_log = {
    .name = "Log",
    .type = FWK_MODULE_TYPE_HAL,
    .api_count = 1,
    .init = log_init,
    .bind = log_bind,
    .process_bind_request = log_process_bind_request,
};

/* Module configuration data */
const struct fwk_module_config config_log = { 0 };
