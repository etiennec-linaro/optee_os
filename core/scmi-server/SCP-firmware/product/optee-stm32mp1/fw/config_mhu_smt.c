/*
 * Arm SCP/MCP Software
 * Copyright (c) 2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_optee_mhu.h>
#include <mod_optee_smt.h>
#include <scmi_agents.h>

#if BUILD_OPTEE
#include <mm/core_memprot.h>
#endif

unsigned int mhu_config[] = {
	[SCMI_CHANNEL_DEVICE_IDX_NS] = SCMI_SERVICE_IDX_NS_CHANNEL,
};

static const struct fwk_element mhu_element_table[] = {
    [SCMI_CHANNEL_DEVICE_IDX_NS] = {
        .name = "SCMI channel for OP-TEE",
        .sub_element_count = 1,
        .data = (void *)&mhu_config[SCMI_CHANNEL_DEVICE_IDX_NS],
    },
    [SCMI_CHANNEL_DEVICE_IDX_COUNT] = { 0 },
};

static const struct fwk_element *mhu_get_element_table(fwk_id_t module_id)
{
    return mhu_element_table;
}

struct fwk_module_config config_optee_mhu = {
    .get_element_table = mhu_get_element_table,
};


#define SCMI_PAYLOAD_SIZE       (128)

uint8_t scmi_psci_mb[SCMI_PAYLOAD_SIZE];
uint8_t *scmi_ospm0_mb = (void *)(CFG_SHMEM_START + CFG_SHMEM_SIZE);
uint8_t scmi_ospm1_mb[SCMI_PAYLOAD_SIZE];

static struct fwk_element smt_element_table[] = {
    [SCMI_SERVICE_IDX_NS_CHANNEL] = {
        .name = "OSPM0",
        .data = &((struct mod_optee_smt_channel_config) {
            .type = MOD_OPTEE_SMT_CHANNEL_TYPE_SLAVE,
            .policies = MOD_OPTEE_SMT_POLICY_INIT_MAILBOX,
            .mailbox_address = (uintptr_t)(CFG_SHMEM_START + CFG_SHMEM_SIZE),
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                                                 SCMI_CHANNEL_DEVICE_IDX_NS, 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_MHU, 0),
        })
    },
    [SCMI_SERVICE_IDX_COUNT] = { 0 },
};

static const struct fwk_element *smt_get_element_table(fwk_id_t module_id)
{
	const void *data = NULL;
	struct mod_optee_smt_channel_config *cfg = NULL;

	/* Set virtual address for mailbox buffers */
	data = smt_element_table[SCMI_SERVICE_IDX_NS_CHANNEL].data;
	cfg = (struct mod_optee_smt_channel_config *)data;

	cfg->mailbox_address = (vaddr_t)phys_to_virt(cfg->mailbox_address,
						     MEM_AREA_IO_NSEC);

	return (const struct fwk_element *)smt_element_table;
}

struct fwk_module_config config_optee_smt = {
    .get_element_table = smt_get_element_table,
};

