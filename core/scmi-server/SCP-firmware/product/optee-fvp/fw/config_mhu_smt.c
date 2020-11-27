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

#if defined(BUILD_OPTEE)
#include <mm/core_memprot.h>
#endif

unsigned int mhu_config[] = {
	[SCMI_CHANNEL_DEVICE_IDX_PSCI] = SCMI_SERVICE_IDX_PSCI,
	[SCMI_CHANNEL_DEVICE_IDX_OSPM_0] = SCMI_SERVICE_IDX_OSPM_0,
	[SCMI_CHANNEL_DEVICE_IDX_OSPM_1] = SCMI_SERVICE_IDX_OSPM_1,
};

static const struct fwk_element mhu_element_table[] = {
    [SCMI_CHANNEL_DEVICE_IDX_PSCI] = {
        .name = "SCMI channel for OP-TEE PSCI wrap",
        .sub_element_count = 1,
        .data = (void *)&mhu_config[SCMI_CHANNEL_DEVICE_IDX_PSCI],
    },
    [SCMI_CHANNEL_DEVICE_IDX_OSPM_0] = {
        .name = "SCMI channel for OP-TEE OSPM #0",
        .sub_element_count = 1,
        .data = (void *)&mhu_config[SCMI_CHANNEL_DEVICE_IDX_OSPM_0],
    },
    [SCMI_CHANNEL_DEVICE_IDX_OSPM_1] = {
        .name = "SCMI channel for OP-TEE OSPM #1",
        .sub_element_count = 1,
        .data = (void *)&mhu_config[SCMI_CHANNEL_DEVICE_IDX_OSPM_1],
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

#define SCMI_SHM_BASE		CFG_FVP_SCMI_SHM_BASE

#define OSPM_0_SHM_BASE		SCMI_SHM_BASE
#define OSPM_1_SHM_BASE		(SCMI_SHM_BASE + SCMI_PAYLOAD_SIZE)
#define PSCI_SHM_BASE		(SCMI_SHM_BASE + 2 * SCMI_PAYLOAD_SIZE)

static struct fwk_element smt_element_table[] = {
    [SCMI_SERVICE_IDX_PSCI] = {
        .name = "PSCI",
        .data = &((struct mod_optee_smt_channel_config) {
            .type = MOD_OPTEE_SMT_CHANNEL_TYPE_SLAVE,
            .policies = MOD_OPTEE_SMT_POLICY_INIT_MAILBOX,
            .mailbox_pa = PSCI_SHM_BASE,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                                                 SCMI_CHANNEL_DEVICE_IDX_PSCI,
						 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_MHU, 0),
        })
    },
    [SCMI_SERVICE_IDX_OSPM_0] = {
        .name = "OSPM0",
        .data = &((struct mod_optee_smt_channel_config) {
            .type = MOD_OPTEE_SMT_CHANNEL_TYPE_SLAVE,
            .policies = MOD_OPTEE_SMT_POLICY_INIT_MAILBOX,
            .mailbox_pa = OSPM_0_SHM_BASE,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                                                 SCMI_CHANNEL_DEVICE_IDX_OSPM_0,
						 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_MHU, 0),
        })
    },
    [SCMI_SERVICE_IDX_OSPM_1] = {
        .name = "OSPM1",
        .data = &((struct mod_optee_smt_channel_config) {
            .type = MOD_OPTEE_SMT_CHANNEL_TYPE_SLAVE,
            .policies = MOD_OPTEE_SMT_POLICY_INIT_MAILBOX,
            .mailbox_pa = OSPM_1_SHM_BASE,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                                                 SCMI_CHANNEL_DEVICE_IDX_OSPM_1,
						 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_MHU, 0),
        })
    },
    [SCMI_SERVICE_IDX_COUNT] = { 0 },
};

static const struct fwk_element *smt_get_element_table(fwk_id_t module_id)
{
	size_t n;

	/* All shared memory is mapped MEM_AREA_IO_NSEC */
	for (n = 0; n < SCMI_SERVICE_IDX_COUNT; n++) {
		struct mod_optee_smt_channel_config *cfg = NULL;
		void *va = NULL;

		cfg = (void *)smt_element_table[n].data;
		if (cfg->mailbox_pa && !cfg->mailbox_address) {
			va = phys_to_virt(cfg->mailbox_pa, MEM_AREA_NSEC_SHM);
			cfg->mailbox_address = (vaddr_t)va;
		}
	}

	return (const struct fwk_element *)smt_element_table;
}

struct fwk_module_config config_optee_smt = {
    .get_element_table = smt_get_element_table,
};
