/*
 * Copyright (c) 2020, Linaro Limited
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
	[SCMI_CHANNEL_DEVICE_IDX_NS0] = SCMI_SERVICE_IDX_NS_CHANNEL0,
	[SCMI_CHANNEL_DEVICE_IDX_NS1] = SCMI_SERVICE_IDX_NS_CHANNEL1,
	[SCMI_CHANNEL_DEVICE_IDX_NS2] = SCMI_SERVICE_IDX_NS_CHANNEL2,
};

static const struct fwk_element mhu_element_table[] = {
    [SCMI_CHANNEL_DEVICE_IDX_NS0] = {
        .name = "SCMI non-secure to OP-TEE channel 0",
        .sub_element_count = 1,
        .data = (void *)&mhu_config[SCMI_CHANNEL_DEVICE_IDX_NS0],
    },
    [SCMI_CHANNEL_DEVICE_IDX_NS1] = {
        .name = "SCMI non-secure to OP-TEE channel 1",
        .sub_element_count = 1,
        .data = (void *)&mhu_config[SCMI_CHANNEL_DEVICE_IDX_NS1],
    },
    [SCMI_CHANNEL_DEVICE_IDX_NS2] = {
        .name = "SCMI non-secure to OP-TEE channel 2",
        .sub_element_count = 1,
        .data = (void *)&mhu_config[SCMI_CHANNEL_DEVICE_IDX_NS2],
    },
    [SCMI_CHANNEL_DEVICE_IDX_COUNT] = { 0 },
};

static const struct fwk_element *mhu_get_element_table(fwk_id_t module_id)
{
    return mhu_element_table;
}

struct fwk_module_config config_optee_mhu = {
    .elements = FWK_MODULE_DYNAMIC_ELEMENTS(mhu_get_element_table),
};


#define SCMI_PAYLOAD_SIZE       (128)

#define NSEC_SCMI_SHMEM0        CFG_STM32MP1_SCMI_SHM_BASE
#define NSEC_SCMI_SHMEM1        (CFG_STM32MP1_SCMI_SHM_BASE + 0x200)
#define NSEC_SCMI_SHMEM2        (CFG_STM32MP1_SCMI_SHM_BASE + 0x400)

static struct fwk_element smt_element_table[] = {
    [SCMI_SERVICE_IDX_NS_CHANNEL0] = {
        .name = "OSPM0",
        .data = &((struct mod_optee_smt_channel_config) {
            .type = MOD_OPTEE_SMT_CHANNEL_TYPE_SLAVE,
            .policies = MOD_OPTEE_SMT_POLICY_INIT_MAILBOX,
            .mailbox_address = (uintptr_t)NSEC_SCMI_SHMEM0,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                                                 SCMI_CHANNEL_DEVICE_IDX_NS0, 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_MHU, 0),
        })
    },
    [SCMI_SERVICE_IDX_NS_CHANNEL1] = {
        .name = "OSPM1",
        .data = &((struct mod_optee_smt_channel_config) {
            .type = MOD_OPTEE_SMT_CHANNEL_TYPE_SLAVE,
            .policies = MOD_OPTEE_SMT_POLICY_INIT_MAILBOX,
            .mailbox_address = (uintptr_t)NSEC_SCMI_SHMEM1,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                                                 SCMI_CHANNEL_DEVICE_IDX_NS1, 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_MHU, 0),
        })
    },
    [SCMI_SERVICE_IDX_NS_CHANNEL2] = {
        .name = "OSPM2",
        .data = &((struct mod_optee_smt_channel_config) {
            .type = MOD_OPTEE_SMT_CHANNEL_TYPE_SLAVE,
            .policies = MOD_OPTEE_SMT_POLICY_INIT_MAILBOX,
            .mailbox_address = (uintptr_t)NSEC_SCMI_SHMEM2,
            .mailbox_size = SCMI_PAYLOAD_SIZE,
            .driver_id = FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                                                 SCMI_CHANNEL_DEVICE_IDX_NS2, 0),
            .driver_api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_OPTEE_MHU, 0),
        })
    },
    [SCMI_SERVICE_IDX_COUNT] = { 0 },
};

static const struct fwk_element *smt_get_element_table(fwk_id_t module_id)
{
	unsigned int n = 0;

	fwk_assert(fwk_id_get_module_idx(module_id) ==
		   FWK_MODULE_IDX_OPTEE_SMT);

	for (n = 0; n < SCMI_SERVICE_IDX_COUNT; n++) {
		struct mod_optee_smt_channel_config *cfg;
		const void *data;
		vaddr_t shm_base;

		data = smt_element_table[n].data;
		cfg = (struct mod_optee_smt_channel_config *)data;
		shm_base = (vaddr_t)phys_to_virt(cfg->mailbox_address,
						 MEM_AREA_IO_NSEC);
		fwk_assert(shm_base);
		cfg->mailbox_address = shm_base;
	}

	return (const struct fwk_element *)smt_element_table;
}

struct fwk_module_config config_optee_smt = {
    .elements = FWK_MODULE_DYNAMIC_ELEMENTS(smt_get_element_table),
};
