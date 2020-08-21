/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *      Message Handling Unit (MHU) Device Driver.
 */

#include <stddef.h>
#include <stdint.h>
#include <fwk_id.h>
#include <fwk_interrupt.h>
#include <fwk_mm.h>
#include <fwk_macros.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <fwk_thread.h>
#include <fwk_host.h>
#include <fwk_status.h>
#include <mod_optee_mhu.h>
#include <mod_optee_smt.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(BUILD_OPTEE)
#include <mm/core_memprot.h>
#endif

struct mhu_smt_channel {
    fwk_id_t id;
    struct mod_optee_smt_driver_input_api *api;
};

/* MHU device context */
struct mhu_device_ctx {
    /* Number of slots (represented by sub-elements) */
    unsigned int slot_count;

    /* Mask of slots that are bound to an SMT channel */
    uint32_t bound_slots;

    /* Table of SMT channels bound to the device */
    struct mhu_smt_channel *smt_channel_table;
};

/* MHU context */
struct mhu_ctx {
    /* Table of device contexts */
    struct mhu_device_ctx *device_ctx_table;

    /* Number of devices in the device context table*/
    unsigned int device_count;
};

static struct mhu_ctx mhu_ctx;

void optee_mhu_signal_smt_message(fwk_id_t device_id, void *memory)
{
    struct mhu_device_ctx *device_ctx;
    struct mhu_smt_channel *smt_channel;
    unsigned int device_idx, slot_idx;

    device_idx = fwk_id_get_element_idx(device_id);

    if (device_idx >= mhu_ctx.device_count)
        return;

    device_ctx = &mhu_ctx.device_ctx_table[device_idx];

    slot_idx = fwk_id_get_sub_element_idx(device_id);

    if (slot_idx < device_ctx->bound_slots) {
        smt_channel = &device_ctx->smt_channel_table[slot_idx];
        smt_channel->api->signal_message(smt_channel->id, memory);
    }
}

int optee_mhu_get_devices_count(void)
{
    return mhu_ctx.device_count;
}

fwk_id_t optee_mhu_get_device(unsigned int id, void* mem, unsigned int size)
{
    int i;
    void *mailbox;
    unsigned int slot, device_index = 0;
    struct mhu_device_ctx *device_ctx;
    struct mhu_smt_channel *smt_channel;
    const fwk_id_t device_id_none = FWK_ID_NONE_INIT;
    fwk_id_t device_id = FWK_ID_NONE_INIT;

    FWK_HOST_PRINT("[MHU] optee_mhu_get_device id %x mbx %p size %u\n",
                   id, mem, size);

    for(device_index = 0; device_index < mhu_ctx.device_count; device_index++) {
        device_ctx = &mhu_ctx.device_ctx_table[device_index];

        /* There is 2 way to identify a channel:
         * - provide @a and size of the mailbox memory. In this case id is set to NULL.
         * - provide an agent identifier.
         */

        device_id = (fwk_id_t)FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                              device_index);

        if (id == device_id.value) {
            device_id = (fwk_id_t)FWK_ID_SUB_ELEMENT(FWK_MODULE_IDX_OPTEE_MHU,
                                 device_index, 0);
            return device_id;
        }

        /* If id is set, don't try to find matching memory @ */
        if (id != 0)
            continue;

        for (slot = 0; slot < device_ctx->slot_count; slot++) {
            smt_channel = &device_ctx->smt_channel_table[slot];
            mailbox = smt_channel->api->get_memory(smt_channel->id);

            FWK_HOST_PRINT("[MHU] device 0x%x channel %u mbx %p\n",
                           device_index, slot, mailbox);

            if (mailbox == mem) {
                device_id = (fwk_id_t)FWK_ID_SUB_ELEMENT_INIT(FWK_MODULE_IDX_OPTEE_MHU,
                                                              device_index, slot);

                FWK_HOST_PRINT("[MHU] found device %08x\n", device_id.value);

                return device_id;
            }
        }
    }

    return device_id_none;
}
/*
 * Mailbox module driver API
 */

/*
 * Provide a raise interrupt interface to the Mailbox driver
 * although this is not useful in case of SMC entry as we will return
 * to client side after returning
 */
static int raise_interrupt(fwk_id_t slot_id)
{
    /* There should be a message in the mailbox */
    return FWK_SUCCESS;
}

const struct mod_optee_smt_driver_api mhu_mod_smt_driver_api = {
    .raise_interrupt = raise_interrupt,
};

/*
 * Framework handlers
 */

static int mhu_init(fwk_id_t module_id, unsigned int device_count,
                    const void *unused)
{
    if (device_count == 0)
        return FWK_E_PARAM;

    mhu_ctx.device_ctx_table = fwk_mm_calloc(device_count,
                                             sizeof(*mhu_ctx.device_ctx_table));
    if (mhu_ctx.device_ctx_table == NULL)
        return FWK_E_NOMEM;

    mhu_ctx.device_count = device_count;

    return FWK_SUCCESS;
}

static int mhu_device_init(fwk_id_t device_id, unsigned int slot_count,
                           const void *data)
{
    unsigned int slot;
    struct mhu_device_ctx *device_ctx;
    struct mhu_smt_channel *smt_channel;

    device_ctx = &mhu_ctx.device_ctx_table[fwk_id_get_element_idx(device_id)];

    device_ctx->smt_channel_table = fwk_mm_calloc(
                                        slot_count,
                                        sizeof(*device_ctx->smt_channel_table));
    if (device_ctx->smt_channel_table == NULL)
        return FWK_E_NOMEM;

    for (slot = 0; slot < slot_count; slot++) {
        smt_channel = &device_ctx->smt_channel_table[slot];
        smt_channel->id = FWK_ID_ELEMENT(FWK_MODULE_IDX_OPTEE_SMT, *((unsigned int *)data));
    }

    device_ctx->slot_count = slot_count;

    /* TBF: Use PENDING to request the creation of a context */
    return FWK_PENDING;
}

static int mhu_bind(fwk_id_t id, unsigned int round)
{
    int status;
    struct mhu_device_ctx *device_ctx;
    unsigned int slot;
    struct mhu_smt_channel *smt_channel;

    if ((round == 1) && fwk_id_is_type(id, FWK_ID_TYPE_ELEMENT)) {
        device_ctx = &mhu_ctx.device_ctx_table[fwk_id_get_element_idx(id)];

        for (slot = 0; slot < device_ctx->slot_count; slot++) {
            smt_channel = &device_ctx->smt_channel_table[slot];

            status = fwk_module_bind(smt_channel->id,
                             FWK_ID_API(FWK_MODULE_IDX_OPTEE_SMT,
                                        MOD_OPTEE_SMT_API_IDX_DRIVER_INPUT),
                             &smt_channel->api);
            if (status != FWK_SUCCESS)
                return status;
        }
    }

    return FWK_SUCCESS;
}

static int mhu_process_bind_request(fwk_id_t source_id, fwk_id_t target_id,
                                    fwk_id_t api_id, const void **api)
{
    struct mhu_device_ctx *device_ctx;
    unsigned int slot;

    if (!fwk_id_is_type(target_id, FWK_ID_TYPE_SUB_ELEMENT))
        return FWK_E_ACCESS;

    device_ctx = &mhu_ctx.device_ctx_table[fwk_id_get_element_idx(target_id)];
    slot = fwk_id_get_sub_element_idx(target_id);

    if (device_ctx->bound_slots & (1 << slot))
        return FWK_E_ACCESS;

    device_ctx->smt_channel_table[slot].id = source_id;
    device_ctx->bound_slots |= 1 << slot;

    *api = &mhu_mod_smt_driver_api;

    return FWK_SUCCESS;
}

static int mhu_start(fwk_id_t id)
{
    return FWK_SUCCESS;
}

/* OPTEE_MHU module definition */
const struct fwk_module module_optee_mhu = {
    .name = "OPTEE_MHU",
    .type = FWK_MODULE_TYPE_DRIVER,
    .api_count = 1,
    .init = mhu_init,
    .element_init = mhu_device_init,
    .bind = mhu_bind,
    .start = mhu_start,
    .process_bind_request = mhu_process_bind_request,
};
