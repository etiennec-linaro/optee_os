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
#include <fwk_errno.h>
#include <fwk_id.h>
#include <fwk_interrupt.h>
#include <fwk_mm.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <fwk_host.h>
#include <mod_host_mailbox.h>
#include <spci_scmi.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <termios.h>

struct mhu_smt_channel {
    fwk_id_t id;
    struct mod_smt_driver_input_api *api;
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

void spci_raise_event_ospm0(void)
{
    struct mhu_device_ctx *device_ctx;
    unsigned int slot;
    struct mhu_smt_channel *smt_channel;

    device_ctx = &mhu_ctx.device_ctx_table[SPCI_DEVICE_IDX_NS_L];
	slot = 0;

	smt_channel = &device_ctx->smt_channel_table[slot];
	smt_channel->api->signal_message(smt_channel->id);
}

extern uint8_t scmi_ospm0_mb[];

void* spci_get_buffer_ospm0(void)
{
	return scmi_ospm0_mb;
}

/*
 * Mailbox module driver API
 */

/*
 * Provide a raise interrupt interface to the Mailbox driver
 * although this is not useful in case of SPCI as we will return
 * to client side after returning
 * Neverthless, use it for debugging purpose and dump the message content
 * before sending it back to client
 */
static int raise_interrupt(fwk_id_t slot_id)
{
    int status;
    struct mhu_device_ctx *device_ctx;
    unsigned int slot, i;
    struct mhu_smt_channel *smt_channel;
	struct mod_smt_memory *mailbox_address;
	size_t size;

	status = fwk_module_check_call(slot_id);
    if (status != FWK_SUCCESS)
        return status;

    device_ctx = &mhu_ctx.device_ctx_table[fwk_id_get_element_idx(slot_id)];
    slot = fwk_id_get_sub_element_idx(slot_id);
	smt_channel = &device_ctx->smt_channel_table[slot];
	mailbox_address = smt_channel->api->get_memory(smt_channel->id);

	FWK_HOST_PRINT("[SPCI] header  %08x\n", mailbox_address->message_header);

	size = mailbox_address->length - sizeof(mailbox_address->message_header);

	for(i=0; i < (size /  sizeof(mailbox_address->payload[0])) ; i++)
	{
			FWK_HOST_PRINT("[SPCI] payload %08x\n", mailbox_address->payload[i]);
	}

	return FWK_SUCCESS;
}

const struct mod_smt_driver_api mhu_mod_smt_driver_api = {
    .raise_interrupt = raise_interrupt,
};

/*
 * Framework handlers
 */

static int mhu_init(fwk_id_t module_id, unsigned int device_count, const void *unused)
{

    mhu_ctx.device_ctx_table = fwk_mm_calloc(device_count, sizeof(mhu_ctx.device_ctx_table[0]));
    if (mhu_ctx.device_ctx_table == NULL)
        return FWK_E_NOMEM;

    mhu_ctx.device_count = device_count;

    return FWK_SUCCESS;
}

static int mhu_device_init(fwk_id_t device_id, unsigned int slot_count, const void *data)
{
    unsigned int slot;
    struct mhu_device_ctx *device_ctx;
    struct mhu_smt_channel *smt_channel;

    device_ctx = &mhu_ctx.device_ctx_table[fwk_id_get_element_idx(device_id)];

    device_ctx->smt_channel_table = fwk_mm_calloc(slot_count, sizeof(device_ctx->smt_channel_table[0]));
	if (device_ctx->smt_channel_table == NULL)
		return FWK_E_NOMEM;

	for (slot = 0; slot < slot_count; slot++) {
		smt_channel = &device_ctx->smt_channel_table[slot];
		smt_channel->id = FWK_ID_ELEMENT(FWK_MODULE_IDX_HMBX, *((unsigned int *)data));
	}

    device_ctx->slot_count = slot_count;

    return FWK_SUCCESS;
}

static int mhu_bind(fwk_id_t id, unsigned int round)
{
    int status;
    unsigned int slot;
    struct mhu_device_ctx *device_ctx;
    struct mhu_smt_channel *smt_channel;

    if ((round == 1) && fwk_id_is_type(id, FWK_ID_TYPE_ELEMENT)) {
        device_ctx = &mhu_ctx.device_ctx_table[fwk_id_get_element_idx(id)];

		for (slot = 0; slot < device_ctx->slot_count; slot++) {
			smt_channel = &device_ctx->smt_channel_table[slot];
			status = fwk_module_bind(smt_channel->id,
					FWK_ID_API(FWK_MODULE_IDX_HMBX, MOD_SMT_API_IDX_DRIVER_INPUT),
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

/* SPCI module definition */
const struct fwk_module module_spci = {
    .name = "SPCI",
    .type = FWK_MODULE_TYPE_DRIVER,
    .api_count = 1,
    .init = mhu_init,
    .element_init = mhu_device_init,
    .bind = mhu_bind,
    .start = mhu_start,
    .process_bind_request = mhu_process_bind_request,
};

unsigned int spci_config[] = {
	[SPCI_DEVICE_IDX_S] = SPCI_SCMI_SERVICE_IDX_PSCI,
	[SPCI_DEVICE_IDX_NS_H] = SPCI_SCMI_SERVICE_IDX_OSPM_0,
	[SPCI_DEVICE_IDX_NS_L] = SPCI_SCMI_SERVICE_IDX_OSPM_1
};

static const struct fwk_element spci_element_table[] = {
    [SPCI_DEVICE_IDX_S] = {
        .name = "SPCI TEE",
        .sub_element_count = 1,
        .data = (void *)&spci_config[SPCI_DEVICE_IDX_S],
    },
    [SPCI_DEVICE_IDX_NS_H] = {
        .name = "SPCI OSPM0",
        .sub_element_count = 1,
        .data = (void *)&spci_config[SPCI_DEVICE_IDX_NS_H],
    },
    [SPCI_DEVICE_IDX_NS_L] = {
        .name = "SPCI OSPM1",
        .sub_element_count = 1,
        .data = (void *)&spci_config[SPCI_DEVICE_IDX_NS_L],
    },
    [SPCI_DEVICE_IDX_COUNT] = { 0 },
};

static const struct fwk_element *spci_get_element_table(fwk_id_t module_id)
{
    return spci_element_table;
}

struct fwk_module_config config_spci = {
    .get_element_table = spci_get_element_table,
};
