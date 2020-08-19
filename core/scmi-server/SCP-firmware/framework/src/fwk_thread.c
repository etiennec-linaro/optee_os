/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *     Single-thread facilities.
 */

#include <internal/fwk_module.h>
#include <internal/fwk_single_thread.h>
#include <internal/fwk_thread.h>
#include <internal/fwk_thread_delayed_resp.h>

#include <fwk_assert.h>
#include <fwk_event.h>
#include <fwk_id.h>
#include <fwk_interrupt.h>
#include <fwk_list.h>
#include <fwk_log.h>
#include <fwk_mm.h>
#include <fwk_module.h>
#include <fwk_noreturn.h>
#include <fwk_slist.h>
#include <fwk_status.h>
#include <fwk_thread.h>

#include <stdbool.h>
#include <string.h>
#include <kernel/thread.h>

static struct __fwk_thread_ctx global_ctx;

#if defined(BUILD_OPTEE)
#include <compiler.h>
#else
#define __maybe_unused
#endif /* BUILD_OPTEE */

static const char __maybe_unused err_msg_line[] = "[FWK] Error %d in %s @%d";
static const char __maybe_unused err_msg_func[] = "[FWK] Error %d in %s";

static struct __fwk_thread_ctx *thread_ctx[CFG_NUM_THREADS];

static struct __fwk_thread_ctx *fwk_get_thread_ctx(void)
{
    struct  __fwk_thread_ctx *tmp;
    int thread_id = thread_get_id();

    return thread_ctx[thread_id];
}

void fwk_set_thread_ctx(fwk_id_t id)
{
    struct  __fwk_thread_ctx *tmp = NULL;
    int thread_id = thread_get_id();

    /* Find a thread context */
    if (fwk_id_is_type(id, FWK_ID_TYPE_MODULE)) {
        tmp = __fwk_module_get_ctx(id)->thread_ctx;
    }

    /* Find an element or sub-element context */
    if (!tmp &&
            (fwk_id_is_type(id, FWK_ID_TYPE_ELEMENT) ||
             fwk_id_is_type(id, FWK_ID_TYPE_SUB_ELEMENT))) {
        tmp = __fwk_module_get_element_ctx(id)->thread_ctx;
    }

    /* Use global one is nothig else */
    if (!tmp)
        tmp = &global_ctx;

    /* Save thread context */
    thread_ctx[thread_id] = tmp;
}

/*
 * Static functions
 */

/*
 * Duplicate an event.
 *
 * \param event Pointer to the event to duplicate.
 *
 * \pre \p event must not be NULL
 *
 * \return The pointer to the duplicated event, NULL if the allocation to
 *      duplicate the event failed.
 */
static struct fwk_event *duplicate_event(struct fwk_event *event)
{
    struct fwk_event *allocated_event = NULL;
    struct __fwk_thread_ctx *ctx;

    fwk_assert(event != NULL);

    ctx = fwk_get_thread_ctx();

    fwk_interrupt_global_disable();
    allocated_event = FWK_LIST_GET(
        fwk_list_pop_head(&ctx->free_event_queue), struct fwk_event, slist_node);
    fwk_interrupt_global_enable();

    if (allocated_event == NULL) {
        FWK_LOG_CRIT(err_msg_func, FWK_E_NOMEM, __func__);
        fwk_assert(false);
    }

    *allocated_event = *event;
    allocated_event->slist_node = (struct fwk_slist_node){ 0 };

    return allocated_event;
}

static int put_event(struct __fwk_thread_ctx *ctx,
                     struct fwk_event *event)
{
    struct fwk_event *allocated_event;
    unsigned int interrupt;

    FWK_LOG_INFO("[THR] Put event %08x src %08x dst %08x\n",
		 event->id.value, event->source_id.value,
		 event->target_id.value);

    if (event->is_delayed_response) {
#ifdef BUILD_HAS_NOTIFICATION
        allocated_event = __fwk_thread_search_delayed_response(
            event->source_id, event->cookie);
        if (allocated_event == NULL) {
            FWK_LOG_CRIT(err_msg_func, FWK_E_NOMEM, __func__);
            return FWK_E_PARAM;
        }

        fwk_list_remove(
            __fwk_thread_get_delayed_response_list(event->source_id),
            &allocated_event->slist_node);

        memcpy(
            allocated_event->params,
            event->params,
            sizeof(allocated_event->params));
#else
        return FWK_E_PANIC;
#endif
    } else {
        allocated_event = duplicate_event(event);
        if (allocated_event == NULL)
            return FWK_E_NOMEM;
    }

    allocated_event->cookie = event->cookie = ctx->event_cookie_counter++;


    if (fwk_interrupt_get_current(&interrupt) != FWK_SUCCESS)
        fwk_list_push_tail(&ctx->event_queue, &allocated_event->slist_node);
    else
        fwk_list_push_tail(&ctx->isr_event_queue, &allocated_event->slist_node);

    return FWK_SUCCESS;
}

static void process_next_event(struct __fwk_thread_ctx *ctx)
{
    int status;
    struct fwk_event *event, *allocated_event, async_response_event = { 0 };
    const struct fwk_module *module;
    int (*process_event)(const struct fwk_event *event,
                         struct fwk_event *resp_event);

    ctx->current_event = event = FWK_LIST_GET(
        fwk_list_pop_head(&ctx->event_queue), struct fwk_event, slist_node);

    FWK_LOG_TRACE(
        "[FWK] Get event (%s: %s -> %s)\n",
        FWK_ID_STR(event->id),
        FWK_ID_STR(event->source_id),
        FWK_ID_STR(event->target_id));

    module = __fwk_module_get_ctx(event->target_id)->desc;
    process_event = event->is_notification ? module->process_notification :
                    module->process_event;

    if (event->response_requested) {
        async_response_event = *event;
        async_response_event.source_id = event->target_id;
        async_response_event.target_id = event->source_id;
        async_response_event.is_delayed_response = false;

        status = process_event(event, &async_response_event);
        if (status != FWK_SUCCESS)
            FWK_LOG_CRIT(err_msg_line, status, __func__, __LINE__);

        async_response_event.is_response = true;
        async_response_event.response_requested = false;
        if (!async_response_event.is_delayed_response)
            put_event(ctx, &async_response_event);
        else {
#ifdef BUILD_HAS_NOTIFICATION
            allocated_event = duplicate_event(&async_response_event);
            if (allocated_event != NULL) {
                fwk_list_push_tail(
                    __fwk_thread_get_delayed_response_list(
                        async_response_event.source_id),
                    &allocated_event->slist_node);
            }
#else
            FWK_LOG_CRIT(err_msg_line, status, __func__, __LINE__);
#endif
        }
    } else {
        status = process_event(event, &async_response_event);
        if (status != FWK_SUCCESS)
            FWK_LOG_CRIT(err_msg_line, status, __func__, __LINE__);
    }

    ctx->current_event = NULL;

    fwk_interrupt_global_disable();
    fwk_list_push_tail(&ctx->free_event_queue, &event->slist_node);
    fwk_interrupt_global_enable();

    return;
}

static void process_isr(struct __fwk_thread_ctx *ctx)
{
    struct fwk_event *isr_event;

    fwk_interrupt_global_disable();
    isr_event = FWK_LIST_GET(fwk_list_pop_head(&ctx->isr_event_queue),
                             struct fwk_event, slist_node);
    fwk_interrupt_global_enable();

    FWK_LOG_TRACE(
        "[FWK] Get ISR event (%s: %s -> %s)\n",
        FWK_ID_STR(isr_event->id),
        FWK_ID_STR(isr_event->source_id),
        FWK_ID_STR(isr_event->target_id));

    fwk_list_push_tail(&ctx->event_queue, &isr_event->slist_node);
}

/*
 * Private interface functions
 */

int __fwk_thread_init(size_t event_count, fwk_id_t id)
{
    struct fwk_event *event_table, *event;
    struct __fwk_thread_ctx *ctx;

    ctx = fwk_get_thread_ctx();

    event_table = fwk_mm_calloc(event_count, sizeof(struct fwk_event));

    /* All the event structures are free to be used. */
    fwk_list_init(&ctx->free_event_queue);
    fwk_list_init(&ctx->event_queue);
    fwk_list_init(&ctx->isr_event_queue);

    for (event = event_table;
         event < (event_table + event_count);
         event++)
        fwk_list_push_tail(&ctx->free_event_queue, &event->slist_node);

    ctx->initialized = true;

    return FWK_SUCCESS;
}

noreturn void __fwk_thread_run(void)
{
    struct __fwk_thread_ctx *ctx;

    ctx = fwk_get_thread_ctx();

    for (;;) {
        while (!fwk_list_is_empty(&ctx->event_queue))
            process_next_event(ctx);

        while (fwk_list_is_empty(&ctx->isr_event_queue)) {
            fwk_log_unbuffer();

            continue;
        }

        process_isr(ctx);
    }
}

void __fwk_run_event(void)
{
    struct __fwk_thread_ctx *ctx;

    ctx = fwk_get_thread_ctx();

    for (;;) {
        while (!fwk_list_is_empty(&ctx->event_queue))
            process_next_event(ctx);

        if (fwk_list_is_empty(&ctx->isr_event_queue)) {
            fwk_log_unbuffer();
            return;
	}

        process_isr(ctx);
    }
}

struct __fwk_thread_ctx *__fwk_thread_get_ctx(void)
{
    return fwk_get_thread_ctx();
}

const struct fwk_event *__fwk_thread_get_current_event(void)
{
    struct __fwk_thread_ctx *ctx;

    ctx = fwk_get_thread_ctx();

    return ctx->current_event;
}

#ifdef BUILD_HAS_NOTIFICATION
int __fwk_thread_put_notification(struct fwk_event *event)
{
    struct __fwk_thread_ctx *ctx;

    ctx = fwk_get_thread_ctx();

    event->is_response = false;
    event->is_notification = true;

    return put_event(ctx, event);
}
#endif

/*
 * Public interface functions
 */

int fwk_thread_put_event(struct fwk_event *event)
{
    int status = FWK_E_PARAM;
    unsigned int interrupt;
    struct __fwk_thread_ctx *ctx;

    ctx = fwk_get_thread_ctx();

    if (!ctx->initialized) {
        status = FWK_E_INIT;
        goto error;
    }

    if (event == NULL)
        goto error;

    if ((fwk_interrupt_get_current(&interrupt) != FWK_SUCCESS) &&
        (ctx->current_event != NULL))
        event->source_id = ctx->current_event->target_id;
    else if (!fwk_module_is_valid_entity_id(event->source_id))
        goto error;

    if (!fwk_module_is_valid_entity_id(event->target_id) ||
        !fwk_module_is_valid_event_id(event->id))
        goto error;

    if (event->is_response) {
        if (fwk_id_get_module_idx(event->source_id) !=
            fwk_id_get_module_idx(event->id))
            goto error;
        if (event->response_requested)
            goto error;
    } else {
        if (fwk_id_get_module_idx(event->target_id) !=
            fwk_id_get_module_idx(event->id))
             goto error;
        if (event->is_notification)
            goto error;
    }

    return put_event(ctx, event);

error:
    FWK_LOG_CRIT(err_msg_func, status, __func__);
    return status;
}
