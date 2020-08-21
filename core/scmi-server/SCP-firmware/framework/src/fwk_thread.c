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

#include <inttypes.h>
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

/* States for put_event_and_wait */
enum wait_states {
    WAITING_FOR_EVENT = 0,
    WAITING_FOR_RESPONSE  = 1,
};

static struct __fwk_thread_ctx *thread_ctx[CFG_NUM_THREADS];

struct __fwk_thread_ctx *__fwk_thread_get_ctx(void)
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
        tmp = fwk_module_get_ctx(id)->thread_ctx;
    }

    /* Find an element or sub-element context */
    if (!tmp &&
            (fwk_id_is_type(id, FWK_ID_TYPE_ELEMENT) ||
             fwk_id_is_type(id, FWK_ID_TYPE_SUB_ELEMENT))) {
        tmp = fwk_module_get_element_ctx(id)->thread_ctx;
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

    ctx = __fwk_thread_get_ctx();

    fwk_interrupt_global_disable();
    allocated_event = FWK_LIST_GET(
        fwk_list_pop_head(&ctx->free_event_queue), struct fwk_event, slist_node);
    fwk_interrupt_global_enable();

    if (allocated_event == NULL) {
        FWK_LOG_CRIT(err_msg_func, FWK_E_NOMEM, __func__);
        fwk_unexpected();

        return NULL;
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
    bool is_wakeup_event = false;

    FWK_LOG_TRACE("[THR] Put event %08x src %08x dst %08x\n",
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

        /* Is this the event put_event_and_wait is waiting for ? */
        if (ctx->waiting_event_processing_completion &&
            (ctx->cookie == event->cookie))
            is_wakeup_event = true;
#else
        return FWK_E_PANIC;
#endif
    } else {
        allocated_event = duplicate_event(event);
        if (allocated_event == NULL)
            return FWK_E_NOMEM;
    }

    allocated_event->cookie = event->cookie = ctx->event_cookie_counter++;

    if (is_wakeup_event)
       ctx->cookie = event->cookie;

    if (fwk_interrupt_get_current(&interrupt) != FWK_SUCCESS)
        fwk_list_push_tail(&ctx->event_queue, &allocated_event->slist_node);
    else
        fwk_list_push_tail(&ctx->isr_event_queue, &allocated_event->slist_node);

    FWK_LOG_TRACE(
        "[FWK] Sent %" PRIu32 ": %s @ %s -> %s",
        event->cookie,
        FWK_ID_STR(event->id),
        FWK_ID_STR(event->source_id),
        FWK_ID_STR(event->target_id));

    return FWK_SUCCESS;
}

static void free_event(struct fwk_event *event)
{
    struct __fwk_thread_ctx *ctx = __fwk_thread_get_ctx();

    fwk_interrupt_global_disable();
    fwk_list_push_tail(&ctx->free_event_queue, &event->slist_node);
    fwk_interrupt_global_enable();
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
        "[FWK] Processing %" PRIu32 ": %s @ %s -> %s\n",
        event->cookie,
        FWK_ID_STR(event->id),
        FWK_ID_STR(event->source_id),
        FWK_ID_STR(event->target_id));

    module = fwk_module_get_ctx(event->target_id)->desc;
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
        if ((status != FWK_SUCCESS) && (status != FWK_PENDING)) {
            FWK_LOG_CRIT(
                "[FWK] Process event (%s: %s -> %s) (%d)\n",
                FWK_ID_STR(event->id),
                FWK_ID_STR(event->source_id),
                FWK_ID_STR(event->target_id), status);
        }
    }

    ctx->current_event = NULL;
    free_event(event);
}

static bool process_isr(struct __fwk_thread_ctx *ctx)
{
    struct fwk_event *isr_event;

    fwk_interrupt_global_disable();
    isr_event = FWK_LIST_GET(fwk_list_pop_head(&ctx->isr_event_queue),
                             struct fwk_event, slist_node);
    fwk_interrupt_global_enable();

    if (isr_event == NULL)
        return false;

    FWK_LOG_TRACE(
        "[FWK] Pulled ISR event (%s: %s -> %s)\n",
        FWK_ID_STR(isr_event->id),
        FWK_ID_STR(isr_event->source_id),
        FWK_ID_STR(isr_event->target_id));

    fwk_list_push_tail(&ctx->event_queue, &isr_event->slist_node);

    return true;
}

/*
 * Private interface functions
 */
#ifdef BUILD_OPTEE
int __fwk_thread_init(size_t event_count, fwk_id_t id)
#else
int __fwk_thread_init(size_t event_count)
#endif
{
    struct fwk_event *event_table, *event;
    struct __fwk_thread_ctx *ctx = __fwk_thread_get_ctx();

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
    struct __fwk_thread_ctx *ctx = __fwk_thread_get_ctx();

    for (;;) {
        while (!fwk_list_is_empty(&ctx->event_queue))
            process_next_event(ctx);

        if (process_isr(ctx))
            continue;

        fwk_log_unbuffer();
    }
}

void __fwk_run_event(void)
{
    struct __fwk_thread_ctx *ctx = __fwk_thread_get_ctx();

    for (;;) {
        while (!fwk_list_is_empty(&ctx->event_queue))
            process_next_event(ctx);

        if (fwk_list_is_empty(&ctx->isr_event_queue)) {
            fwk_log_unbuffer();
            return;
	}

       if (process_isr(ctx))
            continue;

        fwk_log_unbuffer();
    }
}

const struct fwk_event *__fwk_thread_get_current_event(void)
{
    struct __fwk_thread_ctx *ctx = __fwk_thread_get_ctx();

    return ctx->current_event;
}

#ifdef BUILD_HAS_NOTIFICATION
int __fwk_thread_put_notification(struct fwk_event *event)
{
    struct __fwk_thread_ctx *ctx = __fwk_thread_get_ctx();

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
    struct __fwk_thread_ctx *ctx = __fwk_thread_get_ctx();

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

    if (event->is_notification) {
        if (!fwk_module_is_valid_notification_id(event->id))
            goto error;
        if ((!event->is_response) || (event->response_requested))
            goto error;
        if (fwk_id_get_module_idx(event->target_id) !=
            fwk_id_get_module_idx(event->id))
             goto error;
    } else {
        if (!fwk_module_is_valid_event_id(event->id))
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
        }
    }

    return put_event(ctx, event);

error:
    FWK_LOG_CRIT(err_msg_func, status, __func__);
    return status;
}

int fwk_thread_put_event_and_wait(struct fwk_event *event,
    struct fwk_event *resp_event)
{
    const struct fwk_module *module;
    int (*process_event)(const struct fwk_event *event,
                         struct fwk_event *resp_event);
    struct fwk_event response_event;
    struct fwk_event *next_event;
    struct fwk_event *allocated_event;
    unsigned int interrupt;
    int status = FWK_E_PARAM;
    enum wait_states wait_state = WAITING_FOR_EVENT;
    struct __fwk_thread_ctx *ctx = __fwk_thread_get_ctx();

    if (!ctx->initialized) {
        status = FWK_E_INIT;
        goto error;
    }

    if ((event == NULL) || (resp_event == NULL))
        goto error;

    if (!fwk_module_is_valid_event_id(event->id))
        goto error;

    if (fwk_interrupt_get_current(&interrupt) == FWK_SUCCESS) {
        status = FWK_E_STATE;
        goto error;
    }

    if (ctx->current_event != NULL)
        event->source_id = ctx->current_event->target_id;
    else if (!fwk_module_is_valid_entity_id(event->source_id)) {
        FWK_LOG_ERR(
            "[FWK] deprecated put_event_and_wait (%s: %s -> %s)\n",
            FWK_ID_STR(event->id),
            FWK_ID_STR(event->source_id),
            FWK_ID_STR(event->target_id));
        goto error;
    }

    /* No support for nested put_event_and_wait calls */
    if (ctx->waiting_event_processing_completion) {
        status = FWK_E_BUSY;
        goto error;
    }
    ctx->waiting_event_processing_completion = true;
    ctx->previous_event = ctx->current_event;

    FWK_LOG_TRACE(
        "[FWK] deprecated put_event_and_wait (%s: %s -> %s)\n",
        FWK_ID_STR(event->id),
        FWK_ID_STR(event->source_id),
        FWK_ID_STR(event->target_id));

    event->is_response = false;
    event->is_delayed_response = false;
    event->response_requested = true;
    event->is_notification = false;

    status = put_event(ctx, event);
    if (status != FWK_SUCCESS)
        goto exit;

    ctx->cookie = event->cookie;

    for (;;) {

        if (fwk_list_is_empty(&ctx->event_queue)) {
            process_isr(ctx);
            continue;
        }

        ctx->current_event = next_event = FWK_LIST_GET(fwk_list_head(
            &ctx->event_queue), struct fwk_event, slist_node);

        if (next_event->cookie != ctx->cookie) {
            /*
            * Process any events waiting on the event_queue until
            * we get to the event from the waiting call.
            */
            process_next_event(ctx);
            continue;
        }

        /* This is either the original event or the response event */
        next_event = FWK_LIST_GET(
            fwk_list_pop_head(&ctx->event_queue), struct fwk_event, slist_node);

        if (wait_state == WAITING_FOR_EVENT) {
            module = fwk_module_get_ctx(next_event->target_id)->desc;
            process_event = module->process_event;

            response_event = *next_event;
            response_event.source_id = next_event->target_id;
            response_event.target_id = next_event->source_id;
            response_event.is_delayed_response = false;

            /* Execute the event handler */
            status = process_event(next_event, &response_event);
            if (status != FWK_SUCCESS)
                goto exit;

            /*
             * The response event goes onto the queue now
             * and we update the cookie to wait for the
             * response.
             */
            response_event.is_response = true;
            response_event.response_requested = false;
            if (!response_event.is_delayed_response) {
                status = put_event(ctx, &response_event);
                if (status != FWK_SUCCESS)
                    goto exit;
                ctx->cookie = response_event.cookie;
            } else {
#ifdef BUILD_HAS_NOTIFICATION
                allocated_event = duplicate_event(&response_event);
                if (allocated_event != NULL) {
                    fwk_list_push_head(
                        __fwk_thread_get_delayed_response_list(
                            response_event.source_id),
                            &allocated_event->slist_node);
                } else {
                    status = FWK_E_NOMEM;
                    goto exit;
                }
                ctx->cookie = allocated_event->cookie;
#else
                return FWK_E_PANIC;
#endif
            }

            wait_state = WAITING_FOR_RESPONSE;
            free_event(next_event);

            /*
             * Check for any interrupt events that might have been
             * queued while the event was being executed.
             */
            process_isr(ctx);
            continue;
        }

        if (wait_state == WAITING_FOR_RESPONSE) {
            /*
             * The response event has been received, return to
             * the caller.
             */
            memcpy(resp_event->params, next_event->params,
                sizeof(resp_event->params));
            free_event(next_event);
            status = FWK_SUCCESS;
            goto exit;
        }
    }

exit:
    ctx->current_event = ctx->previous_event;
    ctx->waiting_event_processing_completion = false;
    if (status == FWK_SUCCESS)
        return status;
error:
    FWK_LOG_CRIT(err_msg_func, status, __func__);
    return status;
}
