// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef ARM_SCMI_H
#define ARM_SCMI_H

#include <kernel/thread.h>
#include <spci.h>

void __thread_std_scmi_entry(struct thread_smc_args *args);

#ifdef CFG_WITH_SCMI
/* Handles a SCMI notification by calling SCMI server with message arguments */
void thread_std_scmi_entry(void);

int32_t spci_scmi_recv_escape(spci_msg_hdr_t *msg_hdr, struct thread_smc_args *args);

int32_t spci_scmi_send_escape(spci_msg_hdr_t *msg_hdr, struct thread_eret_args *args);

/* from libscmi: spci_get_buffer_ospm0() to get SCMI msg buffer */
void* spci_get_buffer_ospm0(void);

/* from libscmi: optee_init_scmi() initializes the framwork */
void optee_init_scmi(void);

/* from libscmi: optee_process_scmi() process a SCMI message process */
void optee_process_scmi(void);

/* from libscmi: raise an event in the SCMI framwork before calling optee_process_scmi() */
void spci_raise_event_ospm0(void);
#else
static inline void thread_std_scmi_entry(void)
{
}

/* Return not-a-scmi-message */
static inline int32_t spci_scmi_recv_escape(spci_msg_hdr_t *msg_hdr __unused,
					    struct thread_smc_args *args __unused)
{
	return 0;
}
/* Return not-a-scmi-message */
static inline int32_t spci_scmi_send_escape(spci_msg_hdr_t *msg_hdr __unused,
					    struct thread_eret_args *args __unused)
{
	return 0;
}

static inline void* spci_get_buffer_ospm0(void)
{
	return (void *)1;
}

static inline void optee_init_scmi(void)
{
}

static inline void optee_process_scmi(void)
{
}

static inline void spci_raise_event_ospm0(void)
{
}
#endif /*CFG_WITH_SCMI*/

#endif /*ARM_SCMI_H*/
