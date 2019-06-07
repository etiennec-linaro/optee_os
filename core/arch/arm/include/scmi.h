/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2019, Arm Limited. All rights reserved.
 */
#ifndef SCMI_H
#define SCMI_H

#include <kernel/thread.h>
#include <spci.h>

void __thread_std_scmi_entry(struct thread_smc_args *args);

/* Handles a SCMI notification by calling SCMI server with message arguments */
void thread_std_scmi_entry(void);

int32_t spci_scmi_recv_escape(spci_msg_hdr_t *msg_hdr, struct thread_smc_args *args);

int32_t spci_scmi_send_escape(spci_msg_hdr_t *msg_hdr, struct thread_eret_args *args);

#endif /* SCMI_H */
