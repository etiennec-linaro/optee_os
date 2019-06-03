/*
 * spci.c
 *
 * Copyright (C) ST-Ericsson SA 2019
 * Author: YOUR NAME <> for ST-Ericsson.
 * License terms:  GNU General Public License (GPL), version 2
 */

#ifndef _SM_SPCI_H

#include <kernel/thread.h>
#include <sm/sm.h>
#include <spci.h>
#include <stdint.h>

spci_buf_t *get_spci_init_msg(void);

enum sm_handler_ret tee_spci_handler(struct thread_smc_args *args,
				     struct sm_nsec_ctx *nsec);

#endif /*_SM_SPCI_H*/
