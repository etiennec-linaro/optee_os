/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2017, Linaro Limited
 */

#include <arm.h>
#include <arm64_macros.S>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <sm/teesmc_opteed.h>
#if CFG_WITH_SPCI
#include <spci.h>
#endif

FUNC thread_std_scmi_entry , :
	/* pass x0-x7 in a struct thread_smc_args */
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	mov	x0, sp

	/* Call the registered handler */
	bl	__thread_std_scmi_entry

	/*
	 * Load the returned x0-x3 into preserved registers and skip the
	 * "returned" x4-x7 since they will not be returned to normal
	 * world.
	 */
	load_xregs sp, THREAD_SMC_ARGS_X0, 20, 23
	add	sp, sp, #THREAD_SMC_ARGS_SIZE

	/* Mask all maskable exceptions before switching to temporary stack */
	msr	daifset, #DAIFBIT_ALL
	bl	thread_get_tmp_sp
	mov	sp, x0

	bl	thread_state_free

#if CFG_WITH_SPCI
	/* TODO: Passing stale values in x4-x7 back to normal world*/
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	store_xregs sp, THREAD_SMC_ARGS_X0, 20, 23
	mov	x0, sp
	bl	spci_msg_send_prepare
	/* Unwind stack completely */
	add	sp, sp, #THREAD_SMC_ARGS_SIZE
	/* Call SPCI_MSG_SEND_RECV with attributes in x0 */
	b	spci_msg_send_recv_invoke
#else
	ldr	x0, =TEESMC_OPTEED_RETURN_CALL_DONE
	mov	x1, x20
	mov	x2, x21
	mov	x3, x22
	mov	x4, x23
	smc	#0
	b	.	/* SMC should not return */
#endif
END_FUNC thread_std_scmi_entry

