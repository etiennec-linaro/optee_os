/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2019, Linaro Limited
 */

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <sm/teesmc_opteed.h>
#ifdef CFG_WITH_SPCI
#include <spci.h>
#endif

FUNC thread_std_scmi_entry , :
	/* pass r0-r7 in a struct thread_smc_args */
	sub	sp, sp, #(THREAD_SMC_ARGS_SIZE - THREAD_SMC_ARGS_X0)
	stm	sp, {r0-r7}
	sub	sp, sp, #THREAD_SMC_ARGS_X0

	/* Call the registered handler */
	mov	r0, sp
	bl	__thread_std_scmi_entry

	/*
	 * Load the returned r0-r3 into preserved registers and skip the
	 * "returned" r4-r7 since they will not be returned to normal
	 * world.
	 */
	add	sp, sp, #THREAD_SMC_ARGS_X0
	ldm	sp, {r0-r3}
	add	sp, sp, #(THREAD_SMC_ARGS_SIZE - THREAD_SMC_ARGS_X0)

	/* Disable interrupts before switching to temporary stack */
	cpsid	aif
	bl	thread_get_tmp_sp
	mov	sp, r0

	bl	thread_state_free

#ifdef CFG_WITH_SPCI
	/* TODO: Passing stale values in r4-r7 back to normal world*/
	sub	sp, sp, #(THREAD_SMC_ARGS_SIZE - THREAD_SMC_ARGS_X0)
	stm	sp, {r4-r7}
	add	sp, sp, #THREAD_SMC_ARGS_X0
	
	mov	r0, sp
	bl	spci_msg_send_prepare
	/* Unwind stack completely */
	add	sp, sp, #THREAD_SMC_ARGS_SIZE
	/* Call SPCI_MSG_SEND_RECV with attributes in r0 */
	b	spci_msg_send_recv_invoke
#else
	ldr	r0, =TEESMC_OPTEED_RETURN_CALL_DONE
	mov	r1, r4
	mov	r2, r5
	mov	r3, r6
	mov	r4, r7
	smc	#0
	b	.	/* SMC should not return */
#endif
END_FUNC thread_std_scmi_entry

