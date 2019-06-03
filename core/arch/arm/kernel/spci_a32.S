/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Arm Limited
 */

#include <platform_config.h>

#include <arm32_macros.S>
#include <arm.h>
#include <asm.S>
#include <keep.h>
#include <generated/asm-defines.h>
#include <spci.h>

#define MSG_RECV_ATTRIBUTES	((SPCI_MSG_RECV_ATTRS_BLK & \
					SPCI_MSG_RECV_ATTRS_MASK) << \
						SPCI_MSG_RECV_ATTRS_SHIFT)

FUNC spci_msg_recv_invoke , :
	/* Block on MSG_RECV */
	mov	r1, #MSG_RECV_ATTRIBUTES
	mov_imm	r0, SPCI_MSG_RECV
	b	spci_msg_loop
END_FUNC spci_msg_recv_invoke

FUNC spci_msg_send_recv_invoke , :
	/* Move Attributes to x1 */
	mov	r1, r0
	mov_imm	r0, SPCI_MSG_SEND_RECV
END_FUNC spci_msg_send_recv_invoke

FUNC spci_msg_loop , :
	/* Invoke SMC with caller provided parameters */
	mov	r7, #0		/* TODO: Source and target ids are 0 */
	smc	#0

	/*
	 * Make space for parameters and function pointer to handle this
	 * message
	 */
	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
#if 1
//	sub	sp, sp, #(THREAD_SMC_ARGS_SIZE - THREAD_SMC_ARGS_X0)
	stm	sp, {r0-r7}
//	sub	sp, sp, #THREAD_SMC_ARGS_X0
#else
//	sub	sp, sp, #THREAD_SMC_ARGS_SIZE
	str	r0, [sp, #THREAD_SMC_ARGS_X0]
	str	r1, [sp, #(THREAD_SMC_ARGS_X0 + 4)]
	str	r2, [sp, #(THREAD_SMC_ARGS_X0 + 8)]
	str	r3, [sp, #(THREAD_SMC_ARGS_X0 + 12)]
	str	r4, [sp, #(THREAD_SMC_ARGS_X0 + 16)]
	str	r5, [sp, #(THREAD_SMC_ARGS_X0 + 20)]
	str	r6, [sp, #(THREAD_SMC_ARGS_X0 + 24)]
	str	r7, [sp, #(THREAD_SMC_ARGS_X0 + 28)]
#endif
	mov	r1, sp

	/*
	 * Message receive has completed. Parse message in RX and decide next
	 * action
	 */
	bl	spci_msg_recv

	/*
         * TODO: x8 can be used since without S-EL2, OP-TEE will always exit
	 * through a SMC in which case this is a scratch register
	 */
	mov	r8, r0
#if 1
//	add	sp, sp, #THREAD_SMC_ARGS_X0
	ldm	sp, {r0-r7}
//	add	sp, sp, #(THREAD_SMC_ARGS_SIZE - THREAD_SMC_ARGS_X0)
#else
	ldr	r0, [sp, #THREAD_SMC_ARGS_X0]
	ldr	r1, [sp, #(THREAD_SMC_ARGS_X0 + 4)]
	ldr	r2, [sp, #(THREAD_SMC_ARGS_X0 + 8)]
	ldr	r3, [sp, #(THREAD_SMC_ARGS_X0 + 12)]
	ldr	r4, [sp, #(THREAD_SMC_ARGS_X0 + 16)]
	ldr	r5, [sp, #(THREAD_SMC_ARGS_X0 + 20)]
	ldr	r6, [sp, #(THREAD_SMC_ARGS_X0 + 24)]
	ldr	r7, [sp, #(THREAD_SMC_ARGS_X0 + 28)]
#endif
	add	sp, sp, #THREAD_SMC_ARGS_SIZE
//#endif
	bx	r8
END_FUNC spci_msg_loop
