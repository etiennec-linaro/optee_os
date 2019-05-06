/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016-2018, STMicroelectronics
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef __STM32MP1_SMC_H__
#define __STM32MP1_SMC_H__

/*
 * SIP Functions
 */
#define STM32_SIP_SVC_VERSION_MAJOR		0x0
#define STM32_SIP_SVC_VERSION_MINOR		0x1

/* SIP service generic return codes */
#define STM32_SIP_OK				0x0
#define STM32_SIP_NOT_SUPPORTED			0xffffffffU
#define STM32_SIP_FAILED			0xfffffffeU
#define STM32_SIP_INVALID_PARAMS		0xfffffffdU

/*
 * SMC function IDs for STM32 Service queries
 * STM32 SMC services use the space between 0x82000000 and 0x8200FFFF
 * like this is defined in SMC calling Convention by ARM
 * for SiP (Silicon Partner)
 * http://infocenter.arm.com/help/topic/com.arm.doc.den0028a/index.html
 */

/*
 * SIP function STM32_SIP_FUNC_CALL_COUNT
 *
 * Argument a0: (input) SMCC ID
 *		(output) dummy value 0
 */
#define STM32_SIP_FUNC_CALL_COUNT		0xff00

/*
 * SIP function STM32_SIP_FUNC_UID
 *
 * Argument a0: (input) SMCC ID
 *		(output) Lowest 32bit of the stm32mp1 SIP service UUID
 * Argument a1: (output) Next 32bit of the stm32mp1 SIP service UUID
 * Argument a2: (output) Next 32bit of the stm32mp1 SIP service UUID
 * Argument a3: (output) Last 32bit of the stm32mp1 SIP service UUID
 */
#define STM32_SIP_FUNC_UID			0xff01

/*
 * SIP function STM32_SIP_FUNC_VERSION
 *
 * Argument a0: (input) SMCC ID
 *		(output) STM32 SIP service major
 * Argument a1: (output) STM32 SIP service minor
 */
#define STM32_SIP_FUNC_VERSION			0xff03

/*
 * OEM Functions
 */
#define STM32_OEM_SVC_VERSION_MAJOR		0x0
#define STM32_OEM_SVC_VERSION_MINOR		0x1

/* OEM service generic return codes */
#define STM32_OEM_OK				0x0
#define STM32_OEM_NOT_SUPPORTED			0xffffffffU
#define STM32_OEM_FAILED			0xfffffffeU
#define STM32_OEM_INVALID_PARAMS		0xfffffffdU

#endif /* __STM32MP1_SMC_H__*/
