/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#ifndef __RCC_SVC_H__
#define __RCC_SVC_H__

#include <stm32mp1_smc.h>

#ifdef CFG_STM32_RCC_SIP
uint32_t rcc_scv_handler(uint32_t x1, uint32_t x2, uint32_t x3);
#else
static inline uint32_t rcc_scv_handler(uint32_t x1 __unused,
				       uint32_t x2 __unused,
				       uint32_t x3 __unused)
{
	return STM32_SIP_NOT_SUPPORTED;
}
#endif

#endif /*__RCC_SVC_H__*/
