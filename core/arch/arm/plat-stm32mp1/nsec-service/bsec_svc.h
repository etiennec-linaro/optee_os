/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016-2018, STMicroelectronics
 */

#ifndef __STM32MP1_BSEC_SVC_H__
#define __STM32MP1_BSEC_SVC_H__

#include <stm32mp1_smc.h>

#ifdef CFG_STM32_BSEC_SIP
uint32_t bsec_main(uint32_t x1, uint32_t x2, uint32_t x3,
		   uint32_t *ret_otp_value);
#else
static inline uint32_t bsec_main(uint32_t x1 __unused, uint32_t x2 __unused,
				 uint32_t x3 __unused,
				 uint32_t *ret_otp_value __unused)
{
	return STM32_SIP_NOT_SUPPORTED;
}
#endif

#endif /*__STM32MP1_BSEC_SVC_H__*/
