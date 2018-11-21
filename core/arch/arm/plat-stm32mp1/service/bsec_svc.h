/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016-2018, STMicroelectronics
 */

#ifndef __STM32MP1_BSEC_SVC_H__
#define __STM32MP1_BSEC_SVC_H__

#include <drivers/stm32_bsec.h>

uint32_t bsec_main(uint32_t x1, uint32_t x2, uint32_t x3,
		   uint32_t *ret_otp_value);

#endif /*__STM32MP1_BSEC_SVC_H__*/
