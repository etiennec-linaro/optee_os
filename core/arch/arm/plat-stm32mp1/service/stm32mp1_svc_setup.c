// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <arm.h>
#include <assert.h>
#include <drivers/stm32_bsec.h>
#include <kernel/thread.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <stm32_util.h>
#include <stdint.h>
#include <trace.h>

#include "bsec_svc.h"
#include "stm32mp1_smc.h"

/* STM32 SiP Service UUID */
static const TEE_UUID stm32mp1_sip_svc_uid = {
	0x50aa78a7, 0x9bf4, 0x4a14,
	{ 0x8a, 0x5e, 0x26, 0x4d, 0x59, 0x94, 0xc2, 0x14 }
};

bool stm32_sip_service(struct sm_ctx *ctx __unused,
		       uint32_t *a0, uint32_t *a1, uint32_t *a2, uint32_t *a3)
{
	switch (OPTEE_SMC_FUNC_NUM(*a0)) {
	case STM32_SIP_FUNC_CALL_COUNT:
		/* This service is meaningless, return a dummy value */
		*a0 = 0;
		break;
	case STM32_SIP_FUNC_VERSION:
		*a0 = STM32_SIP_SVC_VERSION_MAJOR;
		*a1 = STM32_SIP_SVC_VERSION_MINOR;
		break;
	case STM32_SIP_FUNC_UID:
		*a0 = ((uint32_t *)&stm32mp1_sip_svc_uid)[0];
		*a1 = ((uint32_t *)&stm32mp1_sip_svc_uid)[1];
		*a2 = ((uint32_t *)&stm32mp1_sip_svc_uid)[2];
		*a3 = ((uint32_t *)&stm32mp1_sip_svc_uid)[3];
		break;
#ifdef CFG_STM32_BSEC_SIP
	case STM32_SIP_FUNC_BSEC:
		*a0 = bsec_main(*a1, *a2, *a3, a1);
		break;
#endif
	default:
		return true;
	}

	return false;
}

bool stm32_oem_service(struct sm_ctx *ctx __unused,
		       uint32_t *a0, uint32_t *a1, uint32_t *a2, uint32_t *a3)
{
	switch (OPTEE_SMC_FUNC_NUM(*a0)) {
	default:
		return true;
	}

	return false;
}
