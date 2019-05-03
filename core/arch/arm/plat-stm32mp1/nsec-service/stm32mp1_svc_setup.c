// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <arm.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <string.h>
#include <stm32_util.h>

#include "rcc_svc.h"
#include "stm32mp1_smc.h"

/* STM32 SiP Service UUID */
static const TEE_UUID stm32mp1_sip_svc_uid = {
	0x50aa78a7, 0x9bf4, 0x4a14,
	{ 0x8a, 0x5e, 0x26, 0x4d, 0x59, 0x94, 0xc2, 0x14 }
};

static void get_sip_func_uid(uint32_t *a0, uint32_t *a1,
			     uint32_t *a2, uint32_t *a3)
{
	const void *uid = &stm32mp1_sip_svc_uid;

	memcpy(a0, (char *)uid, sizeof(uint32_t));
	memcpy(a1, (char *)uid + sizeof(uint32_t), sizeof(uint32_t));
	memcpy(a2, (char *)uid + (sizeof(uint32_t) * 2), sizeof(uint32_t));
	memcpy(a3, (char *)uid + (sizeof(uint32_t) * 3), sizeof(uint32_t));
}

static enum sm_handler_ret sip_service(struct sm_ctx *ctx __unused,
				       uint32_t *a0, uint32_t *a1,
				       uint32_t *a2, uint32_t *a3)
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
		get_sip_func_uid(a0, a1, a2, a3);
		break;
	case STM32_SIP_FUNC_RCC:
		*a0 = rcc_scv_handler(*a1, *a2, *a3);
		break;
#endif
	default:
		return SM_HANDLER_PENDING_SMC;
	}

	return SM_HANDLER_SMC_HANDLED;
}

static enum sm_handler_ret oem_service(struct sm_ctx *ctx __unused,
				       uint32_t *a0 __unused,
				       uint32_t *a1 __unused,
				       uint32_t *a2 __unused,
				       uint32_t *a3 __unused)
{
	return SM_HANDLER_PENDING_SMC;
}

/* Override default sm_platform_handler() with paltform specific function */
enum sm_handler_ret sm_platform_handler(struct sm_ctx *ctx)
{
	uint32_t *a0 = (uint32_t *)(&ctx->nsec.r0);
	uint32_t *a1 = (uint32_t *)(&ctx->nsec.r1);
	uint32_t *a2 = (uint32_t *)(&ctx->nsec.r2);
	uint32_t *a3 = (uint32_t *)(&ctx->nsec.r3);

	if (!OPTEE_SMC_IS_FAST_CALL(*a0))
		return SM_HANDLER_PENDING_SMC;

	switch (OPTEE_SMC_OWNER_NUM(*a0)) {
	case OPTEE_SMC_OWNER_SIP:
		return sip_service(ctx, a0, a1, a2, a3);
	case OPTEE_SMC_OWNER_OEM:
		return oem_service(ctx, a0, a1, a2, a3);
	default:
		return SM_HANDLER_PENDING_SMC;
	}
}
