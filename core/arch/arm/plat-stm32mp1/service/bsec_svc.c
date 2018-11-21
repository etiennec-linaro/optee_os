// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2016-2018, STMicroelectronics
 */

#include <trace.h>
#include "bsec_svc.h"
#include "stm32mp1_smc.h"

uint32_t bsec_main(uint32_t x1, uint32_t x2, uint32_t x3, uint32_t *out)
{
	int result;
	uint32_t tmp;

	if (bsec_check_nsec_access_rights(x2) != BSEC_OK)
		return BSEC_ERROR;

	switch (x1) {
	case STM32_SIP_BSEC_READ_SHADOW:
		result = bsec_read_otp(out, x2);
		FMSG("read shadow @%" PRIx32 " = %" PRIx32, x2, *out);
		break;
	case STM32_SIP_BSEC_PROG_OTP:
		FMSG("program @%" PRIx32, x2);
		result = bsec_program_otp(x3, x2);
		break;
	case STM32_SIP_BSEC_WRITE_SHADOW:
		FMSG("write shadow @%" PRIx32, x2);
		result = bsec_write_otp(x3, x2);
		break;
	case STM32_SIP_BSEC_READ_OTP:
		result = bsec_read_otp(&tmp, x2);
		if (result != BSEC_OK)
			break;

		result = bsec_shadow_register(x2);
		if (result != BSEC_OK)
			break;

		result = bsec_read_otp(out, x2);
		if (result != BSEC_OK)
			break;

		result = bsec_write_otp(tmp, x2);
		FMSG("read @%" PRIx32 " = %" PRIx32, x2, *out);
		break;
	default:
		EMSG("Invalid " PRIx32, x1);
		result = BSEC_ERROR;
		break;
	}

	switch (result) {
	case BSEC_OK:
		return STM32_SIP_OK;
	case BSEC_INVALID_PARAM:
		return STM32_SIP_INVALID_PARAMS;
	default:
		return STM32_SIP_FAILED;
	}
}
