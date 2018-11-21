// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <arm.h>
#include <kernel/delay.h>

#define US2CNT(m)	(((uint64_t)m * (uint64_t)read_cntfrq()) / 1000000ULL)
#define CNT2US(m)	((uint32_t)(((uint64_t)m * 1000000ULL) / read_cntfrq()))

void udelay(uint32_t us)
{
	uint64_t start, target;

	start = read_cntpct();
	target = US2CNT(us);

	while (read_cntpct() - start <= target)
		;
}

void mdelay(uint32_t ms)
{
	udelay(1000 * ms);
}

uint64_t utimeout_init(uint32_t us)
{
	return read_cntpct() + US2CNT(us);
}

bool utimeout_elapsed(uint32_t us, uint64_t reference)
{
	uint64_t origin = reference - US2CNT(us);
	uint64_t now = read_cntpct();

	if (origin < reference)
		return now < origin || now > reference;

	return now < origin && now > reference;
}

unsigned int utimeout_elapsed_us(uint32_t us, uint64_t reference)
{
	uint64_t origin = reference - US2CNT(us);
	uint64_t now = read_cntpct();

	if (origin < reference) {
		if (now < origin || now > reference)
			return CNT2US(now - reference);

		return 0;
	}

	if (now < origin && now > reference)
		return CNT2US(now - reference);

	return 0;
}
