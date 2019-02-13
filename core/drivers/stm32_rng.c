// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#include <assert.h>
#include <drivers/stm32_rng.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/delay.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <string.h>

#ifdef CFG_DT
#include <libfdt.h>
#endif

#define DT_RNG_COMPAT		"st,stm32-rng"
#define RNG_CR			0x00U
#define RNG_SR			0x04U
#define RNG_DR			0x08U

#define RNG_CR_RNGEN		BIT(2)
#define RNG_CR_IE		BIT(3)
#define RNG_CR_CED		BIT(5)

#define RNG_SR_DRDY		BIT(0)
#define RNG_SR_CECS		BIT(1)
#define RNG_SR_SECS		BIT(2)
#define RNG_SR_CEIS		BIT(5)
#define RNG_SR_SEIS		BIT(6)

#define RNG_TIMEOUT_US		1000

struct stm32_rng_instance {
	struct io_pa_va base;
	unsigned long clock;
};

static struct stm32_rng_instance *stm32_rng;

/*
 * Extract from the STM32 RNG specification:
 *
 * When a noise source (or seed) error occurs, the RNG stops generating
 * random numbers and sets to “1” both SEIS and SECS bits to indicate
 * that a seed error occurred. (...)

 * The following sequence shall be used to fully recover from a seed
 * error after the RNG initialization:
 * 1. Clear the SEIS bit by writing it to “0”.
 * 2. Read out 12 words from the RNG_DR register, and discard each of
 * them in order to clean the pipeline.
 * 3. Confirm that SEIS is still cleared. Random number generation is
 * back to normal.
 */
static bool conceal_seed_error(vaddr_t rng_base)
{
	if (read32(rng_base + RNG_SR) & (RNG_SR_SECS | RNG_SR_SEIS)) {
		size_t i = 0;

		io_mask32(rng_base + RNG_SR, 0, RNG_SR_SEIS);

		for (i = 12; i != 0; i--)
			(void)read32(rng_base + RNG_DR);

		if (read32(rng_base + RNG_SR) & RNG_SR_SEIS)
			panic("RNG noise");

		return true;
	}

	return false;
}

TEE_Result stm32_rng_read_raw(vaddr_t rng_base, uint8_t *out, size_t size)
{
	uint8_t *buf = out;
	size_t len = size;
	TEE_Result rc = TEE_ERROR_SECURITY;
	int count = 0;

	/* Enable RNG if not, clock error is disabled */
	if (!(read32(rng_base + RNG_CR) & RNG_CR_RNGEN))
		write32(RNG_CR_RNGEN | RNG_CR_CED, rng_base + RNG_CR);

	while (len) {
		uint64_t timeout_ref = timeout_init_us(RNG_TIMEOUT_US);

		/* Wait RNG has produced random well seeded samples */
		while (!timeout_elapsed(timeout_ref)) {
			if (!conceal_seed_error(rng_base) &&
			    read32(rng_base + RNG_SR) & RNG_SR_DRDY)
				break;
		}
		if (conceal_seed_error(rng_base))
			continue;
		if (!(read32(rng_base + RNG_SR) & RNG_SR_DRDY))
			break;

		/* RNG is ready: read data by 32bit word, up to 4 words */
		for (count = 0; count < 4; count++) {
			uint32_t data32 = read32(rng_base + RNG_DR);

			memcpy(buf, &data32, MIN(len, sizeof(uint32_t)));
			buf += MIN(len, sizeof(uint32_t));
			len -= MIN(len, sizeof(uint32_t));

			if (!len) {
				rc = TEE_SUCCESS;
				break;
			}
		}
	}

	/* Disable RNG */
	write32(0, rng_base + RNG_CR);

	return rc;
}

TEE_Result stm32_rng_read(uint8_t *out, size_t size)
{
	TEE_Result rc = 0;

	if (!stm32_rng) {
		DMSG("No RNG");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	stm32_clock_enable(stm32_rng->clock);

	rc = stm32_rng_read_raw(io_pa_or_va(&stm32_rng->base), out, size);

	stm32_clock_disable(stm32_rng->clock);

	if (rc)
		memset(out, 0, size);

	return rc;
}

#ifdef CFG_EMBED_DTB
static TEE_Result stm32_rng_init(void)
{
	void *fdt = NULL;
	struct dt_node_info dt_info = { 0 };
	int node = -1;

	fdt = get_embedded_dt();
	if (!fdt)
		panic();

	while (true) {
		node = fdt_node_offset_by_compatible(fdt, node, DT_RNG_COMPAT);
		if (node < 0)
			break;

		_fdt_fill_device_info(fdt, &dt_info, node);

		if (!(dt_info.status & DT_STATUS_OK_SEC))
			continue;

		if (stm32_rng)
			panic();

		stm32_rng = calloc(1, sizeof(*stm32_rng));
		if (!stm32_rng)
			panic();

		assert(dt_info.clock != DT_INFO_INVALID_CLOCK &&
		       dt_info.reg != DT_INFO_INVALID_REG);

		stm32_rng->base.pa = dt_info.reg;
		stm32_rng->clock = (unsigned long)dt_info.clock;

		DMSG("RNG init");
	}

	return TEE_SUCCESS;
}

driver_init(stm32_rng_init);
#endif /*CFG_EMBED_DTB*/
