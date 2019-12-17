// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, STMicroelectronics
 */
#include <assert.h>
#include <compiler.h>
#include <drivers/scmi-msg.h>
#include <drivers/scmi.h>
#include <dt-bindings/clock/stm32mp1-clks.h>
#include <dt-bindings/reset/stm32mp1-resets.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <stm32_util.h>
#include <tee_api_defines.h>
#include <util.h>

#define TIMEOUT_US_1MS		1000

#define CLOCK_CELL(_scmi_id, _id, _name, _init_enabled) \
	[_scmi_id] = { \
		.clock_id = _id, \
		.name = _name, \
		.enabled = _init_enabled, \
	}

struct stm32_scmi_clk {
	unsigned long clock_id;
	const char *name;
	bool enabled;
};

#define RESET_CELL(_scmi_id, _id, _name) \
	[_scmi_id] = { \
		.reset_id = _id, \
		.name = _name, \
	}

struct stm32_scmi_rd {
	unsigned long reset_id;
	const char *name;
};

/* Locate all non-secure SMT message buffers in last page of SYSRAM */
#define SMT_BUFFER_BASE		CFG_STM32MP1_SCMI_SHM_BASE
#define SMT_BUFFER0_BASE	SMT_BUFFER_BASE
#define SMT_BUFFER1_BASE	(SMT_BUFFER_BASE + 0x200)
#define SMT_BUFFER_END		(SMT_BUFFER1_BASE + SMT_BUF_SLOT_SIZE)

#if SMT_BUFFER_END > (CFG_STM32MP1_SCMI_SHM_BASE + CFG_STM32MP1_SCMI_SHM_SIZE)
#error "SCMI shared memory mismatch"
#endif

register_phys_mem(MEM_AREA_IO_NSEC, CFG_STM32MP1_SCMI_SHM_BASE,
		  CFG_STM32MP1_SCMI_SHM_SIZE);

static struct scmi_msg_channel scmi_channel[] = {
	[0] = {
		/* Virtual address ::shm_addr is computed at init */
		.agent_name = "stm32mp1-clock",
		.shm_addr = { .pa = SMT_BUFFER0_BASE, },
		.shm_size = SMT_BUF_SLOT_SIZE,
	},
	[1] = {
		/* Virtual address ::shm_addr is computed at init */
		.agent_name = "stm32mp1-reset",
		.shm_addr = { .pa = SMT_BUFFER1_BASE, },
		.shm_size = SMT_BUF_SLOT_SIZE,
	},
};

struct scmi_msg_channel *plat_scmi_get_channel(unsigned int agent_id)
{
	assert(agent_id < ARRAY_SIZE(scmi_channel));

	return &scmi_channel[agent_id];
}

struct stm32_scmi_clk stm32_scmi_clock[] = {
	CLOCK_CELL(CK_SCMI_HSE, CK_HSE, "clk-hse", true),
	CLOCK_CELL(CK_SCMI_HSI, CK_HSI, "clk-hsi", true),
	CLOCK_CELL(CK_SCMI_CSI, CK_CSI, "clk-csi", true),
	CLOCK_CELL(CK_SCMI_LSE, CK_LSE, "clk-lse", true),
	CLOCK_CELL(CK_SCMI_LSI, CK_LSI, "clk-lsi", true),
	CLOCK_CELL(CK_SCMI_PLL2_Q, PLL2_Q, "pll2_q", true),
	CLOCK_CELL(CK_SCMI_PLL3_Q, PLL3_Q, "pll3_q", true),
	CLOCK_CELL(CK_SCMI_PLL3_R, PLL3_R, "pll3_r", true),
	CLOCK_CELL(CK_SCMI_MPU, CK_MPU, "ck_mpu", true),
	CLOCK_CELL(CK_SCMI_MCU, CK_MCU, "ck_mcu", true),
	CLOCK_CELL(CK_SCMI_AXI, CK_AXI, "ck_axi", true),
	CLOCK_CELL(CK_SCMI_BSEC, BSEC, "bsec", true),
	CLOCK_CELL(CK_SCMI_CRYP1, CRYP1, "cryp1", false),
	CLOCK_CELL(CK_SCMI_GPIOZ, GPIOZ, "gpioz", false),
	CLOCK_CELL(CK_SCMI_HASH1, HASH1, "hash1", false),
	CLOCK_CELL(CK_SCMI_I2C4, I2C4_K, "i2c4_k", false),
	CLOCK_CELL(CK_SCMI_I2C6, I2C6_K, "i2c6_k", false),
	CLOCK_CELL(CK_SCMI_IWDG1, IWDG1, "iwdg1", false),
	CLOCK_CELL(CK_SCMI_RNG1, RNG1_K, "rng1", false),
	CLOCK_CELL(CK_SCMI_RTC, RTC, "ck_rtc", true),
	CLOCK_CELL(CK_SCMI_RTCAPB, RTCAPB, "rtcapb", true),
	CLOCK_CELL(CK_SCMI_SPI6, SPI6_K, "spi6_k", false),
	CLOCK_CELL(CK_SCMI_USART1, USART1_K, "usart1_k", false),
};

struct stm32_scmi_rd stm32_scmi_reset_domain[] = {
	RESET_CELL(RST_SCMI_SPI6, SPI6_R, "spi6"),
	RESET_CELL(RST_SCMI_I2C4, I2C4_R, "i2c4"),
	RESET_CELL(RST_SCMI_I2C6, I2C6_R, "i2c6"),
	RESET_CELL(RST_SCMI_USART1, USART1_R, "usart1"),
	RESET_CELL(RST_SCMI_STGEN, STGEN_R, "stgen"),
	RESET_CELL(RST_SCMI_GPIOZ, GPIOZ_R, "gpioz"),
	RESET_CELL(RST_SCMI_CRYP1, CRYP1_R, "cryp1"),
	RESET_CELL(RST_SCMI_HASH1, HASH1_R, "hash1"),
	RESET_CELL(RST_SCMI_RNG1, RNG1_R, "rng1"),
	RESET_CELL(RST_SCMI_MDMA, MDMA_R, "mdma"),
	RESET_CELL(RST_SCMI_MCU, MCU_R, "mcu"),
};

struct scmi_agent_resources {
	struct stm32_scmi_clk *clock;
	size_t clock_count;
	struct stm32_scmi_rd *rd;
	size_t rd_count;
	struct stm32_scmi_pd *pd;
	size_t pd_count;
	struct stm32_scmi_perfs *perfs;
	size_t perfs_count;
};

const struct scmi_agent_resources agent_resources[] = {
	[0] = {
		.clock = stm32_scmi_clock,
		.clock_count = ARRAY_SIZE(stm32_scmi_clock),
	},
	[1] = {
		.rd = stm32_scmi_reset_domain,
		.rd_count = ARRAY_SIZE(stm32_scmi_reset_domain),
	},
};

static const struct scmi_agent_resources *find_resource(unsigned int agent_id)
{
	assert(agent_id < ARRAY_SIZE(agent_resources));

	return &agent_resources[agent_id];
}

static size_t __maybe_unused plat_scmi_protocol_count_paranoid(void)
{
	unsigned int n = 0;
	unsigned int count = 0;
	const size_t nb_elts = ARRAY_SIZE(agent_resources);

	for (n = 0; n < nb_elts; n++)
		if (agent_resources[n].clock_count)
			break;
	if (n < nb_elts)
		count++;

	for (n = 0; n < nb_elts; n++)
		if (agent_resources[n].rd_count)
			break;
	if (n < nb_elts)
		count++;

	for (n = 0; n < nb_elts; n++)
		if (agent_resources[n].pd_count)
			break;
	if (n < nb_elts)
		count++;

	for (n = 0; n < nb_elts; n++)
		if (agent_resources[n].perfs_count)
			break;
	if (n < nb_elts)
		count++;

	return count;
}

static const char vendor[] = "ST";
static const char sub_vendor[] = "";

const char *plat_scmi_vendor_name(void)
{
	return vendor;
}

const char *plat_scmi_sub_vendor_name(void)
{
	return sub_vendor;
}

/* Currently supporting Clocks and Reset Domains */
static const uint8_t plat_protocol_list[] = {
	SCMI_PROTOCOL_ID_CLOCK,
	SCMI_PROTOCOL_ID_RESET_DOMAIN,
	0 /* Null termination */
};

size_t plat_scmi_protocol_count(void)
{
	const size_t count = ARRAY_SIZE(plat_protocol_list) - 1;

	assert(count == plat_scmi_protocol_count_paranoid());

	return count;
}

const uint8_t *plat_scmi_protocol_list(unsigned int agent_id __unused)
{

	assert(plat_scmi_protocol_count_paranoid() ==
	       (ARRAY_SIZE(plat_protocol_list) - 1));

	return plat_protocol_list;
}

/*
 * Platform SCMI clocks
 */
static struct stm32_scmi_clk *find_clock(unsigned int agent_id,
					 unsigned int scmi_id)
{
	const struct scmi_agent_resources *resource = find_resource(agent_id);
	struct stm32_scmi_clk *clock = NULL;
	size_t n = 0;

	if (!resource || !resource->clock_count)
		goto out;

	for (n = 0; n < resource->clock_count; n++)
		if (n == scmi_id)
			break;

	if (n < resource->clock_count) {
		clock = &resource->clock[n];
		if (!clock->name ||
		    !stm32mp_nsec_can_access_clock(clock->clock_id))
			clock = NULL;
	}

out:
	return clock;
}

size_t plat_scmi_clock_count(unsigned int agent_id)
{
	const struct scmi_agent_resources *res = find_resource(agent_id);

	if (!res)
		return 0;

	return res->clock_count;
}

const char *plat_scmi_clock_get_name(unsigned int agent_id,
				     unsigned int scmi_id)
{
	/* find_rd() returns NULL if clock exists for denied the agent */
	struct stm32_scmi_clk *clock = find_clock(agent_id, scmi_id);

	if (!clock)
		return NULL;

	return clock->name;
}

int32_t plat_scmi_clock_rates_array(unsigned int agent_id, unsigned int scmi_id,
				    unsigned long *array, size_t *nb_elts)
{
	/* find_rd() returns NULL if clock exists for denied the agent */
	struct stm32_scmi_clk *clock = find_clock(agent_id, scmi_id);

	if (!clock)
		return SCMI_NOT_FOUND;

	if (!array) {
		*nb_elts = 1;

		return SCMI_SUCCESS;
	}

	if (*nb_elts == 1) {
		*array = stm32_clock_get_rate(clock->clock_id);

		return SCMI_SUCCESS;
	}

	return SCMI_GENERIC_ERROR;
}

unsigned long plat_scmi_clock_get_current_rate(unsigned int agent_id,
					       unsigned int scmi_id)
{
	/* find_rd() returns NULL if clock exists for denied the agent */
	struct stm32_scmi_clk *clock = find_clock(agent_id, scmi_id);

	if (!clock)
		return 0;

	return stm32_clock_get_rate(clock->clock_id);
}

int32_t plat_scmi_clock_get_state(unsigned int agent_id, unsigned int scmi_id)
{
	/* find_rd() returns NULL if clock exists for denied the agent */
	struct stm32_scmi_clk *clock = find_clock(agent_id, scmi_id);

	if (!clock)
		return 0;

	return (int32_t)clock->enabled;
}

int32_t plat_scmi_clock_set_state(unsigned int agent_id, unsigned int scmi_id,
				  bool enable_not_disable)
{
	/* find_rd() returns NULL if clock exists for denied the agent */
	struct stm32_scmi_clk *clock = find_clock(agent_id, scmi_id);

	if (!clock)
		return SCMI_NOT_FOUND;

	if (enable_not_disable) {
		if (!clock->enabled) {
			DMSG("SCMI clock %u enable", scmi_id);
			stm32_clock_enable(clock->clock_id);
			clock->enabled = true;
		}
	} else {
		if (clock->enabled) {
			DMSG("SCMI clock %u disable", scmi_id);
			stm32_clock_disable(clock->clock_id);
			clock->enabled = false;
		}
	}

	return SCMI_SUCCESS;
}

/*
 * Platform SCMI reset domains
 */
static struct stm32_scmi_rd *find_rd(unsigned int agent_id,
				     unsigned int scmi_id)
{
	const struct scmi_agent_resources *resource = find_resource(agent_id);
	struct stm32_scmi_rd *reset = NULL;
	size_t n = 0;

	if (!resource || !resource->rd_count)
		goto out;

	for (n = 0; n < resource->rd_count; n++)
		if (n == scmi_id)
			break;

	if (n < resource->rd_count) {
		reset = &resource->rd[n];
		if (!reset->name ||
		    !stm32mp_nsec_can_access_reset(reset->reset_id))
			reset = NULL;
	}

out:
	return reset;
}

const char *plat_scmi_rd_get_name(unsigned int agent_id, unsigned int scmi_id)
{
	/* find_rd() returns NULL is reset exists for denied the agent */
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return NULL;

	return rd->name;
}

size_t plat_scmi_rd_count(unsigned int agent_id)
{
	const struct scmi_agent_resources *res = find_resource(agent_id);

	if (!res)
		return 0;

	return res->rd_count;
}

int32_t plat_scmi_rd_autonomous(unsigned int agent_id, unsigned int scmi_id,
				uint32_t state)
{
	/* find_rd() returns NULL is reset exists for denied the agent */
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return SCMI_NOT_FOUND;

	/* Supports only full reset with context loss */
	if (state)
		return SCMI_NOT_SUPPORTED;

	DMSG("SCMI reset %u cycle", scmi_id);

	if (stm32_reset_assert_to(rd->reset_id, TIMEOUT_US_1MS))
		return SCMI_HARDWARE_ERROR;

	if (stm32_reset_deassert_to(rd->reset_id, TIMEOUT_US_1MS))
		return SCMI_HARDWARE_ERROR;

	return SCMI_SUCCESS;
}

int32_t plat_scmi_rd_set_state(unsigned int agent_id, unsigned int scmi_id,
			       bool assert_not_deassert)
{
	/* find_rd() returns NULL is reset exists for denied the agent */
	const struct stm32_scmi_rd *rd = find_rd(agent_id, scmi_id);

	if (!rd)
		return SCMI_NOT_FOUND;

	if (assert_not_deassert) {
		DMSG("SCMI reset %u assert", scmi_id);
		stm32_reset_set(rd->reset_id);
	} else {
		DMSG("SCMI reset %u deassert", scmi_id);
		stm32_reset_release(rd->reset_id);
	}

	return SCMI_SUCCESS;
}

/*
 * Initialize platform SCMI resources
 */
static TEE_Result stm32mp1_init_scmi_server(void)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(scmi_channel); i++) {
		struct scmi_msg_channel *chan = &scmi_channel[i];

		chan->shm_addr.va = (vaddr_t)phys_to_virt(chan->shm_addr.pa,
							  MEM_AREA_IO_NSEC);
		assert(chan->shm_addr.va);

		scmi_smt_init_agent_channel(chan);
	}

	/* Synchronise SCMI clocks with their target init state */
	for (i = 0; i < ARRAY_SIZE(agent_resources); i++) {
		const struct scmi_agent_resources *res = &agent_resources[i];
		size_t j = 0;

		for (j = 0; j < res->clock_count; j++) {
			struct stm32_scmi_clk *clk = &res->clock[j];

			if (!clk->enabled ||
			    !stm32mp_nsec_can_access_clock(clk->clock_id))
				continue;

			stm32_clock_enable(clk->clock_id);
		}
	}

	return TEE_SUCCESS;
}

driver_init_late(stm32mp1_init_scmi_server);
