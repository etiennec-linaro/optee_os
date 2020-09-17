// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 */

#include <assert.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_clock.h>
#include <mod_scmi_clock.h>
#include <mod_stm32_clock.h>
#include <scmi_agents.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

/*
 * Exported API in DT bindings
 * Macro CLOCK_LIST defines the several SCMI/fwk tables used at module
 * binding to describe and register SCMI clocks and related shim to
 * backend platform driver.
 * The macro defines clocks from stm32mp1_clk.c. These are the stm32mp1
 * source oscillators, the SoC PLLs and gateable clocks from array
 * array stm32mp1_clk_gate[]. The clocks defined this arrays but not listed
 * here are not reacheable from SCMI services, there are:
 * - Clocks for DDR controller/PHY and AXI;
 * - Clocks for TZC1, TZC2, TZPC, BSEC;
 * - Clocks for STGEN (STGEN is alwyas on);
 * - Clocks for BKPSRAM
 */
#define CLOCK_LIST \
	CLOCK_CELL(CLOCK_DEV_IDX_HSE, CK_HSE, "ck_hse", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_HSI, CK_HSI, "ck_hsi", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_CSI, CK_CSI, "ck_csi", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_LSE, CK_LSE, "ck_lse", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_LSI, CK_LSI, "ck_lsi", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2_Q, PLL2_Q, "pll2_q", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2_R, PLL2_R, "pll2_r", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_MPU, CK_MPU, "ck_mpu", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_AXI, CK_AXI, "ck_axi", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_BSEC, BSEC, "bsec", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_CRYP1, CRYP1, "cryp1", 0), \
	CLOCK_CELL(CLOCK_DEV_IDX_GPIOZ, GPIOZ, "gpioz", 0), \
	CLOCK_CELL(CLOCK_DEV_IDX_HASH1, HASH1, "hash1", 0), \
	CLOCK_CELL(CLOCK_DEV_IDX_I2C4, I2C4_K, "i2c4_k", 0), \
	CLOCK_CELL(CLOCK_DEV_IDX_I2C6, I2C6_K, "i2c6_k", 0), \
	CLOCK_CELL(CLOCK_DEV_IDX_IWDG1, IWDG1, "iwdg1", 0), \
	CLOCK_CELL(CLOCK_DEV_IDX_RNG1, RNG1_K, "rng1", 0), \
	CLOCK_CELL(CLOCK_DEV_IDX_RTC, RTC, "ck_rtc", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_RTCAPB, RTCAPB, "rtcapb", 1), \
	CLOCK_CELL(CLOCK_DEV_IDX_SPI6, SPI6_K, "spi6_k", 0), \
	CLOCK_CELL(CLOCK_DEV_IDX_USART1, USART1_K, "usart1_k", 0), \
	/* End of CLOCK_LIST */

/*
 * The static way for storing the elements and module configuration data
 */

/*
 * Clocks from stm32 platform are identified with a platform interger ID value.
 * Config provides a default state and the single supported rate.
 */
#define STM32_CLOCK(_idx, _id)		[(_idx)] = {			\
		.clock_id = (_id),					\
	}

/* Module clock gets stm32_clock (FWK_MODULE_IDX_STM32_CLOCK) elements */
#define CLOCK(_idx, _id)		[(_idx)] = {			\
		.driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_STM32_CLOCK, \
						 (_idx) /* same index */), \
		.api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_CLOCK,	\
					  0 /* API type */),		\
	}

/*
 * SCMI clock binds to clock module (FWK_MODULE_IDX_CLOCK).
 * Common permissions for exposed clocks. All have same permissions.
 */
#define SCMI_CLOCK(_idx, _id, _state)	[(_idx)] =  {			\
		.element_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK,	\
						  (_idx) /* same index */), \
		.state = (_state) ? MOD_CLOCK_STATE_RUNNING :		\
			 MOD_CLOCK_STATE_STOPPED,			\
	}

/*
 * Framwork expects 1 element per module per clock:
 * - stm32_clock elements data configuration provided by stm32_clock_cfg[]
 * - clock elements data configuration provided by clock_cfg[]
 * - scmi_clock elements data configuration provided by scmi_clock_cfg[]
 */
#define STM32_CLOCK_ELT(_idx, _id, _name)	[_idx] = {	\
			.name = #_id,				\
			.data = &stm32_clock_cfg[(_idx)],	\
		}

#define CLOCK_ELT(_idx, _id, _name)		[(_idx)] = {	\
			.name = _name,				\
			.data = &clock_cfg[(_idx)],		\
		}

#define SCMI_CLOCK_ELT(_idx, _id, _name)	[(_idx)] = {	\
			.name = #_id,				\
			.data = &scmi_clock_cfg[(_idx)],	\
		}

/*
 * Elements for clock module: use a function to provide data:
 * FWK_ID_NONE type mandates being initialized at runtime.
 */
#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c, d)	CLOCK(a, b)
static struct mod_clock_dev_config clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c, d)	CLOCK_ELT(a, b, c)
static const struct fwk_element clock_elts[] = {
	CLOCK_LIST
	{ } /* Terminal tag */
};

static const struct fwk_element *clock_config_desc_table(fwk_id_t module_id)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(clock_cfg); i++)
		clock_cfg[i].pd_source_id = FWK_ID_NONE;

	return clock_elts;
}

const struct fwk_module_config config_clock = {
	.elements = FWK_MODULE_DYNAMIC_ELEMENTS(clock_config_desc_table),
};

/*
 * Elements for stm32_clock module: define elements from data table
 */
#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c, d)	STM32_CLOCK(a, b)
static struct mod_stm32_clock_dev_config stm32_clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c, d)	STM32_CLOCK_ELT(a, b, c)
static const struct fwk_element stm32_clock_elt[] = {
	CLOCK_LIST
	{ } /* Terminal tag */
};

static const struct fwk_element *stm32_clock_desc_table(fwk_id_t module_id)
{
	return stm32_clock_elt;
}

const struct fwk_module_config config_stm32_clock = {
	.elements = FWK_MODULE_DYNAMIC_ELEMENTS(stm32_clock_desc_table),
};

/*
 * Elements for SCMI Clock module: define scmi_agent OSPM
 */
#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c, d)	SCMI_CLOCK(a, b, d)
static struct mod_scmi_clock_device scmi_clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c, d)	SCMI_CLOCK_ELT(a, b, c)
static const struct fwk_element scmi_clock_elt[] = {
	CLOCK_LIST
	{ } /* Terminal tag */
};

static const struct mod_scmi_clock_agent clock_agents[SCMI_AGENT_ID_COUNT] = {
	[SCMI_AGENT_ID_NSEC] = {
		.device_table = scmi_clock_cfg,
		.device_count = FWK_ARRAY_SIZE(scmi_clock_cfg),
	},
};

static const struct mod_scmi_clock_config scmi_clock_agents = {
	.max_pending_transactions = 0,
	.agent_table = clock_agents,
	.agent_count = FWK_ARRAY_SIZE(clock_agents),
};

/* Exported in libscmi */
const struct fwk_module_config config_scmi_clock = {
	/* Register module elements straight from data table */
	.data = (void *)&scmi_clock_agents,
};
