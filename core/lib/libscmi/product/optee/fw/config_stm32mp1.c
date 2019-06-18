// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <dt-bindings/clock/stm32mp1-clks.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_clock.h>
#include <mod_scmi_clock.h>
#include <mod_stm32_clock.h>
#include <spci_scmi.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

/* Exported API in DT bindings */
#define CLOCK_LIST \
	/* Platform main clocks */ \
	CLOCK_CELL(CLOCK_DEV_IDX_HSE, CK_HSE, "clk-scmi-hse"), \
	CLOCK_CELL(CLOCK_DEV_IDX_HSI, CK_HSI, "clk-scmi-hsi"), \
	CLOCK_CELL(CLOCK_DEV_IDX_CSI, CK_CSI, "clk-scmi-csi"), \
	CLOCK_CELL(CLOCK_DEV_IDX_LSE, CK_LSE, "clk-scmi-lse"), \
	CLOCK_CELL(CLOCK_DEV_IDX_LSI, CK_LSI, "clk-scmi-lsi"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL1, PLL1, "clk-scmi-pll1"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL1_P, PLL1_P, "clk-scmi-pll1_p"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL1_Q, PLL1_Q, "clk-scmi-pll1_q"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL1_R, PLL1_R, "clk-scmi-pll1_r"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2, PLL2, "clk-scmi-pll2"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2_P, PLL2_P, "clk-scmi-pll2_p"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2_Q, PLL2_Q, "clk-scmi-pll2_q"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2_R, PLL2_R, "clk-scmi-pll2_r"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL3, PLL3, "clk-scmi-pll3"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL3_P, PLL3_P, "clk-scmi-pll3_p"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL3_Q, PLL3_Q, "clk-scmi-pll3_q"), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL3_R, PLL3_R, "clk-scmi-pll3_r"), \
	/* Platform gated clocks: refer to stm32mp1_clk_gate[] */ \
	/* No access to DDR controller/PHY and AXI */ \
	CLOCK_CELL(CLOCK_DEV_IDX_SPI6, SPI6_K, "clk-scmi-spi6"), \
	CLOCK_CELL(CLOCK_DEV_IDX_I2C4, I2C4_K, "clk-scmi-i2c4"), \
	CLOCK_CELL(CLOCK_DEV_IDX_I2C6, I2C6_K, "clk-scmi-i2c6"), \
	CLOCK_CELL(CLOCK_DEV_IDX_USART1, USART1_K, "clk-scmi-usart1"), \
	CLOCK_CELL(CLOCK_DEV_IDX_RTCAPB, RTCAPB, "clk-scmi-rtcapb"), \
	/* No access to TZC1, TZC2, TZPC */ \
	CLOCK_CELL(CLOCK_DEV_IDX_IWDG1, IWDG1, "clk-scmi-iwdg1"), \
	/* No access to BSEC, STGEN. STGEN is alwyas on (shared clock?) */ \
	CLOCK_CELL(CLOCK_DEV_IDX_GPIOZ, GPIOZ, "clk-scmi-gpioz"), \
	CLOCK_CELL(CLOCK_DEV_IDX_CRYP1, CRYP1, "clk-scmi-cryp1"), \
	CLOCK_CELL(CLOCK_DEV_IDX_HASH1, HASH1, "clk-scmi-hash1"), \
	CLOCK_CELL(CLOCK_DEV_IDX_RNG1, RNG1_K, "clk-scmi-rng1"), \
	/* No access to BKPSRAM */ \

/*
 * The static way for storing the elements and module configuration data
 */

/*
 * Clocks from stm32 platform are identified with a platform interger ID value.
 * Config provides a default state and the single supported rate.
 */
#define STM32_CLOCK(_idx, _id)	[(_idx)] = {	\
                    .clock_id = (_id),		\
		}

/* Module clock gets stm32_clock (FWK_MODULE_IDX_STM32_CLOCK) elements */
#define CLOCK(_idx, _id)  [(_idx)] = { \
		.driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_STM32_CLOCK, \
						 (_idx) /* same index */), \
		.api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_STM32_CLOCK,	\
					  0 /* API type */),		\
	}

/*
 * SCMI clock binds to clock module (FWK_MODULE_IDX_CLOCK).
 * Common permissions for exposed clocks.
 */
#define SCMI_CLOCK(_idx, _id)		[(_idx)] =  { \
		.element_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK,	\
						  (_idx) /* same index */), \
		.permissions = MOD_SCMI_CLOCK_PERM_ATTRIBUTES |		\
			       MOD_SCMI_CLOCK_PERM_DESCRIBE_RATES |	\
			       MOD_SCMI_CLOCK_PERM_GET_RATE,		\
	}

/*
 * Framwork expects 1 element per module per clock:
 * - stm32_clock elements data configuration provided by stm32_clock_cfg[]
 * - clock elements data configuration provided by clock_cfg[]
 * - scmi_clock elements data configuration provided by scmi_clock_cfg[]
 */
#define STM32_CLOCK_ELT(_idx, _id, _name)	[_idx] = {	\
			.name = #_id,		\
			.data = &stm32_clock_cfg[(_idx)],	\
		}

#define CLOCK_ELT(_idx, _id, _name)		[(_idx)] = {	\
			.name = _name,		\
			.data = &clock_cfg[(_idx)],		\
		}

#define SCMI_CLOCK_ELT(_idx, _id, _name)	[(_idx)] = {	\
			.name = #_id,		\
			.data = &scmi_clock_cfg[(_idx)],	\
		}

/*
 * Elements for clock module: use a function to provide data:
 * FWK_ID_NONE type mandates being initialized at runtime.
 */
#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c)	CLOCK(a, b)
static struct mod_clock_dev_config clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c)	CLOCK_ELT(a, b, c)
static const struct fwk_element clock_elt[] = {
	CLOCK_LIST
	{ } /* Terminal tag */
};

static const struct fwk_element *clock_config_desc_table(fwk_id_t module_id)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(clock_cfg); i++)
		clock_cfg[i].pd_source_id = FWK_ID_NONE;

	return clock_elt;
}

/* Exported in libscmi */
const struct fwk_module_config config_clock = {
	.get_element_table = clock_config_desc_table,
};

/* Elements for stm32_clock module: define elements from data table */
#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c)	STM32_CLOCK(a, b)
static const struct mod_stm32_clock_dev_config stm32_clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c)	STM32_CLOCK_ELT(a, b, c)
static const struct fwk_element stm32_clock_elt[] = {
	CLOCK_LIST
	{ } /* Terminal tag */
};

static const struct fwk_element *stm32_clock_desc_table(fwk_id_t module_id)
{
	return stm32_clock_elt;
}

/* Exported in libscmi */
const struct fwk_module_config config_stm32_clock = {
	.get_element_table =(void *)stm32_clock_desc_table,
};

/* Elements for SCMI clock module: define scmi_agent OSPM (TODO: get a name) */
#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c)	SCMI_CLOCK(a, b)
static const struct mod_scmi_clock_device scmi_clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL(a, b, c)	SCMI_CLOCK_ELT(a, b, c)
static const struct fwk_element scmi_clock_elt[] = {
	CLOCK_LIST
	{ } /* Terminal tag */
};

static const struct mod_scmi_clock_agent agent_table[SCMI_AGENT_ID_COUNT] = {
    [SCMI_AGENT_ID_OSPM] = {
        .device_table = scmi_clock_cfg,
        .device_count = FWK_ARRAY_SIZE(scmi_clock_cfg),
    },
};

static const struct mod_scmi_clock_config scmi_agent = {
        .max_pending_transactions = 0,
        .agent_table = agent_table,
        .agent_count = FWK_ARRAY_SIZE(agent_table),
};

/* Exported in libscmi */
const struct fwk_module_config config_scmi_clock = {
	/* Register module elements straight from data table */
	.data = (void *)&scmi_agent,
};

// Register 2 dummy power-domains

// Register 2 dummy reset

#if 0 // Dynamic alloc: build table dynamically and free them when not needed

/*
 * Simulate a platform that internally handles clocks with an identifer,
 * not an index in a clock table.
 */
static TEE_Result vexpress_dummy_scmi(void)
{
#ifdef CFG_SCMI_CLOCK
	if (libscmi_register_clocks(dummy_clocks, ARRAY_SIZE(dummy_clocks)))
		panic();
#endif
#ifdef CFG_SCMI_POWER_DOMAIN
	if (libscmi_register_power_domains(dummy_pd, ARRAY_SIZE(dummy_pd)))
		panic();
#endif
#ifdef CFG_SCMI_RESET
	if (libscmi_register_resets(dummy_reset, ARRAY_SIZE(dummy_reset)))
		panic();
#endif
}
static int clock_config_post_init(fwk_id_t module_id)
{
	// test freeing allocated tables.
	// module scmi_clock references the permissions per clock information
}

#endif
