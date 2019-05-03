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
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <mod_clock.h>
#include <mod_stm32_clock.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

#include "clock_devices.h"

/* Exported API in DT bindings */
#define CLOCK_LIST \
	/* Platform main clocks */ \
	CLOCK_CELL(CLOCK_DEV_IDX_HSE, CK_HSE), \
	CLOCK_CELL(CLOCK_DEV_IDX_HSI, CK_HSI), \
	CLOCK_CELL(CLOCK_DEV_IDX_CSI, CK_CSI), \
	CLOCK_CELL(CLOCK_DEV_IDX_LSE, CK_LSE), \
	CLOCK_CELL(CLOCK_DEV_IDX_LSI, CK_LSI), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL1, PLL1), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL1_P, PLL1_P), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL1_Q, PLL1_Q), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL1_R, PLL1_R), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2, PLL2), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2_P, PLL2_P), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2_Q, PLL2_Q), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL2_R, PLL2_R), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL3, PLL3), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL3_P, PLL3_P), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL3_Q, PLL3_Q), \
	CLOCK_CELL(CLOCK_DEV_IDX_PLL3_R, PLL3_R), \
	/* Platform gated clocks: refer to stm32mp1_clk_gate[] */ \
	/* No access to DDR controller/PHY and AXI */ \
	CLOCK_CELL(CLOCK_DEV_IDX_SPI6, SPI6_K), \
	CLOCK_CELL(CLOCK_DEV_IDX_I2C4, I2C4_K), \
	CLOCK_CELL(CLOCK_DEV_IDX_I2C6, I2C6_K), \
	CLOCK_CELL(CLOCK_DEV_IDX_USART1, USART1_K), \
	CLOCK_CELL(CLOCK_DEV_IDX_RTCAPB, RTCAPB), \
	/* No access to TZC1, TZC2, TZPC */ \
	CLOCK_CELL(CLOCK_DEV_IDX_IWDG1, IWDG1), \
	/* No access to BSEC, STGEN. STGEN is alwyas on (shared clock?) */ \
	CLOCK_CELL(CLOCK_DEV_IDX_GPIOZ, GPIOZ), \
	CLOCK_CELL(CLOCK_DEV_IDX_CRYP1, CRYP1), \
	CLOCK_CELL(CLOCK_DEV_IDX_HASH1, HASH1), \
	CLOCK_CELL(CLOCK_DEV_IDX_RNG1, RNG1_K), \
	/* No access to BKPSRAM */ \

/*
 * The static way for storing the elements and module configuration data
 */

/* Clock from dummy clock are identified with a platform interger ID value */
#define STM32_CLOCK(_idx, _id)	[(_idx)] = {		\
                    .clock_id = (id),		\
		}

/* Module clock gets dummy_clock (FWK_MODULE_IDX_DUMMY_CLOCK) elements */
#define CLOCK(_idx, _id)  [(_idx)] = { \
		.driver_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_DUMMY_CLOCK, \
						 (_idx) /* same index */), \
		.api_id = FWK_ID_API_INIT(FWK_MODULE_IDX_DUMMY_CLOCK,	\
					  0 /* API type */),		\
	}

/*
 * SCMI clock binds to clock module (FWK_MODULE_IDX_CLOCK).
 * Common permissions for exposed clocks.
 */
#define SCMI_CLOCK(_idx)		[(_idx)] =  { \
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
#define STM32_CLOCK_ELT(_idx)	[_idx] = {		\
		.name = clock_table[(_idx)].name,	\
		.data = (void *)&stm32_clock_cfg[(_idx)], \
	}

#define CLOCK_ELT(_idx)		[(_idx)] = {		\
		.name = clock_table[(_idx)].name,	\
		.data = (void *)&clock_cfg[(_idx)],	\
	}

#define SCMI_CLOCK_ELT(_idx)	[(_idx)] = {		\
		.name = clock_table[(_idx)].name,	\
		.data = (void *)&scmi_clock_cfg[(_idx)], \
	}

/*
 * Elements for clock module: use a function to provide data:
 * FWK_ID_NONE type mandates being initialized at runtime.
 */
#undef CLOCK_CELL
#define CLOCK_CELL	CLOCK
static struct mod_clock_dev_config clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL	CLOCK_ELT
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

struct fwk_module_config config_clock = {
	.get_element_table = clock_config_desc_table,
};

/* Elements for stm32_clock module: define elements from data table */
#undef CLOCK_CELL
#define CLOCK_CELL	STM32_CLOCK
static const struct mod_stm32_clock_dev_config stm32_clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL	STM32_CLOCK_ELT
static const struct fwk_element stm32_clock_elt[] = {
	CLOCK_LIST
	{ } /* Terminal tag */
};

struct fwk_module_config config_stm32_clock = {
	.data =(void *)stm32_clock_elt,
};

/* Elements for SCMI clock module: define scmi_agent OSPM (TODO: get a name) */
#undef CLOCK_CELL
#define CLOCK_CELL	SCMI_CLOCK
static const struct mod_scmi_clock_device scmi_clock_cfg[] = {
	CLOCK_LIST
};

#undef CLOCK_CELL
#define CLOCK_CELL	SCMI_CLOCK_ELT
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

static const struct fwk_module_config config_scmi_clock = {
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
