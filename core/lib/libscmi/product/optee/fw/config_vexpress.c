// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

// Register 2 dummy clocks

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
#include <mod_dummy_clock.h>
#include <mod_scmi_clock.h>
#include <spci_scmi.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

/* Fake bindings for SCMI clock identifiers */
#include <dt-bindings/clock/vexpress_scmi_clks.h>

/* Platform internal identifer for the clock */
#define DUMMY_CLOCK_1_ID	0x0100
#define DUMMY_CLOCK_2_ID	0x0200
#define DUMMY_CLOCK_3_ID	0x0300
#define DUMMY_CLOCK_4_ID	0x0400

#define NSEC_CLOCK_LIST \
	CLOCK_CELL(CK_SCMI_DUMMY1, DUMMY_CLOCK_1_ID), \
	CLOCK_CELL(CK_SCMI_DUMMY2, DUMMY_CLOCK_2_ID), \
	CLOCK_CELL(CK_SCMI_DUMMY3, DUMMY_CLOCK_3_ID), \
	CLOCK_CELL(CK_SCMI_DUMMY4, DUMMY_CLOCK_4_ID), \

/*
 * Clock configuration: store only reference to name
 */
struct clock_ref {
	const char *name;
};
#define CLOCK_REF(_idx, _id)	[(_idx)] = {	\
		.name = #_id,			\
	}

#undef CLOCK_CELL
#define CLOCK_CELL 	CLOCK_REF

static const struct clock_ref clock_table[] = {
	CLOCK_REF(0x0100 /*a platform ID*/, CK_SCMI_DUMMY1),
	CLOCK_REF(0x0200 /*a platform ID*/, CK_SCMI_DUMMY2),
	CLOCK_REF(0x0300 /*a platform ID*/, CK_SCMI_DUMMY3),
	CLOCK_REF(0x0400 /*a platform ID*/, CK_SCMI_DUMMY4),
};

/*
 * The static way for storing the elements and module configuration data
 */

/*
 * Clock from dummy clock are identified with a platform interger ID value
 * Config provides a default state and the single supported rate.
 */
#define DUMMY_CLOCK(_idx, _id)	[(_idx)] = {		\
                    .clock_id = (_id),			\
                    .state = MOD_CLOCK_STATE_STOPPED,	\
                    .rate = 10 * 1000 * 1000,		\
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
#define SCMI_CLOCK(_idx, _id)		[(_idx)] =  { \
		.element_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK,	\
						  (_idx) /* same index */), \
		.permissions = MOD_SCMI_CLOCK_PERM_ATTRIBUTES |		\
			       MOD_SCMI_CLOCK_PERM_DESCRIBE_RATES |	\
			       MOD_SCMI_CLOCK_PERM_GET_RATE,		\
	}

/*
 * Framwork expects 1 element per module per clock:
 * - dummy_clock elements data configuration provided by dummy_clock_cfg[]
 * - clock elements data configuration provided by clock_cfg[]
 * - scmi_clock elements data configuration provided by scmi_clock_cfg[]
 */
#define DUMMY_CLOCK_ELT(_idx, _id)	[_idx] = {		\
		.name = #_id,	\
		.data = (void *)&dummy_clock_cfg[(_idx)], \
	}

#define CLOCK_ELT(_idx, _id)		[(_idx)] = {		\
		.name = #_id,	\
		.data = (void *)&clock_cfg[(_idx)],	\
	}

#define SCMI_CLOCK_ELT(_idx, _id)	[(_idx)] = {		\
		.name = #_id,	\
		.data = (void *)&scmi_clock_cfg[(_idx)], \
	}

/*
 * Elements for clock module: use a function to provide data:
 * FWK_ID_NONE type mandates being initialized at runtime.
 */
static struct mod_clock_dev_config clock_cfg[] = {
	CLOCK(CK_SCMI_DUMMY1, DUMMY_CLOCK_1_ID),
	CLOCK(CK_SCMI_DUMMY2, DUMMY_CLOCK_2_ID),
	CLOCK(CK_SCMI_DUMMY3, DUMMY_CLOCK_3_ID),
	CLOCK(CK_SCMI_DUMMY4, DUMMY_CLOCK_4_ID),
};
static const struct fwk_element clock_elt[] = {
	CLOCK_ELT(CK_SCMI_DUMMY1, DUMMY_CLOCK_1_ID),
	CLOCK_ELT(CK_SCMI_DUMMY2, DUMMY_CLOCK_2_ID),
	CLOCK_ELT(CK_SCMI_DUMMY3, DUMMY_CLOCK_3_ID),
	CLOCK_ELT(CK_SCMI_DUMMY4, DUMMY_CLOCK_4_ID),
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

/* Elements for dummy_clock module: define elements from data table */
static const struct mod_dummy_clock_dev_config dummy_clock_cfg[] = {
	DUMMY_CLOCK(CK_SCMI_DUMMY1, DUMMY_CLOCK_1_ID),
	DUMMY_CLOCK(CK_SCMI_DUMMY2, DUMMY_CLOCK_2_ID),
	DUMMY_CLOCK(CK_SCMI_DUMMY3, DUMMY_CLOCK_3_ID),
	DUMMY_CLOCK(CK_SCMI_DUMMY4, DUMMY_CLOCK_4_ID),
};

static const struct fwk_element dummy_clock_elt[] = {
	DUMMY_CLOCK_ELT(CK_SCMI_DUMMY1, DUMMY_CLOCK_2_ID),
	DUMMY_CLOCK_ELT(CK_SCMI_DUMMY2, DUMMY_CLOCK_1_ID),
	DUMMY_CLOCK_ELT(CK_SCMI_DUMMY3, DUMMY_CLOCK_3_ID),
	DUMMY_CLOCK_ELT(CK_SCMI_DUMMY4, DUMMY_CLOCK_4_ID),
	{ } /* Terminal tag */
};

static const struct fwk_element *dummy_clock_desc_table(fwk_id_t module_id)
{
	return dummy_clock_elt;
}

/* Exported in libscmi */
const struct fwk_module_config config_dummy_clock = {
	.get_element_table = dummy_clock_desc_table,
};

/* Elements for SCMI clock module: define scmi_agent OSPM (TODO: get a name) */
static const struct mod_scmi_clock_device scmi_clock_cfg[] = {
	SCMI_CLOCK(CK_SCMI_DUMMY1, DUMMY_CLOCK_1_ID),
	SCMI_CLOCK(CK_SCMI_DUMMY2, DUMMY_CLOCK_2_ID),
	SCMI_CLOCK(CK_SCMI_DUMMY3, DUMMY_CLOCK_3_ID),
	SCMI_CLOCK(CK_SCMI_DUMMY4, DUMMY_CLOCK_4_ID),
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


