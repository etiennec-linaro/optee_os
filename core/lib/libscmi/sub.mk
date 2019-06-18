#
# Arm SCP/MCP Software
# Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# The order of the modules in the BS_FIRMWARE_MODULES list is the order in which
# the modules are initialized, bound, started during the pre-runtime phase.

$(call force,CFG_WITH_SPCI,y)

SCMI_VERSION_MAJOR = 2
SCMI_VERSION_MINOR = 4
SCMI_VERSION_PATCH = 0

#libscmi misses a generic include/ directory
#global-incdirs-y += include

# SCP-firmware does not follow some directives
cflags-y += -Wno-unused-parameter
cflags-y += -Wno-unused-variable
cflags-y += -Wno-suggest-attribute=format
# tricky in fwk id aggregated structure passed as return argument
cflags-framework/src/fwk_id.c-y = -Wno-aggregate-return
cflags-framework/src/fwk_module.c-y = -Wno-aggregate-return
cflags-framework/src/fwk_thread.c-y = -Wno-aggregate-return

cflags-y += -DBUILD_VERSION_MAJOR=$(SCMI_VERSION_MAJOR)
cflags-y += -DBUILD_VERSION_MINOR=$(SCMI_VERSION_MINOR)
cflags-y += -DBUILD_VERSION_PATCH=$(SCMI_VERSION_PATCH)

# Below are tested as if <MACRO>, expected defined to 0 or 1
cflags-y += -DBUILD_HAS_MOD_CLOCK=1
cflags-y += -DBUILD_HAS_MOD_POWER_DOMAIN=0
cflags-y += -DBUILD_HAS_MOD_CSS_CLOCK=0
cflags-y += -DBUILD_HAS_MOD_SYSTEM_POWER=0
cflags-y += -DBUILD_HAS_MOD_DMC500=0
# Below are tested as ifdef/ifndef
# -DBUILD_HAS_MULTITHREADING: do not enable fwk multi-threading
# -DBUILD_HAS_NOTIFICATION: do not enable fwk notification
# Enable hacky part in fwk_module.c (BUILD_OPTEE)
cflags-y += -DBUILD_OPTEE

# Generate fwk_module_idx.h and fwk_module_list.c
#
# TODO: Maybe no need to generate source files for this
# Static amount of modules embedded into the framwork (fwk)
#
libscmi_modules-y := log scmi
libscmi_modules-$(CFG_WITH_SPCI) += spci hmbx
libscmi_modules-$(CFG_SCMI_CLOCK) += clock scmi_clock
libscmi_modules-$(CFG_SCMI_POWER_DOMAIN) += scmi_power_domain
libscmi_modules-$(CFG_SCMI_STM32MP1) += stm32_clock
libscmi_modules-$(CFG_SCMI_DUMMY_CLOCK) += dummy_clock

gensrcs-y += scmi_module_list
libscmi-module-list-out = $(out-dir)/core/lib/libscmi
cleanfiles += $(libscmi-module-list-out)/fwk_module_list.c
cleanfiles += $(libscmi-module-list-out)/fwk_module_idx.h
produce-scmi_module_list = fwk_module_list.c
depends-scmi_module_list = core/lib/libscmi/tools/gen_module_code.py FORCE
recipe-scmi_module_list = \
	echo "SCMI libscmi module list: $(libscmi_modules-y)" && \
	core/lib/libscmi/tools/gen_module_code.py \
		--path $(libscmi-module-list-out) \
		$(libscmi_modules-y) > /dev/null

# Build libscmi with:
# - product/optee: modules configuration and local mmodules
# - module/xxx: SCMI related modules and few generic ones
# - framework: fwk stuff, likely more than needed.
global-incdirs-y += module/clock/include
global-incdirs-y += module/log/include
global-incdirs-y += module/power_domain/include
global-incdirs-y += module/scmi/include
global-incdirs-y += module/scmi_clock/include
global-incdirs-y += module/scmi_power_domain/include
global-incdirs-y += product/optee/include
global-incdirs-y += product/optee/module/dummy_clock/include
global-incdirs-y += product/optee/module/hmbx/include
global-incdirs-y += product/optee/module/stm32_clock/include

srcs-y += product/optee/module/log/src/mod_log.c

srcs-y += module/scmi/src/mod_scmi.c
srcs-$(CFG_SCMI_CLOCK) += module/clock/src/mod_clock.c
srcs-$(CFG_SCMI_CLOCK) += module/scmi_clock/src/mod_scmi_clock.c
srcs-$(CFG_WITH_SPCI) += product/optee/module/hmbx/src/mod_hmbx.c
srcs-$(CFG_WITH_SPCI) += product/optee/module/spci/src/mod_spci.c

srcs-$(CFG_SCMI_DUMMY_CLOCK) += product/optee/module/dummy_clock/src/mod_dummy_clock.c

srcs-y += product/optee/fw/config_hmbx.c
srcs-y += product/optee/fw/config_scmi.c

srcs-$(CFG_SCMI_VEXPRESS) += product/optee/fw/config_vexpress.c

global-incdirs-y += framework/include
srcs-y += arch/src/optee.c
srcs-y += framework/src/fwk_assert.c
srcs-y += framework/src/fwk_dlist.c
srcs-y += framework/src/fwk_id.c
srcs-y += framework/src/fwk_interrupt.c
srcs-y += framework/src/fwk_module.c
srcs-y += framework/src/fwk_slist.c
srcs-y += framework/src/fwk_thread.c
