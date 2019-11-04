# Currently based on SCP-firmware revision 2.5.
SCMI_VERSION_MAJOR = 2
SCMI_VERSION_MINOR = 5
SCMI_VERSION_PATCH = 0

scmi-server-scp-path = SCP-firmware

scmi-server-generic-modules-y += log scmi optee_smt optee_mhu
scmi-server-generic-modules-$(CFG_SCMI_SERVER_CLOCK) += clock scmi_clock
scmi-server-generic-modules-$(CFG_SCMI_SERVER_RESET_DOMAIN) += reset_domain scmi_reset_domain
scmi-server-generic-modules-$(CFG_SCMI_SERVER_POWER_DOMAIN) += power_domain scmi_power_domain

# Some modules header files must be visible
# (Alternate: use incdirs-lib$(libname)-$(sm) to list libs headers pathes)
global-incdirs-y += $(scmi-server-scp-path)/module/clock/include
global-incdirs-y += $(scmi-server-scp-path)/module/reset_domain/include
global-incdirs-y += $(scmi-server-scp-path)/module/power_domain/include

# Internal build switches and directives
cppflags-lib-y += -DBUILD_VERSION_MAJOR=$(SCMI_VERSION_MAJOR) \
		  -DBUILD_VERSION_MINOR=$(SCMI_VERSION_MINOR) \
		  -DBUILD_VERSION_PATCH=$(SCMI_VERSION_PATCH)

cppflags-lib-y += -Wno-unused-parameter \
		  -Wno-unused-variable \
		  -Wno-suggest-attribute=format

cppflags-lib-y += -DBUILD_OPTEE

# Configuration switches for SCP-firmware are enabled when defined or are
# enabled/disabled when defined to 1/0.
define define-if-enable
cppflags-lib-y += $(if $(strip $(filter y,$($2))),-D$1,)
endef
define define-as-binary
cppflags-lib-y += $(if $(strip $(filter y,$($2))),-D$1=1,-D$1=0)
endef

$(eval $(call define-if-enable,BUILD_HAS_MULTITHREADING,CFG_SCMI_SERVER_MULTITHREADING))
$(eval $(call define-if-enable,BUILD_HAS_NOTIFICATION,CFG_SCMI_SERVER_NOTIFICATION))

$(eval $(call define-as-binary,BUILD_HAS_MOD_CLOCK,CFG_SCMI_SERVER_CLOCK))
$(eval $(call define-as-binary,BUILD_HAS_MOD_POWER_DOMAIN,CFG_SCMI_SERVER_POWER_DOMAIN))
$(eval $(call define-as-binary,BUILD_HAS_MOD_RESET_DOMAIN,CFG_SCMI_SERVER_RESET_DOMAIN))

srcs-y += scmi_server.c
subdirs-y += $(scmi-server-scp-path)/framework/src

# Helper to add module source and header files in framework
# Used for generic modules and product specific modules
define scmi-server-add-module
global-incdirs-y += $1/module/$2/include
subdirs-y += $1/module/$2/src
endef

$(foreach m,$(scmi-server-generic-modules-y), \
    $(eval $(call scmi-server-add-module,$(scmi-server-scp-path),$(strip $(m)))))

# Generate fwk_module_idx.h and fwk_module_list.c
scmi-server-script = $(libdir)/$(scmi-server-scp-path)/tools/gen_module_code.py

scmi-server-out-path = $(out-dir)/$(libdir)
scmi-server-modules-y = $(scmi-server-generic-modules-y)

gensrcs-y += scmi_module_list
cleanfiles += $(scmi-server-out-path)/fwk_module_list.c
cleanfiles += $(scmi-server-out-path)/fwk_module_idx.h
produce-scmi_module_list = fwk_module_list.c
depends-scmi_module_list = $(1) $(scmi-server-script) FORCE
recipe-scmi_module_list = \
	$(scmi-server-script) --path $(scmi-server-out-path) \
		$(scmi-server-modules-y) > /dev/null

# fwk_module_idx.h must be build before source files are compiled
# hence it is a dependency for main target all.
cflags-lib$(libname)-$(sm) += -I$(out-dir)/$(libdir)
$(scmi-server-out-path)/fwk_module_idx.h: $(scmi-server-out-path)/fwk_module_list.c
all: $(scmi-server-out-path)/fwk_module_idx.h
