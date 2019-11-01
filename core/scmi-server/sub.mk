# Currently based on SCP-firmware revision 2.5.
SCMI_VERSION_MAJOR = 2
SCMI_VERSION_MINOR = 5
SCMI_VERSION_PATCH = 0

scmi-server-scp-path = SCP-firmware

# Internal build switches and directives
cppflags-lib-y += -DBUILD_VERSION_MAJOR=$(SCMI_VERSION_MAJOR) \
		  -DBUILD_VERSION_MINOR=$(SCMI_VERSION_MINOR) \
		  -DBUILD_VERSION_PATCH=$(SCMI_VERSION_PATCH)

cppflags-lib-y += -Wno-unused-parameter \
		  -Wno-unused-variable \
		  -Wno-suggest-attribute=format

cppflags-lib-y += -DBUILD_OPTEE

# Configuration switches for SCP-firmware specific configuration
define define-if-enable
cppflags-lib-y += $(if $(strip $(filter y,$$2)),-D$1,)
endef

$(eval $(call define-if-enable, BUILD_HAS_MULTITHREADING, \
				CFG_SCMI_SERVER_MULTITHREADING))
$(eval $(call define-if-enable, BUILD_HAS_NOTIFICATION, \
				CFG_SCMI_SERVER_NOTIFICATION))

srcs-y += scmi_server.c
subdirs-y += $(scmi-server-scp-path)/framework/src
