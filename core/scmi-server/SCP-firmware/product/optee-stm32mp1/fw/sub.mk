srcs-$(CFG_SCMI_SERVER_CLOCK) += config_clock.c
srcs-y += config_mhu_smt.c
srcs-y += config_scmi.c
srcs-$(CFG_SCMI_SERVER_RESET_DOMAIN) += config_scmi_reset_domains.c
srcs-$(CFG_SCMI_SERVER_VOLTAGE_DOMAIN) += config_scmi_voltage_domains.c
