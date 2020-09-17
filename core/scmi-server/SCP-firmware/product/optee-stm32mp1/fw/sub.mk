srcs-$(CFG_SCMI_SERVER_CLOCK) += config_clock.c
srcs-y += config_mhu_smt.c
srcs-$(CFG_SCMI_SERVER_RESET_DOMAIN) += config_reset_domain.c
srcs-y += config_scmi.c
srcs-$(CFG_SCMI_SERVER_VOLTAGE_DOMAIN) += config_pwr_regu.c
srcs-$(CFG_SCMI_SERVER_VOLTAGE_DOMAIN) += config_voltd.c
