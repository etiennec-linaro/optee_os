srcs-$(CFG_SCMI_SERVER_CLOCK) += config_clock.c
srcs-y += config_mhu_smt.c
srcs-y += config_scmi.c
ifeq ($(CFG_STPMIC1),y)
srcs-$(CFG_SCMI_SERVER_VOLTAGE_DOMAIN) += config_pmic_regu.c
endif
srcs-$(CFG_SCMI_SERVER_VOLTAGE_DOMAIN) += config_pwr_regu.c
srcs-$(CFG_SCMI_SERVER_VOLTAGE_DOMAIN) += config_voltd.c
srcs-$(CFG_SCMI_SERVER_RESET_DOMAIN) += config_scmi_reset_domains.c
