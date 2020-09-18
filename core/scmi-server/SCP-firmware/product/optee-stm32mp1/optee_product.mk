scmi-server-product-modules-$(CFG_SCMI_SERVER_CLOCK) += stm32_clock
scmi-server-product-modules-$(CFG_SCMI_SERVER_RESET_DOMAIN) += stm32_reset
ifeq ($(CFG_STPMIC1),y)
scmi-server-product-modules-$(CFG_SCMI_SERVER_VOLTAGE_DOMAIN) += stm32_pmic_regu
endif
scmi-server-product-modules-$(CFG_SCMI_SERVER_VOLTAGE_DOMAIN) += stm32_pwr_regu
