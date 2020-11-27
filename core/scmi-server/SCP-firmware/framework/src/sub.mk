global-incdirs-y += ../include

# There is a trick in fwk id aggregated structure passed as return argument
cflags-fwk_id.c-y = -Wno-aggregate-return
cflags-fwk_module.c-y = -Wno-aggregate-return
cflags-fwk_thread.c-y = -Wno-aggregate-return

# Non NULL comparision reported in list helper functions
cflags-fwk_dlist.c-y = -Wno-nonnull-compare
cflags-fwk_slist.c-y = -Wno-nonnull-compare

srcs-no += assert.c
srcs-y += fwk_arch.c
srcs-y += fwk_dlist.c
srcs-y += fwk_id.c
srcs-y += fwk_interrupt.c
srcs-no += fwk_io.c
srcs-no += fwk_log.c
srcs-no += fwk_mm.c
srcs-y += fwk_module.c
srcs-y += fwk_slist.c
srcs-y += fwk_status.c
ifeq ($(CFG_SCMI_SERVER_MULTITHREADING),y)
srcs-y += fwk_multi_thread.c
else
srcs-y += fwk_thread.c
endif
srcs-$(CFG_SCMI_SERVER_NOTIFICATION) += fwk_notification.c
srcs-$(CFG_SCMI_SERVER_NOTIFICATION) += fwk_thread_delayed_resp.c
srcs-no += fwk_time.c
