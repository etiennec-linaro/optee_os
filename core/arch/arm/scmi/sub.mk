ifeq ($(CFG_WITH_SPCI),y)
srcs-y += thread.c
srcs-$(CFG_ARM64_core) += thread_a64.S
srcs-$(CFG_ARM32_core) += thread_a32.S

LDADD += `cat $(HOME)/Projects/stm32mp1-1.0/SCP-firmware/build/product/optee/fw/release/obj/tmp.txt`
endif


