
ifeq ($(CFG_WITH_SPCI),y)
srcs-y += thread.c
srcs-$(CFG_ARM64_core) += thread_a64.S

LDADD += `cat /media/vingu/vingu_ext/Linaro/Boards/FVP/SPCI_dev/SCP-firmware/build/product/optee/fw/release/obj/tmp.txt`
endif


