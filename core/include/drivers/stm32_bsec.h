/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2015-2018, STMicroelectronics
 */

#ifndef __STM32_BSEC_H__
#define __STM32_BSEC_H__

#include <stdint.h>
#include <io.h>

#define BSEC_OTP_MASK			GENMASK_32(4, 0)
#define BSEC_OTP_BANK_SHIFT		5

#define BSEC_TIMEOUT_VALUE		0xFFFF

#define ADDR_LOWER_OTP_PERLOCK_SHIFT	3
#define DATA_LOWER_OTP_PERLOCK_BIT	3
#define DATA_LOWER_OTP_PERLOCK_MASK	GENMASK_32(2, 0)
#define ADDR_UPPER_OTP_PERLOCK_SHIFT	4
#define DATA_UPPER_OTP_PERLOCK_BIT	1
#define DATA_UPPER_OTP_PERLOCK_MASK	GENMASK_32(3, 0)

/* Return status */
#define BSEC_OK				0U
#define BSEC_ERROR			0xFFFFFFFFU
#define BSEC_DISTURBED			0xFFFFFFFEU
#define BSEC_INVALID_PARAM		0xFFFFFFFCU
#define BSEC_PROG_FAIL			0xFFFFFFFBU
#define BSEC_LOCK_FAIL			0xFFFFFFFAU
#define BSEC_WRITE_FAIL			0xFFFFFFF9U
#define BSEC_SHADOW_FAIL		0xFFFFFFF8U
#define BSEC_TIMEOUT			0xFFFFFFF7U

/* BSEC REGISTER OFFSET (base relative) */
#define BSEC_OTP_CONF_OFF		0x000U
#define BSEC_OTP_CTRL_OFF		0x004U
#define BSEC_OTP_WRDATA_OFF		0x008U
#define BSEC_OTP_STATUS_OFF		0x00CU
#define BSEC_OTP_LOCK_OFF		0x010U
#define BSEC_DEN_OFF			0x014U
#define BSEC_FEN_OFF			0x018U
#define BSEC_DISTURBED_OFF		0x01CU
#define BSEC_DISTURBED1_OFF		0x020U
#define BSEC_DISTURBED2_OFF		0x024U
#define BSEC_ERROR_OFF			0x034U
#define BSEC_ERROR1_OFF			0x038U
#define BSEC_ERROR2_OFF			0x03CU
#define BSEC_WRLOCK_OFF			0x04CU
#define BSEC_WRLOCK1_OFF		0x050U
#define BSEC_WRLOCK2_OFF		0x054U
#define BSEC_SPLOCK_OFF			0x064U
#define BSEC_SPLOCK1_OFF		0x068U
#define BSEC_SPLOCK2_OFF		0x06CU
#define BSEC_SWLOCK_OFF			0x07CU
#define BSEC_SWLOCK1_OFF		0x080U
#define BSEC_SWLOCK2_OFF		0x084U
#define BSEC_SRLOCK_OFF			0x094U
#define BSEC_SRLOCK1_OFF		0x098U
#define BSEC_SRLOCK2_OFF		0x09CU
#define BSEC_JTAG_IN_OFF		0x0ACU
#define BSEC_JTAG_OUT_OFF		0x0B0U
#define BSEC_SCRATCH_OFF		0x0B4U
#define BSEC_OTP_DATA_OFF		0x200U
#define BSEC_IPHW_CFG_OFF		0xFF0U
#define BSEC_IPVR_OFF			0xFF4U
#define BSEC_IP_ID_OFF			0xFF8U
#define BSEC_IP_MAGIC_ID_OFF		0xFFCU

/* BSEC_CONFIGURATION Register */
#define BSEC_CONF_POWER_UP_MASK		BIT(0)
#define BSEC_CONF_POWER_UP_SHIFT	0
#define BSEC_CONF_FRQ_MASK		GENMASK_32(2, 1)
#define BSEC_CONF_FRQ_SHIFT		1
#define BSEC_CONF_PRG_WIDTH_MASK	GENMASK_32(6, 3)
#define BSEC_CONF_PRG_WIDTH_SHIFT	3
#define BSEC_CONF_TREAD_MASK		GENMASK_32(8, 7)
#define BSEC_CONF_TREAD_SHIFT		7

/* BSEC_CONTROL Register */
#define BSEC_READ			0x000U
#define BSEC_WRITE			0x100U
#define BSEC_LOCK			0x200U

/* STATUS Register */
#define BSEC_MODE_STATUS_MASK		GENMASK_32(2, 0)
#define BSEC_MODE_BUSY_MASK		BIT(3)
#define BSEC_MODE_PROGFAIL_MASK		BIT(4)
#define BSEC_MODE_PWR_MASK		BIT(5)
#define BSEC_MODE_BIST1_LOCK_MASK	BIT(6)
#define BSEC_MODE_BIST2_LOCK_MASK	BIT(7)

/* Debug */
#define BSEC_HDPEN			BIT(4)
#define BSEC_SPIDEN			BIT(5)
#define BSEC_SPINDEN			BIT(6)
#define BSEC_DBGSWGEN			BIT(10)
#define BSEC_DEN_ALL_MSK		GENMASK_32(10, 0)

/*
 * OTP Lock services definition
 * Value must corresponding to the bit position in the register
 */
#define BSEC_LOCK_UPPER_OTP		0x00
#define BSEC_LOCK_DEBUG			0x02
#define BSEC_LOCK_PROGRAM		0x03

/* Values for struct bsec_config::freq */
#define FREQ_10_20_MHZ			0x0
#define FREQ_20_30_MHZ			0x1
#define FREQ_30_45_MHZ			0x2
#define FREQ_45_67_MHZ			0x3

uint32_t bsec_shadow_register(uint32_t otp);
uint32_t bsec_read_otp(uint32_t *val, uint32_t otp);
uint32_t bsec_write_otp(uint32_t val, uint32_t otp);
uint32_t bsec_program_otp(uint32_t val, uint32_t otp);
uint32_t bsec_permanent_lock_otp(uint32_t otp);

uint32_t bsec_write_debug_conf(uint32_t val);
uint32_t bsec_read_debug_conf(void);

uint32_t bsec_get_status(void);
uint32_t bsec_get_hw_conf(void);
uint32_t bsec_get_version(void);
uint32_t bsec_get_id(void);
uint32_t bsec_get_magic_id(void);

bool bsec_write_sr_lock(uint32_t otp, uint32_t value);
bool bsec_read_sr_lock(uint32_t otp);
bool bsec_write_sw_lock(uint32_t otp, uint32_t value);
bool bsec_read_sw_lock(uint32_t otp);
bool bsec_write_sp_lock(uint32_t otp, uint32_t value);
bool bsec_read_sp_lock(uint32_t otp);
bool bsec_wr_lock(uint32_t otp);
uint32_t bsec_otp_lock(uint32_t service, uint32_t value);

bool bsec_mode_is_closed_device(void);
uint32_t bsec_shadow_read_otp(uint32_t *otp_value, uint32_t word);
uint32_t bsec_check_nsec_access_rights(uint32_t otp);

#endif /*__STM32_BSEC_H__*/
