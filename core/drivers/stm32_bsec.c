// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#include <assert.h>
#include <drivers/stm32_bsec.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/spinlock.h>
#include <limits.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <stm32_util.h>
#include <util.h>

static uint32_t bsec_power_safmem(bool enable);

/* BSEC access protection */
static unsigned int lock = SPINLOCK_UNLOCK;

static uint32_t bsec_lock(void)
{
	return may_spin_lock(&lock);
}

static void bsec_unlock(uint32_t exceptions)
{
	return may_spin_unlock(&lock, exceptions);
}

static uint32_t otp_bank_offset(uint32_t otp)
{
	assert(otp <= stm32mp_get_otp_max());

	return ((otp & ~BSEC_OTP_MASK) >> BSEC_OTP_BANK_SHIFT) *
		sizeof(uint32_t);
}

static uintptr_t bsec_base(void)
{
	return stm32mp_get_bsec_base();
}

/*
 * bsec_check_error
 * otp: OTP number.
 * return: BSEC_OK on success, else a BSEC_xxx error core
 */
static uint32_t bsec_check_error(uint32_t otp)
{
	uint32_t bit = BIT(otp & BSEC_OTP_MASK);
	uint32_t bank = otp_bank_offset(otp);

	if (read32(bsec_base() + BSEC_DISTURBED_OFF + bank) & bit)
		return BSEC_DISTURBED;

	if (read32(bsec_base() + BSEC_ERROR_OFF + bank) & bit)
		return BSEC_ERROR;

	return BSEC_OK;
}

/*
 * bsec_shadow_register: Copy SAFMEM OTP to BSEC data.
 * otp: OTP number.
 * return: BSEC_OK on success, else a BSEC_xxx error core
 */
uint32_t bsec_shadow_register(uint32_t otp)
{
	uint32_t result;
	uint32_t exc;

	if (otp > stm32mp_get_otp_max())
		return BSEC_INVALID_PARAM;

	/* Check if shadowing of OTP is locked */
	if (bsec_read_sr_lock(otp))
		IMSG("BSEC : OTP locked, register will not be refreshed");

	result = bsec_power_safmem(true);
	if (result != BSEC_OK)
		return result;

	exc = bsec_lock();

	write32(otp | BSEC_READ, bsec_base() + BSEC_OTP_CTRL_OFF);

	while (bsec_get_status() & BSEC_MODE_BUSY_MASK)
		;

	result = bsec_check_error(otp);

	bsec_unlock(exc);

	bsec_power_safmem(false);

	return result;
}

/*
 * bsec_read_otp: Read an OTP data value
 * val: Output read value
 * otp: OTP number
 * return: BSEC_OK on success, else a BSEC_xxx error core
 */
uint32_t bsec_read_otp(uint32_t *val, uint32_t otp)
{
	uint32_t exc;
	uint32_t result;

	if (otp > stm32mp_get_otp_max())
		return BSEC_INVALID_PARAM;

	exc = bsec_lock();

	*val = read32(bsec_base() + BSEC_OTP_DATA_OFF +
		      (otp * sizeof(uint32_t)));

	result = bsec_check_error(otp);

	bsec_unlock(exc);

	return result;
}

/*
 * bsec_write_otp: Write value in BSEC data register
 * val: Value to write
 * otp: OTP number
 * return: BSEC_OK on success, else a BSEC_xxx error core
 */
uint32_t bsec_write_otp(uint32_t val, uint32_t otp)
{
	uint32_t exc;
	uint32_t result;

	if (otp > stm32mp_get_otp_max())
		return BSEC_INVALID_PARAM;

	/* Check if programming of OTP is locked */
	if (bsec_read_sw_lock(otp))
		IMSG("BSEC : OTP locked, write will be ignored");

	exc = bsec_lock();

	write32(val, bsec_base() + BSEC_OTP_DATA_OFF +
		(otp * sizeof(uint32_t)));

	result = bsec_check_error(otp);

	bsec_unlock(exc);

	return result;
}

/*
 * bsec_program_otp: Program a bit in SAFMEM without BSEC data refresh
 * val: Value to program.
 * otp: OTP number.
 * return: BSEC_OK on success, else a BSEC_xxx error core
 */
uint32_t bsec_program_otp(uint32_t val, uint32_t otp)
{
	uint32_t result;
	uint32_t exc;

	if (otp > stm32mp_get_otp_max())
		return BSEC_INVALID_PARAM;

	/* Check if programming of OTP is locked */
	if (bsec_read_sp_lock(otp))
		IMSG("BSEC : OTP locked, prog will be ignored");

	if (read32(bsec_base() + BSEC_OTP_LOCK_OFF) & BIT(BSEC_LOCK_PROGRAM))
		IMSG("BSEC : GPLOCK activated, prog will be ignored");

	result = bsec_power_safmem(true);
	if (result != BSEC_OK)
		return result;

	exc = bsec_lock();

	write32(val, bsec_base() + BSEC_OTP_WRDATA_OFF);
	write32(otp | BSEC_WRITE, bsec_base() + BSEC_OTP_CTRL_OFF);

	while ((bsec_get_status() & BSEC_MODE_BUSY_MASK) == 0U)
		;

	if (bsec_get_status() & BSEC_MODE_PROGFAIL_MASK)
		result = BSEC_PROG_FAIL;
	else
		result = bsec_check_error(otp);

	bsec_unlock(exc);

	bsec_power_safmem(false);

	return result;
}

/*
 * bsec_permanent_lock_otp: Permanent lock of OTP in SAFMEM
 * otp: OTP number
 * return: BSEC_OK on success, else a BSEC_xxx error core
 */
uint32_t bsec_permanent_lock_otp(uint32_t otp)
{
	uint32_t result;
	uint32_t data;
	uint32_t addr;
	uint32_t exc;

	if (otp > stm32mp_get_otp_max())
		return BSEC_INVALID_PARAM;

	result = bsec_power_safmem(true);
	if (result != BSEC_OK)
		return result;

	if (otp < stm32mp_get_otp_upper_start()) {
		addr = otp >> ADDR_LOWER_OTP_PERLOCK_SHIFT;
		data = DATA_LOWER_OTP_PERLOCK_BIT <<
		       ((otp & DATA_LOWER_OTP_PERLOCK_MASK) << 1U);
	} else {
		addr = (otp >> ADDR_UPPER_OTP_PERLOCK_SHIFT) + 2U;
		data = DATA_UPPER_OTP_PERLOCK_BIT <<
		       (otp & DATA_UPPER_OTP_PERLOCK_MASK);
	}

	exc = bsec_lock();

	write32(data, bsec_base() + BSEC_OTP_WRDATA_OFF);
	write32(addr | BSEC_WRITE | BSEC_LOCK, bsec_base() + BSEC_OTP_CTRL_OFF);

	while (bsec_get_status() & BSEC_MODE_BUSY_MASK)
		;

	if (bsec_get_status() & BSEC_MODE_PROGFAIL_MASK)
		result = BSEC_PROG_FAIL;
	else
		result = bsec_check_error(otp);

	bsec_unlock(exc);

	bsec_power_safmem(false);

	return result;
}

/*
 * bsec_write_debug_conf: Enable/disable debug service
 * val: Value to write
 * return: BSEC_OK on success, else a BSEC_xxx error core
 */
uint32_t bsec_write_debug_conf(uint32_t val)
{
	uint32_t result = BSEC_ERROR;
	uint32_t masked_val = val & BSEC_DEN_ALL_MSK;
	unsigned int exc;

	exc = bsec_lock();

	write32(val, bsec_base() + BSEC_DEN_OFF);

	if ((read32(bsec_base() + BSEC_DEN_OFF) ^ masked_val) == 0U)
		result = BSEC_OK;

	bsec_unlock(exc);

	return result;
}

/*
 * bsec_read_debug_conf : Read debug configuration
 */
uint32_t bsec_read_debug_conf(void)
{
	return read32(bsec_base() + BSEC_DEN_OFF);
}

/*
 * bsec_get_status : Return status register value
 */
uint32_t bsec_get_status(void)
{
	return read32(bsec_base() + BSEC_OTP_STATUS_OFF);
}

/*
 * bsec_get_hw_conf : Return hardware configuration
 */
uint32_t bsec_get_hw_conf(void)
{
	return read32(bsec_base() + BSEC_IPHW_CFG_OFF);
}

/*
 * bsec_get_version : Return BSEC version
 */
uint32_t bsec_get_version(void)
{
	return read32(bsec_base() + BSEC_IPVR_OFF);
}

/*
 * bsec_get_id : Return BSEC ID
 */
uint32_t bsec_get_id(void)
{
	return read32(bsec_base() + BSEC_IP_ID_OFF);
}

/*
 * bsec_get_magic_id : Return BSEC magic number
 */
uint32_t bsec_get_magic_id(void)
{
	return read32(bsec_base() + BSEC_IP_MAGIC_ID_OFF);
}

/*
 * bsec_write_sr_lock: Write shadow-read lock
 * otp: OTP number
 * value: Value to write in the register, must be non null
 * return: True if OTP is locked, else false
 */
bool bsec_write_sr_lock(uint32_t otp, uint32_t value)
{
	uint32_t bank = otp_bank_offset(otp);
	uint32_t bank_value;
	uint32_t otp_mask = BIT(otp & BSEC_OTP_MASK);
	uint32_t exc;

	if (!value)
		return false;

	exc = bsec_lock();

	bank_value = read32(bsec_base() + BSEC_SRLOCK_OFF + bank);

	if ((bank_value & otp_mask) != value) {
		/*
		 * We can write 0 in all other OTP
		 * if the lock is activated in one of other OTP.
		 * Write 0 has no effect.
		 */
		write32(bank_value | otp_mask,
			bsec_base() + BSEC_SRLOCK_OFF + bank);
	}

	bsec_unlock(exc);

	return true;
}

/*
 * bsec_read_sr_lock: Read shadow-read lock
 * otp: OTP number
 * return: True if otp is locked, else false
 */
bool bsec_read_sr_lock(uint32_t otp)
{
	uint32_t bank = otp_bank_offset(otp);
	uint32_t otp_mask = BIT(otp & BSEC_OTP_MASK);
	uint32_t bank_value = read32(bsec_base() + BSEC_SRLOCK_OFF + bank);

	return (bank_value & otp_mask) != 0U;
}

/*
 * bsec_write_sw_lock: Write shadow-write lock
 * otp: OTP number
 * value: Value to write in the register, must be non null
 * return: True if OTP is locked, else false
 */
bool bsec_write_sw_lock(uint32_t otp, uint32_t value)
{
	uint32_t bank = otp_bank_offset(otp);
	uint32_t otp_mask = BIT(otp & BSEC_OTP_MASK);
	uint32_t bank_value;
	unsigned int exc;

	if (!value)
		return false;

	exc = bsec_lock();

	bank_value = read32(bsec_base() + BSEC_SWLOCK_OFF + bank);

	if ((bank_value & otp_mask) != value) {
		/*
		 * We can write 0 in all other OTP
		 * if the lock is activated in one of other OTP.
		 * Write 0 has no effect.
		 */
		write32(bank_value | otp_mask,
			bsec_base() + BSEC_SWLOCK_OFF + bank);
	}

	bsec_unlock(exc);

	return true;
}

/*
 * bsec_read_sw_lock: Read shadow-write lock
 * otp: OTP number
 * return: True if OTP is locked, else false
 */
bool bsec_read_sw_lock(uint32_t otp)
{
	uint32_t bank = otp_bank_offset(otp);
	uint32_t otp_mask = BIT(otp & BSEC_OTP_MASK);
	uint32_t bank_value = read32(bsec_base() + BSEC_SWLOCK_OFF + bank);

	return (bank_value & otp_mask) != 0U;
}

/*
 * bsec_write_sp_lock: Write shadow-program lock
 * otp: OTP number
 * value: Value to write in the register, must be non null
 * return: True if OTP is locked, else false
 */
bool bsec_write_sp_lock(uint32_t otp, uint32_t value)
{
	uint32_t bank = otp_bank_offset(otp);
	uint32_t bank_value;
	uint32_t otp_mask = BIT(otp & BSEC_OTP_MASK);
	unsigned int exc;

	if (!value)
		return false;

	exc = bsec_lock();

	bank_value = read32(bsec_base() + BSEC_SPLOCK_OFF + bank);

	if ((bank_value & otp_mask) != value) {
		/*
		 * We can write 0 in all other OTP
		 * if the lock is activated in one of other OTP.
		 * Write 0 has no effect.
		 */
		write32(bank_value | otp_mask,
			bsec_base() + BSEC_SPLOCK_OFF + bank);
	}

	bsec_unlock(exc);

	return true;
}

/*
 * bsec_read_sp_lock: Read shadow-program lock
 * otp: OTP number
 * return: True if OTP is locked, else false
 */

bool bsec_read_sp_lock(uint32_t otp)
{
	uint32_t bank = otp_bank_offset(otp);
	uint32_t otp_mask = BIT(otp & BSEC_OTP_MASK);
	uint32_t bank_value = read32(bsec_base() + BSEC_SPLOCK_OFF + bank);

	return (bank_value & otp_mask) != 0U;
}

/*
 * bsec_wr_lock: Read permanent lock status
 * otp: OTP number
 * return: True if OTP is locked, else false
 */
bool bsec_wr_lock(uint32_t otp)
{
	uint32_t bank = otp_bank_offset(otp);
	uint32_t lock_bit = BIT(otp & BSEC_OTP_MASK);

	if ((read32(bsec_base() + BSEC_WRLOCK_OFF + bank) & lock_bit) != 0U) {
		/*
		 * In case of write don't need to write,
		 * the lock is already set.
		 */
		return true;
	}

	return false;
}

/*
 * bsec_otp_lock: Lock Upper OTP or Global programming or debug enable
 * service: Service to lock see header file
 * value: Value to write must always set to 1 (only use for debug purpose)
 * return: BSEC_OK if succeed
 */
uint32_t bsec_otp_lock(uint32_t service, uint32_t value)
{
	uintptr_t reg = bsec_base() + BSEC_OTP_LOCK_OFF;

	switch (service) {
	case BSEC_LOCK_UPPER_OTP:
		write32(value << BSEC_LOCK_UPPER_OTP, reg);
		break;
	case BSEC_LOCK_DEBUG:
		write32(value << BSEC_LOCK_DEBUG, reg);
		break;
	case BSEC_LOCK_PROGRAM:
		write32(value << BSEC_LOCK_PROGRAM, reg);
		break;
	default:
		return BSEC_INVALID_PARAM;
	}

	return BSEC_OK;
}

static uint32_t enable_power(void)
{
	size_t cntdown;

	io_mask32(bsec_base() + BSEC_OTP_CONF_OFF, BSEC_CONF_POWER_UP_MASK,
		  BSEC_CONF_POWER_UP_MASK);

	for (cntdown = BSEC_TIMEOUT_VALUE; cntdown; cntdown--)
		if (bsec_get_status() & BSEC_MODE_PWR_MASK)
			break;

	return cntdown ? BSEC_OK : BSEC_TIMEOUT;
}

static uint32_t disable_power(void)
{
	size_t cntdown;

	io_mask32(bsec_base() + BSEC_OTP_CONF_OFF, 0, BSEC_CONF_POWER_UP_MASK);

	for (cntdown = BSEC_TIMEOUT_VALUE; cntdown; cntdown--)
		if (!(bsec_get_status() & BSEC_MODE_PWR_MASK))
			break;

	return cntdown ? BSEC_OK : BSEC_TIMEOUT;
}

/*
 * bsec_power_safmem: Activate or deactivate SAFMEM power.
 * power: True to power up, false to power down
 * return: BSEC_OK if succeed
 */
static uint32_t bsec_power_safmem(bool enable)
{
	static unsigned int refcnt = ~0UL;
	uint32_t result = BSEC_OK;
	uint32_t exc = 0;

	/* Get the initial state */
	if (refcnt == ~0UL) {
		refcnt = !!(bsec_get_status() & BSEC_MODE_PWR_MASK);
		DMSG("Reset SAFMEM refcnt to %u", refcnt);
	}

	exc = bsec_lock();

	if (enable && (incr_refcnt(&refcnt) != 0U))
		result = enable_power();

	if (!enable && (decr_refcnt(&refcnt) != 0U))
		result = disable_power();

	bsec_unlock(exc);

	return result;
}

/*
 * bsec_mode_is_closed_device: Read OTP secure sub-mode.
 * return: False if open_device and true if closed_device.
 */
bool bsec_mode_is_closed_device(void)
{
	uint32_t value;

	if ((bsec_shadow_register(DATA0_OTP) != BSEC_OK) ||
	    (bsec_read_otp(&value, DATA0_OTP) != BSEC_OK)) {
		return true;
	}

	return (value & DATA0_OTP_SECURED) == DATA0_OTP_SECURED;
}

/*
 * bsec_shadow_read_otp: Load OTP from SAFMEM and provide its value
 * otp_value: Output read value
 * word: OTP number
 * return value: BSEC_OK if no error
 */
uint32_t bsec_shadow_read_otp(uint32_t *otp_value, uint32_t word)
{
	uint32_t result;

	result = bsec_shadow_register(word);
	if (result != BSEC_OK) {
		EMSG("BSEC: %u Shadowing Error %i\n", word, result);
		return result;
	}

	result = bsec_read_otp(otp_value, word);
	if (result != BSEC_OK)
		EMSG("BSEC: %u Read Error %i\n", word, result);

	return result;
}

/*
 * bsec_check_nsec_access_rights: Check non-secure access rights to target OTP
 * otp: OTP number
 * return: BSEC_OK if authorized access
 */
uint32_t bsec_check_nsec_access_rights(uint32_t otp)
{
	if (otp > stm32mp_get_otp_max())
		return BSEC_INVALID_PARAM;

	if (otp >= stm32mp_get_otp_upper_start() &&
	    bsec_mode_is_closed_device())
		return BSEC_ERROR;

	return BSEC_OK;
}

