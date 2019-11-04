/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *     OP-TEE mailbox buffer layer
 */

#ifndef MOD_OPTEE_MHU_H
#define MOD_OPTEE_MHU_H

/*!
 * \brief Signal a SMT message
 */
void optee_mhu_signal_smt_message(unsigned int device_index, unsigned int slot_index);

#endif /* MOD_OPTEE_MHU_H */
