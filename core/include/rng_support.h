/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __RNG_SUPPORT_H__
#define __RNG_SUPPORT_H__

#include <stdint.h>

/* Return a random byte from a platform strong RNG */
uint8_t hw_get_random_byte(void);

/*
 * hw_get_available_entropy() - Get entropy accumulated by strong RNG
 *
 * @buf: output buffer to fill
 * @size: @out size in bytes
 * Return number of random byte filled in @out
 */
size_t hw_get_available_entropy(uint8_t *buf, size_t size);

/*
 * hw_get_entropy() - Get random bytes from strong RNG
 *
 * @buf: output buffer to fill
 * @size: @out size in bytes
 * Return number of random byte filled in @out
 */
size_t hw_get_entropy(uint8_t *buf, size_t size);


#endif /* __RNG_SUPPORT_H__ */
