/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once

typedef struct {
	bool enabled;
	uint32_t interval;
	time_t next_timeout;
} timeout_t;

OSStatus timeout_init(timeout_t * data, int len);
OSStatus timeout_enable(int index, uint32_t interval);
OSStatus timeout_disable(int index);
OSStatus timeout_disable_all(void);
int timeout_get(void);
uint32_t timeout_next_timeout(void);
