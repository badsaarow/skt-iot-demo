/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"
#include "timeout.h"
#include "smarthome_conf.h"

static int timeout_len;
static timeout_t *timeout_table;

uint32_t timeout_next_timeout(void)
{
    int i;
    time_t cur = time(NULL);
    uint32_t next = 0x7fffffff;
    int diff;

    for (i = 0; i < timeout_len; i++) {
	if (!timeout_table[i].enabled)
	    continue;

	diff = timeout_table[i].next_timeout - cur;
	if (diff <= 0)
	    return 0;
	if (next > diff)
	    next = diff;
    }
    return next;
}

int timeout_get(void)
{
    int i;
    time_t cur = time(NULL);

    for (i = 0; i < timeout_len; i++) {
	if (timeout_table[i].enabled && cur - timeout_table[i].next_timeout >= 0) {
	    timeout_table[i].next_timeout = cur + timeout_table[i].interval;
	    return i;
	}
    }
    return -1;
}

OSStatus timeout_disable(int index)
{
    OSStatus err = kNoErr;
    require_action(index >= 0 && index < timeout_len, exit, err = kRangeErr);
    timeout_table[index].enabled = false;
    omp_log("Disable timeout: index=%d", index);
  exit:
    return err;
}

OSStatus timeout_disable_all(void)
{
    memset(timeout_table, 0, sizeof(timeout_t) * timeout_len);
    omp_log("Disable timeout all");
    return kNoErr;
}

OSStatus timeout_enable(int index, uint32_t interval)
{
    time_t cur;
    OSStatus err = kNoErr;
    require_action(index >= 0 && index < timeout_len, exit, err = kRangeErr);

    omp_log("Enable timeout: index=%d, interval=%lu", index, interval);
    cur = time(NULL);
    timeout_table[index].interval = interval;
    timeout_table[index].next_timeout = cur + interval;
    timeout_table[index].enabled = true;
  exit:
    return err;
}

OSStatus timeout_init(timeout_t * data, int len)
{
    memset(data, 0, sizeof(timeout_t) * len);
    timeout_table = data;
    timeout_len = len;
    return kNoErr;
}
