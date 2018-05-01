/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once

#define N_ELEMENT(tbl)  (sizeof(tbl)/sizeof((tbl)[0]))
#define N_OFFSET(type, member)  ((uint32_t)(&(((type*)0)->member)))
#define N_SIZE(type, member)   ((sizeof)(((type*)0)->member))
