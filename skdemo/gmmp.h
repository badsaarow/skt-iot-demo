/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once

typedef struct
{
	uint8_t version;	/* GMMP Versino */
	uint16_t length;	/* GMMP Message Length including header */
	uint8_t type;		/* GMMP Message Type */

	uint32_t timestamp;	/* GMMP Origin Time Stamp (Unix Epoch Time) */
	uint16_t total_count;	/* GMMP Total Count */
	uint16_t current_count;	/* GMMP Current Count */
	uint8_t auth_id[16];	/* GMMP Auth ID */
	uint8_t auth_key[16];	/* GMMP Auth Key */
	uint32_t tid;		/* Transaction ID */
	uint8_t encrypted;	/* Encrypted Field */
	uint8_t reserved;	/* Reserved */
} __attribute__((packed)) gmmp_header_t;

