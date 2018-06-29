/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once

#include "smarthome_conf.h"

#define HEARTBEAT_INTERVAL	60

typedef enum {
    GMMP_GW_REG_REQ		= 0x01,
    GMMP_GW_REG_RESP		= 0x02,
    GMMP_GW_DEREG_REQ		= 0x03,
    GMMP_GW_DEREG_RESP		= 0x04,
    GMMP_CTRL_REQ		= 0x0d,
    GMMP_CTRL_RESP		= 0x0e,
    GMMP_HEARTBEAT_REQ		= 0x0f,
    GMMP_HEARTBEAT_RESP		= 0x10,
    GMMP_CTRL_NOTI		= 0x17,
    GMMP_CTRL_NOTI_RESP		= 0x18,
    GMMP_ENC_INFO_REQ		= 0x19,
    GMMP_ENC_INFO_RESP		= 0x1a,
    GMMP_SET_ENC_KEY_REQ	= 0x1b,
    GMMP_SET_ENC_KEY_RESP	= 0x1c
} gmmp_type_t;


typedef struct {
    uint8_t ver;		/* GMMP Versino */
    uint16_t len;		/* GMMP Message Length including header */
    uint8_t type;		/* GMMP Message Type */

    uint32_t timestamp;		/* GMMP Origin Time Stamp (Unix Epoch Time) */
    uint16_t total_count;	/* GMMP Total Count */
    uint16_t current_count;	/* GMMP Current Count */
    uint8_t auth_id[LEN_SERIAL_NUMBER];	/* GMMP Auth ID */
    uint8_t auth_key[LEN_AUTH_KEY];	/* GMMP Auth Key */
    uint32_t tid;		/* Transaction ID */
    uint8_t encrypted;		/* Encrypted Field */
    uint8_t reserved;		/* Reserved */
} __attribute__((packed)) gmmp_header_t;

typedef struct _gw_reg_req_t {
    char domain_code[LEN_DOMAIN_CODE];
    char manufacture_id[LEN_MANUFACTURE_ID];
} __attribute__((packed)) gw_reg_req_t;

typedef struct _gw_reg_resp_t {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    uint8_t result_code;
} __attribute__((packed)) gw_reg_resp_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[16];
    uint8_t control_type;
} __attribute__((packed)) ctrl_req_t;

typedef struct _ctrl_resp_t {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[16];
    uint8_t control_type;
    uint8_t result_code;
} __attribute__((packed)) ctrl_resp_t;

typedef struct _heartbeat_req_t {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
} __attribute__((packed)) heartbeat_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[16];
} __attribute__((packed)) enc_info_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[16];
    uint8_t result_code;
    uint8_t enc_flag;
    uint8_t enc_algorithm;
} __attribute__((packed)) enc_info_resp_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[16];
    char enc_key[LEN_AES_KEY];
} __attribute__((packed)) set_enc_key_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[16];
    uint8_t result_code;
} __attribute__((packed)) set_enc_key_resp_t;

typedef struct _gw_reg_req_t gw_dereg_req_t;
typedef struct _gw_reg_resp_t gw_dereg_resp_t;
typedef struct _ctrl_resp_t ctrl_noti_t;
typedef struct _ctrl_resp_t  ctrl_noti_resp_t;
typedef struct _heartbeat_req_t heartbeat_resp_t;


OSStatus read_gmmp_frame( int fd, void *buf, size_t *size );
size_t fill_reg_req( void* buf );
size_t fill_heartbeat_req( void* buf );
size_t fill_ctrl_resp( void* buf, gmmp_header_t *req);
size_t fill_ctrl_noti( void* buf, int control_type );
