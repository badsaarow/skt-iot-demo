/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once

#include "smarthome_conf.h"

#define LEN_GW_ID		16
#define LEN_DEVICE_ID		16
#define LEN_AUTH_KEY		16
#define LEN_AES_KEY		32

#define HEARTBEAT_INTERVAL	600

#define MEDIA_TYPE_APPLICATION_JSON	0x65

typedef enum {
    GMMP_GW_REG_REQ		= 0x01,
    GMMP_GW_REG_RESP		= 0x02,
    GMMP_GW_DEREG_REQ		= 0x03,
    GMMP_GW_DEREG_RESP		= 0x04,
    GMMP_PROFILE_REQ		= 0x05,
    GMMP_PROFILE_RESP		= 0x06,
    GMMP_DEV_REG_REQ		= 0x07,
    GMMP_DEV_REG_RESP		= 0x08,
    GMMP_DEV_DEREG_REQ		= 0x09,
    GMMP_DEV_DEREG_RESP		= 0x0a,
    GMMP_DELIVERY_REQ		= 0x0b,
    GMMP_DELIVERY_RESP		= 0x0c,
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

typedef enum {
    REPORT_COLLECT_DATA = 1,
    REPORT_ALARM_DATA = 2,
    REPORT_EVENT_DATA = 3,
    REPORT_ALARM_CLEAR = 4
} gmmp_report_type_t;

typedef enum {
    ENC_AES_128 = 1,
    ENC_AES_192 = 2,
    ENC_AES_256 = 3,
    ENC_SEED_128 = 4,
    ENC_SEED_256 = 5
} gmmp_enc_type_t;

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

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char manufacture_id[LEN_MANUFACTURE_ID];
} __attribute__((packed)) gw_reg_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    uint8_t result_code;
} __attribute__((packed)) gw_reg_resp_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char manufacture_id[LEN_MANUFACTURE_ID];
} __attribute__((packed)) dev_reg_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
    uint8_t result_code;
} __attribute__((packed)) dev_reg_resp_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
} __attribute__((packed)) profile_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
    uint8_t result_code;
    uint32_t heartbeat_period;
    uint32_t report_period;
    uint32_t report_offset;
    uint32_t response_timeout;
    char model[32];
    char firmware_version[16];
    char software_version[16];
    char hardware_version[16];
} __attribute__((packed)) profile_resp_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
    uint8_t report_type;
    uint8_t media_type;
} __attribute__((packed)) delivery_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
    uint8_t result_code;
    uint32_t backoff_time;
} __attribute__((packed)) delivery_resp_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
    uint8_t control_type;
} __attribute__((packed)) ctrl_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
    uint8_t control_type;
    uint8_t result_code;
} __attribute__((packed)) ctrl_resp_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
} __attribute__((packed)) heartbeat_req_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
    uint8_t result_code;
    uint8_t enc_flag;
    uint8_t enc_algorithm;
} __attribute__((packed)) enc_info_resp_t;

typedef struct {
    char domain_code[LEN_DOMAIN_CODE];
    char gw_id[LEN_GW_ID];
    char device_id[LEN_DEVICE_ID];
    char enc_key[LEN_AES_KEY];
} __attribute__((packed)) set_enc_key_req_t;

typedef gw_reg_req_t gw_dereg_req_t;
typedef gw_reg_resp_t gw_dereg_resp_t;
typedef ctrl_resp_t ctrl_noti_t;
typedef ctrl_resp_t  ctrl_noti_resp_t;
typedef heartbeat_req_t heartbeat_resp_t;
typedef profile_req_t dev_dereg_req_t;
typedef profile_req_t enc_info_req_t;
typedef dev_reg_resp_t dev_dereg_resp_t;
typedef dev_reg_resp_t set_enc_key_resp_t;

OSStatus read_gmmp_frame( int fd, void *buf, size_t *size );
size_t fill_gw_reg_req( void* buf );
size_t fill_dev_reg_req( void* buf );
size_t fill_enc_info_req( void* buf );
size_t fill_set_enc_key_req( void* buf );
size_t fill_heartbeat_req( void* buf );
size_t fill_profile_req( void* buf );
size_t fill_ctrl_resp( void* buf, gmmp_header_t *req);
size_t fill_delivery_req( void* buf, gmmp_report_type_t report_type, int json_size );
size_t fill_ctrl_noti( void* buf, int control_type, int json_size, uint32_t tid );
void set_tid( uint32_t tid );

