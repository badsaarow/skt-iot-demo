/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once

#include "gmmp.h"

#define MAX_OMP_FRAME				(600)
 
#define OMP_CLIENT_SOCKET_TIMEOUT              (5000)  // 5s
#define OMP_CLIENT_SOCKET_TCP_KEEPIDLE         (10)  // tcp keepavlie idle time 10s
#define OMP_CLIENT_SOCKET_TCP_KEEPINTVL        (10)  // tcp keepavlie interval time 10s
#define OMP_CLIENT_SOCKET_TCP_KEEPCNT          (5)  // max retry

typedef enum {
    OMP_REPORT_PERIODIC,
    OMP_REPORT_NONPERIODIC
} omp_report_type_t;

typedef enum {
    OMP_INIT	= 0x80,
    OMP_REPORT_INTERVAL = 0x81,
    OMP_DEINIT	= 0x83,
    OMP_CONTROL = 0x94,
    OMP_NOTIFY	= 0x95
} omp_type_t;

typedef void (*fill_json)( json_object *msg, omp_report_type_t rtype );
typedef void (*reply_control)( const char* cmd, const char* value );

typedef struct
{
    char auth_key[LEN_AUTH_KEY+1];		/* auth key */
    char gw_id[LEN_GW_ID+1];			/* Gateway ID */
    char dev_id[LEN_DEVICE_TYPE+1];		/* Devcie ID */
    char aes128_key[LEN_AES_KEY+1];		/* AES key (128,192,256) */
    bool use_aes128;
     
    int report_period;
    int heartbeat_period;
    fill_json fill_json;
    reply_control reply_control;
} smarthome_state_t;

extern smarthome_state_t smarthome_state;

inline smarthome_state_t *get_smarthome_state( void ) {
    return &smarthome_state;
}

OSStatus omp_client_start( fill_json report, reply_control reply_control );
OSStatus omp_client_stop( void );
OSStatus omp_trigger_event( void );
