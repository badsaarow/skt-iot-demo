/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"

#define MAX_OMP_FRAME				(600)
 
#define OMP_CLIENT_SOCKET_TIMEOUT              (5000)  // 5s
#define OMP_CLIENT_SOCKET_TCP_KEEPIDLE         (10)  // tcp keepavlie idle time 10s
#define OMP_CLIENT_SOCKET_TCP_KEEPINTVL        (10)  // tcp keepavlie interval time 10s
#define OMP_CLIENT_SOCKET_TCP_KEEPCNT          (5)  // max retry

typedef enum {
    OMP_INIT	= 0x80,
    OMP_REPORT_INTERVAL = 0x81,
    OMP_DEINIT	= 0x82,
    OMP_CONTROL = 0x84,
    OMP_NOTIFY	= 0x85
} omp_type_t;

typedef void (*fill_json)( json_object *msg );

OSStatus omp_client_start( fill_json fn );
OSStatus omp_client_stop( void );
