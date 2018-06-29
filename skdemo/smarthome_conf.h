/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once

#define LEN_MANUFACTURE_ID	16
#define LEN_DEVICE_TYPE		32
#define LEN_MODEL_ID		32
#define LEN_SERIAL_NUMBER	16
#define LEN_DOMAIN_CODE		10
#define LEN_AES_KEY		32
#define LEN_AUTH_KEY		16
#define LEN_GW_ID		16

/* Device Information
 *
 * This information is used in pairing procedure with App.
 * Refer to DP1100 in 'Smart Home Pairing Spec. Flow for OMP device'. 
 */
typedef struct
{
    char device_mf_id[LEN_MANUFACTURE_ID+1];	/* Manufacturer ID (LG) */
    char device_type[LEN_DEVICE_TYPE+1];	/* Device Type (aircondition, ...) */
    char device_model_id[LEN_MODEL_ID+1];	/* Device Model ID (LG-N3333) */
    char device_sn[LEN_SERIAL_NUMBER+1];	/* Device Serial Number(auth_id) */
} smarthome_device_info_t;

typedef struct
{
    char ip[32];				/* service ip address */
    ushort port;				/* server port */

    char domain_code[LEN_DOMAIN_CODE+1];	/* domain code(application id) */
    char aes_key[LEN_AES_KEY+1];		/* AES key (128,192,256) */
    char auth_key[LEN_AUTH_KEY+1];		/* auth key */
    char gw_id[LEN_GW_ID+1];			/* Gateway ID */
} smarhome_server_info_t;
    
typedef struct
{
    smarthome_device_info_t dev_info;
    smarhome_server_info_t server;
} smarthome_device_user_conf_t;

#define smarthome_get_size_user_data()	(sizeof(smarthome_device_user_conf_t))

int smarthome_conf_cli_register( void );

static inline smarthome_device_user_conf_t *get_user_conf(void)
{
	return mico_system_context_get_user_data(mico_system_context_get());
}
