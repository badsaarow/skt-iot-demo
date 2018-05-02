/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once


/* Device Information
 *
 * This information is used in pairing procedure with App.
 * Refer to DP1100 in 'Smart Home Pairing Spec. Flow for OMP device'. 
 */
typedef struct
{
    char device_mf_id[32];	/* Manufacturer ID (LG) */
    char device_type[32];	/* Device Type (aircondition, ...) */
    char device_model_id[32];	/* Device Model ID (LG-N3333) */
    char device_sn[32];		/* Device Serial Number */
} smarthome_device_info_t;

typedef struct
{
    char ip[32];		/* service ip address */
    ushort port;		/* server port */

} smarhome_server_info_t;
    
typedef struct
{
    smarthome_device_info_t dev_info;
    smarhome_server_info_t server;
} smarthome_device_user_conf_t;

#define smarthome_get_size_user_data()	(sizeof(smarthome_device_user_conf_t))

smarthome_device_user_conf_t* smarthome_conf_get( void );
int smarthome_conf_cli_register( void );
