/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#pragma once

#define APP_INFO   "MiCO BASIC Demo"

#define FIRMWARE_REVISION   "MICO_BASIC_1_0"
#define MANUFACTURER        "MXCHIP Inc."
#define SERIAL_NUMBER       "20140606"
#define PROTOCOL            "com.mxchip.basic"

/************************************************************************
 * Application thread stack size */
#define MICO_DEFAULT_APPLICATION_STACK_SIZE         (2000)

/************************************************************************
 * Enable wlan connection, start easylink configuration if no wlan settings are existed */
#define MICO_WLAN_CONNECTION_ENABLE

#define MICO_WLAN_CONFIG_MODE CONFIG_MODE_SOFTAP

#define EasyLink_TimeOut                60000 /**< EasyLink timeout 60 seconds. */

#define EasyLink_ConnectWlan_Timeout    20000 /**< Connect to wlan after configured by easylink.
                                                   Restart easylink after timeout: 20 seconds. */

#define HL_USE_SKT_PAIRING

/************************************************************************
 * Device enter MFG mode if MICO settings are erased. */
//#define MFG_MODE_AUTO 

/************************************************************************
 * Command line interface */
#define MICO_CLI_ENABLE  

/************************************************************************
 * Start a system monitor daemon, application can register some monitor  
 * points, If one of these points is not executed in a predefined period, 
 * a watchdog reset will occur. */
#define MICO_SYSTEM_MONITOR_ENABLE

/************************************************************************
 * Add service _easylink._tcp._local. for discovery */
#define MICO_SYSTEM_DISCOVERY_ENABLE  

/************************************************************************
 * MiCO TCP server used for configuration and ota. */
#define MICO_CONFIG_SERVER_ENABLE 
#define MICO_CONFIG_SERVER_PORT    8000

