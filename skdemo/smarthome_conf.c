/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"
#include "smarthome_conf.h"

extern system_context_t* sys_context;

static void factory_Command( char *pcWriteBuffer, int xWriteBufferLen,int argc, char **argv );
static void devinfo_Command( char *pcWriteBuffer, int xWriteBufferLen,int argc, char **argv );

static const struct cli_command smarthome_clis[] = {
    {"devinfo", "get/set device info", devinfo_Command},
    {"factory", "set factory setting", factory_Command},
};

smarthome_device_user_conf_t* smarthome_conf_get( void )
{
    smarthome_device_user_conf_t* conf = NULL;
    mico_Context_t* in_context = mico_system_context_get();
    require(in_context, exit);

    conf = mico_system_context_get_user_data( in_context );
    require(conf, exit);
exit:
    return conf;
}

#define FILL_USER_CONF(cmd, field)					\
{									\
    if (!processed && !strcasecmp(argv[1], cmd)) {			\
	require_action_string(strlen(argv[2]) < sizeof(conf->field), WRONGCMD, \
		      mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex ), \
			      "Too long value.");			\
	memset(conf->field, 0, sizeof(conf->field));			\
	strcpy(conf->field, argv[2]);					\
	processed = MICO_TRUE;						\
    }									\
}

static void factory_Command( char *pcWriteBuffer, int xWriteBufferLen,int argc, char **argv )
{
    OSStatus status;
    smarthome_device_user_conf_t* conf;
    conf = smarthome_conf_get();
    mico_rtos_lock_mutex( &sys_context->flashContentInRam_mutex );
    memset( &conf->server, 0, sizeof(conf->server) );
    sys_context->flashContentInRam.micoSystemConfig.configured = unConfigured;
    mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex );
    status = mico_system_context_update(mico_system_context_get());
    check_string(status == kNoErr, "Fail to update conf to Flash memory");
    cmd_printf( "Reset All State\n" );
}

static void devinfo_Command( char *pcWriteBuffer, int xWriteBufferLen,int argc, char **argv )
{
    smarthome_device_user_conf_t* conf;
    conf = smarthome_conf_get();
    require(conf, WRONGCMD);

    if (argc == 1) {
	mico_rtos_lock_mutex( &sys_context->flashContentInRam_mutex ); 
	cmd_printf("Manufaturer ID : %s\r\n", conf->dev_info.device_mf_id);
	cmd_printf("Device Type    : %s\r\n", conf->dev_info.device_type);
	cmd_printf("Model ID       : %s\r\n", conf->dev_info.device_model_id);
	cmd_printf("Serial Number  : %s\r\n", conf->dev_info.device_sn);
	cmd_printf("Server IP      : %s\r\n", conf->server.ip);
	cmd_printf("Server Port    : %d\r\n", conf->server.port);
	cmd_printf("AES Key	   : %s\r\n", conf->server.aes_key);
	cmd_printf("Domain Code    : %s\r\n", conf->server.domain_code);
	cmd_printf("GW ID          : %s\r\n", conf->server.gw_id);
	cmd_printf("Auth Key       : %s\r\n", conf->server.auth_key);
	cmd_printf("Configured     : %d\r\n", sys_context->flashContentInRam.micoSystemConfig.configured);
	mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex );
	return;
    } 

    if (argc == 3) {
	OSStatus status;
	mico_bool_t processed = MICO_FALSE;

	mico_rtos_lock_mutex( &sys_context->flashContentInRam_mutex );
	FILL_USER_CONF("mf_id", dev_info.device_mf_id);
	FILL_USER_CONF("type", dev_info.device_type);
	FILL_USER_CONF("model_id", dev_info.device_model_id);
	FILL_USER_CONF("sn", dev_info.device_sn);
	FILL_USER_CONF("server", server.ip);
	if (!processed && !strcasecmp(argv[1], "port")) {
	    conf->server.port = (ushort)atoi(argv[2]);
	    processed = MICO_TRUE;
	}
	if (!processed && !strcasecmp(argv[1], "config")) {
	    if (argv[2][0] == '1')
		sys_context->flashContentInRam.micoSystemConfig.configured = allConfigured;
	    else
		sys_context->flashContentInRam.micoSystemConfig.configured = unConfigured;
	    processed = MICO_TRUE;
	}
	mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex );
	status = mico_system_context_update(mico_system_context_get());
	check_string(status == kNoErr, "Fail to update conf to Flash memory");
	return;
    }

WRONGCMD:
    cmd_printf("Usage: devinfo\r\n"
	       "       devinfo mf_id|type|model_id|sn|server|config [value]\r\n");
}

int smarthome_conf_cli_register( void )
{
    cli_register_commands(smarthome_clis, sizeof(smarthome_clis)/sizeof(struct cli_command));
    return 0;
}
