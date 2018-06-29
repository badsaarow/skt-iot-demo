/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

/*
 * This module is implemented according to "SKTSmart Home Pairing Spec. Flow for OMP device v1.2"
 * And this code is based on system/config_server/config_server.c
 */ 
#include "mico.h"
#include "system_internal.h"

#include "SocketUtils.h"

#include "utils.h"
#include "smarthome_pairing.h"
#include "smarthome_conf.h"

#define PAIRING_VERSION			"v100"
#define PAIRING_VERSION_LEN		4
#define SMARTHOME_PAIRING_SERVER_PORT	5000
#define MAX_PAIRING_BUFFER_SIZE		256
#define MAX_TRANSACTION_KEY		50

typedef enum
{
    PAIRING_UNKNOWN,
    PAIRING_REQUEST,
    PAIRING_RESPONSE,
} pairing_type_t;

typedef enum
{
    CODE_UNKNOWN,
    CODE_LOGIN,
    CODE_WIFI_INFO,
    CODE_CONNECT
} pairing_code_t;

typedef struct
{
    char version[4];
    uint32_t len;
    char data[1];
} pairing_msg_t;

typedef struct
{
    const char* key;
    char* value;
    size_t max;
} json_field_t;

static void localPairinglistener_thread( mico_thread_arg_t arg );
static void localPairing_thread(uint32_t inFd);

bool is_pairing_server_established = false;
static config_server_uap_configured_cb _uap_configured_cb = NULL;

/* Defined in uAP config mode */
extern system_context_t* sys_context;

static mico_semaphore_t close_listener_sem = NULL, close_client_sem[ MAX_TCP_CLIENT_PER_SERVER ] = { NULL };

void pairing_server_set_uap_cb( config_server_uap_configured_cb callback )
{
    _uap_configured_cb = callback;
}

static bool is_valid_pairing_msg(const char *buf, size_t len)
{
    pairing_msg_t *d = (pairing_msg_t *)buf;
    if( len < N_OFFSET(pairing_msg_t, data) )
	return true;

    require_string(strncmp(d->version, PAIRING_VERSION, sizeof(d->version)) == 0, bad, "Bad Pairing Version");
    require_string(ntohl(d->len) < MAX_PAIRING_BUFFER_SIZE, bad, "Too Big Pairing Packet");
    return true;
  bad:
    return false;
}

static bool is_receive_completed(const char *buf, size_t len)
{
    pairing_msg_t *d = (pairing_msg_t *)buf;
 
    if( len < N_OFFSET(pairing_msg_t, data) )
	return false;

    if( len >= ntohl(d->len) )
	return true;
    return false;
}

typedef enum {
    E_TYPE,
    E_CODE,
    E_KEY,
    E_SSID,
    E_PWD,
    E_IP,
    E_PORT,
    E_SID
} pairing_json_field_t;

static OSStatus process_request_message( int fd, char* buf, size_t len )
{
    size_t i;
    OSStatus err = kUnknownErr;
    pairing_msg_t *msg = (pairing_msg_t*)buf;
    json_object* report = NULL, *config = NULL;
    const char *  json_str;

    json_field_t fields[] = {
	[E_TYPE] = { "type", NULL, 4 },
	[E_CODE] = { "code", NULL, 7 },
	[E_KEY]  = { "key", NULL, MAX_TRANSACTION_KEY },
	[E_SSID] = { "ssid", NULL, maxSsidLen },
	[E_PWD]  = { "pwd", NULL, maxKeyLen },
	[E_IP]   = { "ip", NULL, maxIpLen },
	[E_PORT] = { "port", NULL, 6 },
	[E_SID]  = { "serviceid", NULL, maxNameLen },
    };

    config = json_tokener_parse( msg->data );
    require_action( config, exit, err = kUnknownErr );
    system_log( "Recv data from smartphone =%s", json_object_to_json_string( config ) );
    
    json_object_object_foreach( config, key, val ) {
	for( i = 0; i < N_ELEMENT(fields); i++) {
	    if( strcmp( key, fields[i].key ) == 0 ) {
		const char *str = json_object_get_string(val);
		require_string( strlen(str) < fields[i].max, exit, "Too long value" );
		require( fields[i].value == NULL, exit );
		fields[i].value = calloc(1, fields[i].max);
		strncpy(fields[i].value, str, fields[i].max);
		break;
	    }
	}
	if (i == N_ELEMENT(fields))
		system_log("Unknown field: %s\n", key);
    }

    require_string( fields[E_TYPE].value && fields[E_CODE].value && fields[E_KEY].value,
		    exit, "No manadatory fields: type, code, key");
    require_string( strcmp(fields[E_TYPE].value, "REQ" ) == 0, exit, "Invalid type field");

    report = json_object_new_object();
    json_object_object_add(report, "type", json_object_new_string("RES"));
    json_object_object_add(report, "code", json_object_new_string(fields[E_CODE].value));
    json_object_object_add(report, "key", json_object_new_string(fields[E_KEY].value));
    
    if ( strcmp( fields[E_CODE].value, "DP0000" ) == 0 ) {
	/* login */
	err = kNoErr;
    } else if ( strcmp( fields[E_CODE].value, "DP1000" ) == 0 ) {
	/* Wi-Fi SSID & Password Send */
	require_string( fields[E_SSID].value && fields[E_PWD].value, exit, "No manadatory fields: ssid, pwd");
	mico_rtos_lock_mutex(&sys_context->flashContentInRam_mutex);
	strncpy(sys_context->flashContentInRam.micoSystemConfig.ssid, fields[E_SSID].value, maxSsidLen);
	sys_context->flashContentInRam.micoSystemConfig.channel = 0;
	memset(sys_context->flashContentInRam.micoSystemConfig.bssid, 0x0, 6);
	sys_context->flashContentInRam.micoSystemConfig.security = SECURITY_TYPE_AUTO;
	strncpy(sys_context->flashContentInRam.micoSystemConfig.key, fields[E_PWD].value, maxKeyLen);
	sys_context->flashContentInRam.micoSystemConfig.keyLength = strlen(fields[E_PWD].value);
        sys_context->flashContentInRam.micoSystemConfig.configured = allConfigured;
	mico_rtos_unlock_mutex(&sys_context->flashContentInRam_mutex);
	err = mico_system_context_update(mico_system_context_get());
	check_string(err == kNoErr, "Fail to update conf to Flash memory");
	err = kNoErr;
    } else if ( strcmp( fields[E_CODE].value, "DP1100" ) == 0 ) {
	/* Device Info */
	smarthome_device_user_conf_t* user = get_user_conf();
	mico_rtos_lock_mutex(&sys_context->flashContentInRam_mutex);
	json_object_object_add(report, "device_mf_id", json_object_new_string(user->dev_info.device_mf_id));
	json_object_object_add(report, "device_type", json_object_new_string(user->dev_info.device_type));
	json_object_object_add(report, "device_model_id", json_object_new_string(user->dev_info.device_model_id));
	json_object_object_add(report, "device_sn", json_object_new_string(user->dev_info.device_sn));
	mico_rtos_unlock_mutex(&sys_context->flashContentInRam_mutex);
	err = kNoErr;
    } else if ( strcmp( fields[E_CODE].value, "DP1200" ) == 0 ) {
	/* Connect to Server */
	smarthome_device_user_conf_t* user = get_user_conf();
	mico_rtos_lock_mutex(&sys_context->flashContentInRam_mutex);
	strncpy(user->server.ip, fields[E_IP].value, maxSsidLen);
	user->server.port = atoi(fields[E_PORT].value);
	memset(user->server.domain_code, 0, sizeof(user->server.domain_code));
	strncpy(user->server.domain_code, fields[E_SID].value, sizeof(user->server.domain_code)-1);
	mico_rtos_unlock_mutex(&sys_context->flashContentInRam_mutex);
	err = mico_system_context_update(mico_system_context_get());
	check_string(err == kNoErr, "Fail to update conf to Flash memory");
	err = kNoErr;
    } else {
	system_log( "Unknown message code" );
    }
    json_object_object_add(report, "result", json_object_new_string("200"));

    json_str = json_object_to_json_string(report);
    require_action( json_str, exit, err = kNoMemoryErr );
    system_log("Send config object=%s", json_str);

    {
	i = strlen(json_str);
	msg = calloc(1, sizeof(pairing_msg_t) + i + 4);
	strcpy(msg->version, PAIRING_VERSION);
	i += N_OFFSET(pairing_msg_t, data);
	msg->len = htonl(i);
	strcpy(msg->data, json_str);
	err = SocketSend( fd, (uint8_t*)msg, i);
	require_noerr( err, exit );
	free(msg);
    }

  exit:
    if(config)
        json_object_put(config);
    if(report)
	json_object_put(report);

    for( i = 0; i < N_ELEMENT(fields); i++) {
	if (fields[i].value)
	    free(fields[i].value);
    }
    return err;
}

OSStatus smarthome_pairing_server_start( void )
{
    int i = 0;
    OSStatus err = kNoErr;

    require( sys_context, exit );

    is_pairing_server_established = true;

    close_listener_sem = NULL;
    for(; i < MAX_TCP_CLIENT_PER_SERVER; i++)
	close_client_sem[ i ] = NULL;
    err = mico_rtos_create_thread( NULL, MICO_APPLICATION_PRIORITY, "Pairing Server",
				   localPairinglistener_thread, STACK_SIZE_LOCAL_CONFIG_SERVER_THREAD, 0 );
    require_noerr(err, exit);
  
    mico_thread_msleep(200);

  exit:
    return err;
}

OSStatus smarthome_pairing_server_stop( void )
{
    int i = 0;
    OSStatus err = kNoErr;

    if( !is_pairing_server_established )
	return kNoErr;

    for(; i < MAX_TCP_CLIENT_PER_SERVER; i++){
	if( close_client_sem[ i ] != NULL )
	    mico_rtos_set_semaphore( &close_client_sem[ i ] );
    }
    mico_thread_msleep(50);

    if( close_listener_sem != NULL )
	mico_rtos_set_semaphore( &close_listener_sem );

    mico_thread_msleep(500);
    is_pairing_server_established = false;
  
    return err;
}

static void localPairinglistener_thread( mico_thread_arg_t arg )
{
    OSStatus err = kUnknownErr;
    int j;
    struct sockaddr_in addr;
    int sockaddr_t_size;
    fd_set readfds;
    char ip_address[16];
  
    int localPairinglistener_fd = -1;
    int close_listener_fd = -1;

    mico_rtos_init_semaphore( &close_listener_sem, 1 );
    close_listener_fd = mico_create_event_fd( close_listener_sem );

    /*Establish a TCP server fd that accept the tcp clients connections*/ 
    localPairinglistener_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    require_action(IsValidSocket( localPairinglistener_fd ), exit, err = kNoResourcesErr );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons( SMARTHOME_PAIRING_SERVER_PORT );
    err = bind( localPairinglistener_fd, (struct sockaddr *)&addr, sizeof(addr) );
    require_noerr( err, exit );

    err = listen(localPairinglistener_fd, 1);
    require_noerr( err, exit );

    system_log("Pairing Server established at port: %d, fd: %d", SMARTHOME_PAIRING_SERVER_PORT, localPairinglistener_fd);
  
    while (1) {
	FD_ZERO( &readfds );
	FD_SET( localPairinglistener_fd, &readfds );
	FD_SET( close_listener_fd, &readfds );
	select( Max(localPairinglistener_fd, close_listener_fd) + 1, &readfds, NULL, NULL, NULL );

	/* Check close requests */
	if(FD_ISSET( close_listener_fd, &readfds )){
	    mico_rtos_get_semaphore( &close_listener_sem, 0 );
	    goto exit;
	}

	/* Check tcp connection requests */
	if(FD_ISSET( localPairinglistener_fd, &readfds )){
	    sockaddr_t_size = sizeof(struct sockaddr_in);
	    j = accept( localPairinglistener_fd, (struct sockaddr *)&addr, (socklen_t *)&sockaddr_t_size );
	    if( IsValidSocket( j ) ){
		strcpy( ip_address, inet_ntoa( addr.sin_addr ) );
		system_log( "Config Client %s:%d connected, fd: %d", ip_address, addr.sin_port, j );
		if (kNoErr !=  mico_rtos_create_thread(NULL, MICO_APPLICATION_PRIORITY, "Pairing Clients",
						       localPairing_thread, STACK_SIZE_LOCAL_CONFIG_CLIENT_THREAD,
						       (mico_thread_arg_t)j) )
		    SocketClose( &j );
	    }
	}
    }

  exit:
    if( close_listener_sem != NULL ){
	mico_delete_event_fd( close_listener_fd );
	mico_rtos_deinit_semaphore( &close_listener_sem );
	close_listener_sem = NULL;
    };
    system_log( "Exit: Pairing listener exit with err = %d", err );
    SocketClose( &localPairinglistener_fd );
    is_pairing_server_established = false;
    mico_rtos_delete_thread( NULL );
    return;
}

static void localPairing_thread(uint32_t inFd)
{
    OSStatus err = kNoErr;
    int clientFd = (int)inFd;
    int close_sem_index;
    fd_set readfds;
    struct timeval t;
    int close_client_fd = -1;
    bool completed = false;

    char buf[MAX_PAIRING_BUFFER_SIZE];
    size_t buf_pos = 0;

    for( close_sem_index = 0; close_sem_index < MAX_TCP_CLIENT_PER_SERVER; close_sem_index++ ){
	if( close_client_sem[close_sem_index] == NULL )
	    break;
    }

    if( close_sem_index == MAX_TCP_CLIENT_PER_SERVER ){
	mico_rtos_delete_thread( NULL );
	return;
    }

    mico_rtos_init_semaphore( &close_client_sem[close_sem_index], 1 );
    close_client_fd = mico_create_event_fd( close_client_sem[close_sem_index] );

    t.tv_sec = 60;
    t.tv_usec = 0;
    system_log("Free memory %d bytes", MicoGetMemoryInfo()->free_memory) ; 

    while(1){
	FD_ZERO(&readfds);
	FD_SET(clientFd, &readfds);
	FD_SET(close_client_fd, &readfds);

	require(select( Max(clientFd, close_client_fd) + 1 , &readfds, NULL, NULL, &t) >= 0, exit);

	/* Check close requests */
	if( FD_ISSET(close_client_fd, &readfds) ){
	    mico_rtos_get_semaphore( &close_client_sem[close_sem_index], 0 );
	    err = kConnectionErr;
	    goto exit;
	}    
  
	if( FD_ISSET(clientFd, &readfds) ) {
	    ssize_t n;
	    n = read( clientFd, &buf[buf_pos], sizeof(buf) - buf_pos );
	    if (n < 0) {
		err = kConnectionErr;
		break;
	    }

	    buf_pos += (size_t)n;
	    require_string(buf_pos < MAX_PAIRING_BUFFER_SIZE, exit, "Too big pairing message");
	    require_string(is_valid_pairing_msg( buf, buf_pos ), exit, "Bad pairing message header");
	    if (is_receive_completed( buf, buf_pos )) {
		    buf[buf_pos] = '\0';
		    process_request_message( clientFd, buf, buf_pos );
		    mico_rtos_lock_mutex( &sys_context->flashContentInRam_mutex );
		    if (sys_context->flashContentInRam.micoSystemConfig.configured)
			completed = true;
		    mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex );
		    if (completed)
			break;
	    }
	}
    }

  exit:
    system_log( "Exit: Client exit with err = %d", err );
    SocketClose( &clientFd );

    if( close_client_sem[close_sem_index] != NULL )
    {
	mico_delete_event_fd( close_client_fd );
	mico_rtos_deinit_semaphore( &close_client_sem[close_sem_index] );
	close_client_sem[close_sem_index] = NULL;
    };

    if ( completed ) {
        mico_system_power_perform( &sys_context->flashContentInRam, eState_Software_Reset );
    }

    mico_rtos_delete_thread( NULL );
    return;
}
