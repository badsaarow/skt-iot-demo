/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"
#include "SocketUtils.h"

#include "smarthome_conf.h"
#include "smarthome.h"
#include "gmmp.h"
#include "timeout.h"
#include "AESUtils.h"

extern system_context_t* sys_context;

typedef enum {
    TIMEOUT_GENERAL,
    TIMEOUT_HEARTBEAT,
    TIMEOUT_DELIVERY,
    TIMEOUT_MAX
} timeout_type_t;

smarthome_state_t smarthome_state = {
    .report_period = 600,
    .heartbeat_period = 600,
    .fill_json = NULL,
    .reply_control = NULL,

    .use_aes128 = false,
};

static mico_semaphore_t update_state_sem = NULL;
static int update_state_fd = 0;

static timeout_t timeout_table[TIMEOUT_MAX];

static OSStatus usergethostbyname( const char * domain, uint8_t * addr, uint8_t addrLen )
{
    struct hostent* host = NULL;
    struct in_addr in_addr;
    char **pptr = NULL;
    char *ip_addr = NULL;

    if(addr == NULL || addrLen < 16)
    {
        return kGeneralErr;
    }

    host = gethostbyname( domain );
    if((host == NULL) || (host->h_addr_list) == NULL)
    {
        return kGeneralErr;
    }

    pptr = host->h_addr_list;
    {
        in_addr.s_addr = *(uint32_t *) (*pptr);
        ip_addr = inet_ntoa(in_addr);
        memset(addr, 0, addrLen);
        memcpy(addr, ip_addr, strlen(ip_addr));
    }

    return kNoErr;
}

static int connect_gmmp( const char* addr, int port )
{
    int sock_fd;
    OSStatus err = kUnknownErr;
    char ipstr[16];
    unsigned long ip_addr;;
    struct sockaddr_in s_addr;
    int addr_size;
    int net_timeout_ms = OMP_CLIENT_SOCKET_TIMEOUT;  //o socket send && recv timeout = 5s
    int opt;

    omp_log( "connect to server: %s:%d", addr, port );
    memset( ipstr, 0, sizeof(ipstr) );
    err = usergethostbyname( addr, (uint8_t *)ipstr, sizeof(ipstr));
    require_noerr_string( err, exit, "gethostbyname failed" );
    
    ip_addr = inet_addr(ipstr);
    s_addr.sin_port = htons(port);
    s_addr.sin_addr.s_addr = ip_addr;
    s_addr.sin_family = AF_INET;
    addr_size = sizeof(s_addr);
    
    sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    require_action( IsValidSocket( sock_fd ), exit, err = kNoResourcesErr );

    err = setsockopt( sock_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&net_timeout_ms, sizeof(int) );
    require_noerr_string( err, exit, "setsockopt SO_SNDTIMEO error" );
    err = setsockopt( sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&net_timeout_ms, sizeof(int) );
    require_noerr_string( err, exit, "setsockopt SO_RECVTIMEO error" );
    
    opt = 1;
    err = setsockopt( sock_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&opt, sizeof(opt) );
    require_noerr_string( err, exit, "setsockopt SO_KEEPALIVE error" );
    opt = OMP_CLIENT_SOCKET_TCP_KEEPIDLE;
    setsockopt( sock_fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&opt, sizeof(opt) );
    require_noerr_string( err, exit, "setsockopt TCP_KEEPIDLE error" );
    opt = OMP_CLIENT_SOCKET_TCP_KEEPINTVL;
    setsockopt( sock_fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&opt, sizeof(opt) );
    require_noerr_string( err, exit, "setsockopt TCP_KEEPINTVL error" );
    opt = OMP_CLIENT_SOCKET_TCP_KEEPCNT;
    setsockopt( sock_fd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&opt, sizeof(opt) );
    require_noerr_string( err, exit, "setsockopt TCP_KEEPCNT error" );

    err = connect( sock_fd, (struct sockaddr *)&s_addr, addr_size );
    require_noerr_string( err, exit, "connect error" );

    omp_log( "connected" );
    return sock_fd;
  exit:
    return err;
}

static OSStatus send_gw_register( int sock_fd )
{
    void *buf = NULL;
    int len;
    size_t size;
    OSStatus err = kNoErr;

    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );

    size = fill_gw_reg_req( buf );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_GW_REG_REQ" );

  exit:
    if ( buf )
	free( buf );
    return err;
}

static OSStatus send_dev_register( int sock_fd )
{
    void *buf = NULL;
    int len;
    size_t size;
    OSStatus err = kNoErr;

    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );

    size = fill_dev_reg_req( buf );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_DEV_REG_REQ" );

  exit:
    if ( buf )
	free( buf );
    return err;
}

static OSStatus send_enc_info_req( int sock_fd )
{
    void *buf = NULL;
    int len;
    size_t size;
    OSStatus err = kNoErr;

    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );

    size = fill_enc_info_req( buf );
    len = write( sock_fd, buf, size );
    require_action_string( len  > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_ENC_INFO_REQ" );

  exit:
    if ( buf )
	free( buf );
    return err;
}

static OSStatus send_set_enc_key_req( int sock_fd )
{
    void *buf = NULL;
    int len;
    size_t size;
    OSStatus err = kNoErr;

    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );

    size = fill_set_enc_key_req( buf );
    len = write( sock_fd, buf, size );
    require_action_string( len  > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_ENC_INFO_REQ" );

  exit:
    if ( buf )
	free( buf );
    return err;
}

static OSStatus send_profile_req( int sock_fd )
{
    void *buf = NULL;
    int len;
    size_t size;
    OSStatus err = kNoErr;

    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );

    size = fill_profile_req( buf );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_PROFILE_REQ" );

  exit:
    if ( buf )
	free( buf );
    return err;
}

static OSStatus send_heaertbeat( int sock_fd )
{
    void *buf = NULL;
    int len;
    size_t size;
    OSStatus err = kNoErr;

    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );

    size = fill_heartbeat_req( buf );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_HEARTBEAT_REQ" );

  exit:
    if ( buf )
	free( buf );
    return err;
}

static OSStatus send_report( int sock_fd, omp_report_type_t rtype )
{
    OSStatus err = kNoErr;
    json_object* report = NULL;
    json_object* msg = NULL;
    const char * report_str;
    int report_size;
    int len;
    size_t size;
    void *buf = NULL;
    gmmp_report_type_t hd_rtype;

    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );

    omp_log("Prepare periodic report");
    report = json_object_new_object();
    msg = json_object_new_object();
    require( report && msg, exit );

    smarthome_state.fill_json( msg, rtype );

    if (rtype == OMP_REPORT_PERIODIC) {
	report_str = "periodic_data";
	hd_rtype = REPORT_COLLECT_DATA;
    } else {
	report_str = "nonperiodic_data";
	hd_rtype = REPORT_EVENT_DATA;
    }
    json_object_object_add(report, "content_type", json_object_new_string(report_str));
    json_object_object_add(report, "content_value", msg);
    report_str = json_object_to_json_string( report );
    report_size = strlen( report_str );
    omp_log("%s", report_str);

    size = fill_delivery_req( buf, hd_rtype, report_size );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_CTRL_NOTI" );
    len = write( sock_fd, report_str, report_size );
    require_action( len > 0 && len == report_size, exit, err = kWriteErr );

  exit:
    if ( buf )
	free( buf );
    if ( report )
	json_object_put(report);
    if ( msg )
	json_object_put(msg);

    return err;
}

static OSStatus process_omp_init( int sock_fd, uint32_t tid, json_object *msg, void *buf )
{
    int len;
    int json_size;
    size_t size;
    json_object* report = NULL;
    const char *  json_str;
    OSStatus err = kNoErr;

    report = json_object_new_object();
    json_object_object_foreach( msg, key, val ) {
	if ( strcmp( key, "command_id" ) == 0 ) {
	    json_object_object_add(report, "command_id", json_object_new_string(json_object_get_string(val)));
	} else if ( strcmp( key, "content_cycle" ) == 0 ) {
	    json_object_object_add(report, "content_cycle", json_object_new_string(json_object_get_string(val)));
	}
    }
    json_str = json_object_to_json_string(report);
    omp_log("%s", json_str);
    require_action( json_str, exit, err = kNoMemoryErr );

    json_size = strlen(json_str);
    size = fill_ctrl_noti( buf, OMP_INIT, json_size, tid );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_CTRL_NOTI" );
    len = write( sock_fd, json_str, json_size );
    require_action( len > 0 && len == json_size, exit, err = kWriteErr );

    /* force to trigger send delivery message */
    timeout_enable( TIMEOUT_DELIVERY, 0 );
    
  exit:
    if(report)
	json_object_put(report);
    return err;
}

static OSStatus process_omp_control( int sock_fd, uint32_t tid, json_object *msg, void *buf )
{
    int len;
    int json_size;
    size_t size;
    json_object* report = NULL;
    json_object* response = NULL;
    const char *  json_str;
    OSStatus err = kNoErr;
    char cmd_type[20] = "";
    char cmd_value[20] = "";

    report = json_object_new_object();
    response = json_object_new_object();
    json_object_object_foreach( msg, key, val ) {
	if ( strcmp( key, "command_id" ) == 0 ) {
	    json_object_object_add(report, "command_id", json_object_new_string(json_object_get_string(val)));
	} else if ( strcmp( key, "command_type" ) == 0 ) {
	    strcpy( cmd_type, json_object_get_string(val) );
	} else if ( strcmp( key, "request_value" ) == 0 ) {
	    strcpy( cmd_value, json_object_get_string(val) );
	}
    }

    json_object_object_add(response, cmd_type, json_object_new_string(cmd_value));

    json_object_object_add(report, "response_value", response);
    json_str = json_object_to_json_string(report);
    omp_log("%s", json_str);
    require_action( json_str, exit, err = kNoMemoryErr );

    json_size = strlen(json_str);
    size = fill_ctrl_noti( buf, OMP_CONTROL, json_size, tid );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_CTRL_NOTI" );
    len = write( sock_fd, json_str, json_size );
    require_action( len > 0 && len == json_size, exit, err = kWriteErr );

    smarthome_state.reply_control(cmd_type, cmd_value);

  exit:
    if(report)
	json_object_put(report);
    if (response)
	json_object_put(response);
    return err;
}

static OSStatus process_omp_deinit( int sock_fd, uint32_t tid, json_object *msg, void *buf )
{
    int len;
    int json_size;
    size_t size;
    json_object* report = NULL;
    const char *  json_str;
    OSStatus err = kNoErr;

    report = json_object_new_object();
    json_object_object_foreach( msg, key, val ) {
	if ( strcmp( key, "command_id" ) == 0 ) {
	    json_object_object_add(report, "command_id", json_object_new_string(json_object_get_string(val)));
	}
    }
    json_str = json_object_to_json_string(report);
    omp_log("%s", json_str);
    require_action( json_str, exit, err = kNoMemoryErr );

    json_size = strlen(json_str);
    size = fill_ctrl_noti( buf, OMP_DEINIT, json_size, tid );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_CTRL_NOTI" );
    len = write( sock_fd, json_str, json_size );
    require_action( len > 0 && len == json_size, exit, err = kWriteErr );

  exit:
    if(report)
	json_object_put(report);
    return err;
}

static OSStatus process_control_message( int sock_fd, uint32_t tid, int control_type, char* str, void *buf )
{
    OSStatus err = kNoErr;
    json_object *msg = NULL;
    omp_log("%s", str);

    msg = json_tokener_parse( str );
    require_action( msg, exit, err = kUnknownErr );

    switch (control_type) {
    case OMP_INIT:
	err = process_omp_init( sock_fd, tid, msg, buf );
	require_noerr(err, exit);
	break;
    case OMP_CONTROL:
	err = process_omp_control( sock_fd, tid, msg, buf );
	require_noerr(err, exit);
	break;
    case OMP_DEINIT:
	err = process_omp_deinit( sock_fd, tid, msg, buf );
	require_noerr(err, exit);
	break;
    case OMP_REPORT_INTERVAL:
    default:
	omp_log("Unknown control type = %d(0x%x)", control_type, control_type);
	break;
    }

  exit:
    if(msg)
	json_object_put(msg);
    return err;
}

static OSStatus process_recv_message( int sock_fd )
{
    void *buf = NULL;
    size_t size;
    OSStatus err = kUnknownErr;
    gmmp_header_t *hd, *hd_resp;
    buf = malloc( MAX_OMP_FRAME * 2 );
    require( buf, exit );
    hd = buf;

    size = MAX_OMP_FRAME;
    err = read_gmmp_frame( sock_fd, buf, &size );
    require_noerr_string( err, exit, "fail to recv reg_resp" );
    if (size == 0) {
	err = kNoErr;
	goto exit;
    }
    omp_log("Message size: %u", size);
    
    switch ( hd->type ) {
    case GMMP_GW_REG_RESP: {
	bool update = false;
	gw_reg_resp_t *body = (gw_reg_resp_t*)&hd[1];
	omp_log("Recv GMMP_GW_REG_RESP: result=0x%x", body->result_code);
	require_action_string(body->result_code == 0, exit, err = kResponseErr, "Bad result code");

	mico_rtos_lock_mutex( &sys_context->flashContentInRam_mutex );
	if ( memcmp( smarthome_state.auth_key, hd->auth_key, sizeof(hd->auth_key)) != 0 ) {
	    update = true;
	    memset( smarthome_state.auth_key, 0, sizeof(smarthome_state.auth_key) );
	    memcpy( smarthome_state.auth_key, hd->auth_key, sizeof(hd->auth_key) );
	}
	if ( memcmp(smarthome_state.gw_id, body->gw_id, sizeof(body->gw_id)) != 0 ) {
	    update = true;
	    memset( smarthome_state.gw_id, 0, sizeof(smarthome_state.gw_id) );
	    memcpy( smarthome_state.gw_id, body->gw_id, sizeof(body->gw_id) );
	}
	mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex );
	if (update) {
	    err = mico_system_context_update(mico_system_context_get());
	    check_string(err == kNoErr, "Fail to update conf to Flash memory");
	}

	err = send_enc_info_req( sock_fd );
	require_noerr( err, exit );
	break;
    }
    case GMMP_PROFILE_RESP: {
	profile_resp_t *body = (profile_resp_t*)&hd[1];
	body->heartbeat_period = ntohl(body->heartbeat_period);
	body->report_period = ntohl(body->report_period);
	omp_log("Recv GMMP_PROFILE_RESP: hearteat=%lu, report=%lu", body->heartbeat_period, body->report_period);
	smarthome_state.report_period = body->report_period * 60;
	smarthome_state.heartbeat_period = body->heartbeat_period * 60;

	timeout_enable(TIMEOUT_HEARTBEAT, 1); /* force to trigger */
	timeout_enable(TIMEOUT_DELIVERY, smarthome_state.report_period);

	/* NOTE: seems unnessary */
	if (0) {
	    err = send_dev_register( sock_fd );
	    require_noerr( err, exit );
	}
	break;
    }
    case GMMP_DEV_REG_RESP: {
	bool update = false;
	dev_reg_resp_t *body = (dev_reg_resp_t*)&hd[1];
	omp_log("Recv GMMP_DEV_REG_RESP: result=0x%x", body->result_code);
	require_action_string(body->result_code == 0, exit, err = kResponseErr, "Bad result code");
	
	mico_rtos_lock_mutex( &sys_context->flashContentInRam_mutex );
	if ( memcmp(smarthome_state.dev_id, body->device_id, sizeof(body->device_id)) != 0 ) {
	    update = true;
	    memset( smarthome_state.dev_id, 0, sizeof(smarthome_state.dev_id) );
	    memcpy( smarthome_state.dev_id, body->device_id, sizeof(body->device_id) );
	}
	mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex );
	if (update) {
	    err = mico_system_context_update(mico_system_context_get());
	    check_string(err == kNoErr, "Fail to update conf to Flash memory");
	}
	break;
    }
    case GMMP_GW_DEREG_RESP: {
	gw_dereg_resp_t *body = (gw_dereg_resp_t*)&hd[1];
	omp_log("Recv GMMP_GW_DEREG_RESP: result=0x%x", body->result_code);
	break;
    }
    case GMMP_HEARTBEAT_RESP: {
	omp_log("Recv GMMP_HEARTBEAT_RESP");
	break;
    }
    case GMMP_DELIVERY_RESP: {
	delivery_resp_t *body = (delivery_resp_t*)&hd[1];
	body->backoff_time = ntohl(body->backoff_time);
	omp_log("Recv GMMP_DELIVERY_RESP: result=0x%x, backoff time=0x%lx", body->result_code, body->backoff_time);
	require_action_string(body->result_code == 0, exit, err = kResponseErr, "Bad result code");
	break;

    }
    case GMMP_CTRL_NOTI_RESP: {
	ctrl_noti_resp_t *body = (ctrl_noti_resp_t*)&hd[1];
	omp_log("Recv GMMP_CTRL_NOTI_RESP: result=0x%x, control type=0x%x", body->result_code, body->control_type);
	require_action_string(body->result_code == 0, exit, err = kResponseErr, "Bad result code");

	if (body->control_type == OMP_DEINIT && body->result_code == 0) {
		smarthome_device_user_conf_t* conf = get_user_conf();
		mico_rtos_lock_mutex( &sys_context->flashContentInRam_mutex );
		memset( &conf->server, 0, sizeof(conf->server) );
		sys_context->flashContentInRam.micoSystemConfig.configured = unConfigured;
		mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex );
		mico_system_context_update(mico_system_context_get());
		mico_system_power_perform( &sys_context->flashContentInRam, eState_Software_Reset );
	}
	break;
    }
    case GMMP_ENC_INFO_RESP: {
	enc_info_resp_t *body = (enc_info_resp_t*)&hd[1];
	omp_log("Recv GMMP_ENC_INFO_RESP: result=0x%x", body->result_code);
	require_action_string(body->result_code == 0, exit, err = kResponseErr, "Bad result code");

	omp_log("ENC_FLAG: %d, ENC_ALGORITHM: %d", body->enc_flag, body->enc_algorithm);
	check_string(!body->enc_flag || body->enc_algorithm == ENC_AES_128, "Currently support AES128 only");
	if (body->enc_flag && body->enc_algorithm == ENC_AES_128) {
	    MicoRandomNumberRead(smarthome_state.aes128_key, kAES_ECB_Size);

	    err = send_set_enc_key_req( sock_fd );
	} else {
	    /* skip encryption */
	    err = send_profile_req( sock_fd );
	}
	require_noerr( err, exit );
	break;
    }
    case GMMP_SET_ENC_KEY_RESP: {
	set_enc_key_resp_t *body = (set_enc_key_resp_t*)&hd[1];
	omp_log("Recv GMMP_SET_ENC_KEY_RESP: result=0x%x", body->result_code);
	require_action_string(body->result_code == 0, exit, err = kResponseErr, "Bad result code");
	smarthome_state.use_aes128 = true;
	
	err = send_profile_req( sock_fd );
	require_noerr( err, exit );
	break;
    }
    case  GMMP_CTRL_REQ: {
	int len;
	ctrl_req_t *body = (ctrl_req_t*)&hd[1];
	char *json_data = (char*)&body[1];
	size_t size = hd->len - sizeof(*hd) - sizeof(*body);
	json_data[size] = '\0';
	omp_log("Recv GMMP_CTRL_REQ: control type=0x%x (json=%u)", body->control_type, size);

	/* reply first */
	hd_resp = (void*)((char*)buf + MAX_OMP_FRAME);
	size = fill_ctrl_resp( hd_resp, hd );
	len = write( sock_fd, hd_resp, size );
	require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to respond GMMP_CTRL_REQ" );

	err = process_control_message( sock_fd, hd->tid, body->control_type, json_data, hd_resp );
	require_noerr(err, exit);

	if (body->control_type == OMP_INIT)
	    timeout_enable(TIMEOUT_DELIVERY, 2); /* trigger delivery message */

	break;
    }
    default:
	omp_log("Recv not interresting message: type=0x%x", hd->type);
	break;
    }

  exit:
    if (buf)
	free( buf );
    return err;
    
}

static void omp_thread( mico_thread_arg_t arg )
{
    int id;
    int sock_fd;
    fd_set readfds;
    struct timeval t;
    OSStatus err = kUnknownErr;
    smarthome_device_user_conf_t* s_conf = get_user_conf();

    timeout_init(timeout_table, TIMEOUT_MAX);

    if(update_state_sem == NULL)
	mico_rtos_init_semaphore( &update_state_sem, 1 );

    update_state_fd = mico_create_event_fd( update_state_sem );

    while ( 1 ) {
	sock_fd = connect_gmmp( s_conf->server.ip, s_conf->server.port );
	require( sock_fd > 0, retry );

	timeout_disable_all();
	send_gw_register( sock_fd );

	while (1) {
	    t.tv_sec = timeout_next_timeout();
	    /* FIXME: need to verify select with semaphore */
	    t.tv_sec = 1;
	    t.tv_usec = 0;
	    FD_ZERO(&readfds);
	    FD_SET(update_state_fd, &readfds);
	    FD_SET(sock_fd, &readfds);
	    require(select( Max(sock_fd, update_state_fd) + 1 , &readfds, NULL, NULL, &t) >= 0, retry);

	    if ( FD_ISSET( update_state_fd, &readfds ) ){
		mico_rtos_get_semaphore( &update_state_sem, 0 );
		err = send_report( sock_fd, OMP_REPORT_NONPERIODIC );
		require_noerr_string(err, retry, "Fail to send non-periodic Delivery");
	    }
	    
	    if ( FD_ISSET(sock_fd, &readfds) ) {
		err = process_recv_message( sock_fd );
		require_noerr(err, retry);
	    }

	    id = timeout_get();
	    switch (id) {
	    case TIMEOUT_GENERAL:
		break;
	    case TIMEOUT_HEARTBEAT:
		err = send_heaertbeat( sock_fd );
		require_noerr_string(err, retry, "Fail to send Heartbeat");
		timeout_enable( TIMEOUT_HEARTBEAT, smarthome_state.heartbeat_period );
		break;
	    case TIMEOUT_DELIVERY:
		err = send_report( sock_fd, OMP_REPORT_PERIODIC );
		require_noerr_string(err, retry, "Fail to send Delivery");
		timeout_enable( TIMEOUT_DELIVERY, smarthome_state.report_period );
		break;
	    default:
		break;
	    }
	    
	}
      retry:
	close( sock_fd );
	sock_fd = -1;
	mico_thread_msleep(2000);
    }
}

OSStatus omp_client_start( fill_json report, reply_control reply_control )
{
    OSStatus err = kNoErr;

    smarthome_state.fill_json = report;
    smarthome_state.reply_control = reply_control;

    err = mico_rtos_create_thread( NULL, MICO_APPLICATION_PRIORITY, "OMP",
				   omp_thread, STACK_SIZE_LOCAL_CONFIG_CLIENT_THREAD, 0 );
    require_noerr(err, exit);
    mico_thread_msleep(200);

  exit:
    return err;
}
    
OSStatus omp_client_stop( void )
{
    OSStatus err = kNoErr;
    require_action_string(0, exit, err = kUnsupportedErr, "Not supported");
  exit:
    return err;
}

OSStatus omp_trigger_event( void )
{
    if(update_state_sem)
	mico_rtos_set_semaphore( &update_state_sem );
    return kNoErr;
}
