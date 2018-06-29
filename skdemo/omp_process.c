/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"
#include "SocketUtils.h"

#include "smarthome_conf.h"
#include "gmmp.h"
#include "omp.h"

extern system_context_t* sys_context;

typedef struct
{
    int content_cycle;
    fill_json fill_json;

} omp_state_t;

static omp_state_t omp_state = {
    .content_cycle = 600,
    .fill_json = NULL
};

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

static bool is_registered_already( void )
{
    smarthome_device_user_conf_t* s_conf = get_user_conf();
    smarhome_server_info_t* server = &s_conf->server;

    if (server->domain_code[0] && server->auth_key[0] && server->gw_id[0])
	return true;
    else
	return false;
}

static OSStatus process_register( int sock_fd )
{
    OSStatus err = kUnknownErr;
    void *buf;
    size_t size;
    int len;
    gmmp_header_t *hd;
    gw_reg_resp_t *reg_resp;
    smarthome_device_user_conf_t* s_conf = get_user_conf();
    
    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );
    hd = buf;
    reg_resp = (gw_reg_resp_t*)&hd[1];

    while (1) {
	/* register request */
	size = fill_reg_req( buf );
	len = write( sock_fd, buf, size );
	require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send reg_req" );

	size = MAX_OMP_FRAME;
	err = read_gmmp_frame( sock_fd, buf, &size );
	require_noerr_string( err, exit, "fail to recv reg_resp" );
	if (size == 0)
	    continue;

	require_string( hd->type == GMMP_GW_REG_RESP, exit, "no reg_resp message" );
	omp_log("Recv GMMP_GW_REG_RESP Packet");
	omp_log(" size: %u, tid: %lu, result_code: 0x%x", hd->len, hd->tid, reg_resp->result_code);

	if (reg_resp->result_code == 0)
	    break;

	mico_thread_msleep(2000);
    }
    
    /* fill auth_key and gw id */
    mico_rtos_lock_mutex( &sys_context->flashContentInRam_mutex );
    memset( s_conf->server.auth_key, 0, sizeof(s_conf->server.auth_key) );
    memset( s_conf->server.gw_id, 0, sizeof(s_conf->server.gw_id) );
    memcpy( s_conf->server.auth_key, hd->auth_key, sizeof(hd->auth_key) );
    memcpy( s_conf->server.gw_id, reg_resp->gw_id, sizeof(reg_resp->gw_id) );
    mico_rtos_unlock_mutex( &sys_context->flashContentInRam_mutex );
    err = mico_system_context_update(mico_system_context_get());
    check_string(err == kNoErr, "Fail to update conf to Flash memory");

  exit:
    free( buf );
    return err;
}

static OSStatus process_omp_init( int sock_fd, json_object *msg, void *buf )
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
    size = fill_ctrl_noti( buf, OMP_INIT, json_size );
    len = write( sock_fd, buf, size );
    require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to send GMMP_CTRL_NOTI" );
    len = write( sock_fd, json_str, json_size );
    require_action( len > 0 && len == json_size, exit, err = kWriteErr );

  exit:
    if(report)
	json_object_put(report);
    return err;
}

static OSStatus process_control_message( int sock_fd, int control_type, char* str, size_t size, void *buf )
{
    OSStatus err = kNoErr;
    json_object *msg = NULL;
    omp_log("%s", str);

    msg = json_tokener_parse( str );
    require_action( msg, exit, err = kUnknownErr );

    switch (control_type) {
    case OMP_INIT:
	err = process_omp_init( sock_fd, msg, buf );
	break;
    case OMP_REPORT_INTERVAL:
    case OMP_DEINIT:
    case OMP_CONTROL:
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
    void *buf;
    size_t size;
    OSStatus err = kUnknownErr;
    gmmp_header_t *hd, *hd_resp;
    buf = malloc( MAX_OMP_FRAME * 2 );
    require( buf, exit );
    hd = buf;

    size = MAX_OMP_FRAME;
    err = read_gmmp_frame( sock_fd, buf, &size );
    require_noerr_string( err, exit, "fail to recv reg_resp" );
    if (size == 0)
	return kNoErr;
    omp_log("Message size: %u", size);
    
    switch ( hd->type ) {
    case GMMP_GW_REG_RESP: {
	gw_reg_resp_t *body = (gw_reg_resp_t*)&hd[1];
	omp_log("Recv GMMP_GW_REG_RESP: result=0x%x", body->result_code);
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
    case GMMP_CTRL_NOTI_RESP: {
	ctrl_noti_resp_t *body = (ctrl_noti_resp_t*)&hd[1];
	omp_log("Recv GMMP_CTRL_NOTI_RESP: result=0x%x, control type=0x%x", body->result_code, body->control_type);
	break;
    }
    case GMMP_ENC_INFO_RESP: {
	enc_info_resp_t *body = (enc_info_resp_t*)&hd[1];
	omp_log("Recv GMMP_ENC_INFO_RESP: result=0x%x", body->result_code);
	break;
    }
    case GMMP_SET_ENC_KEY_RESP: {
	set_enc_key_resp_t *body = (set_enc_key_resp_t*)&hd[1];
	omp_log("Recv GMMP_SET_ENC_KEY_RESP: result=0x%x", body->result_code);
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
	len = write( sock_fd, buf, size );
	require_action_string( len > 0 && size == len, exit, err = kWriteErr, "fail to respond GMMP_CTRL_REQ" );
	
	err = process_control_message( sock_fd, body->control_type, json_data, size, hd_resp );

	break;
    }
    default:
	omp_log("Recv not interresting message: type=0x%x", hd->type);
	break;
    }

  exit:
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

static OSStatus send_periodic_report( int sock_fd )
{
    OSStatus err = kNoErr;
    json_object* report = NULL;
    json_object* msg = NULL;
    const char * msg_str;
    const char * report_str;
    int report_size;
    int len;
    size_t size;
    void *buf = NULL;

    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );

    omp_log("Prepare periodic report");
    report = json_object_new_object();
    msg = json_object_new_object();
    require( report && msg, exit );

    omp_state.fill_json( msg );

    msg_str = json_object_to_json_string( msg );
    omp_log("%s", msg_str);
    require_action( msg_str, exit, err = kNoMemoryErr );

    json_object_object_add(report, "content_type", json_object_new_string("periodic_data"));
    json_object_object_add(report, "content_value", json_object_new_string(msg_str));
    report_str = json_object_to_json_string( report );
    report_size = strlen( report_str );
    omp_log("%s", report_str);

    size = fill_ctrl_noti( buf, OMP_NOTIFY, report_size );
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

static void omp_thread( mico_thread_arg_t arg )
{
    int sock_fd;
    fd_set readfds;
    struct timeval t;
    OSStatus err = kUnknownErr;
    smarthome_device_user_conf_t* s_conf = get_user_conf();
    time_t heartbeat_time = 0;
    time_t periodic_data_time = 0;

    while ( 1 ) {
	sock_fd = connect_gmmp( s_conf->server.ip, s_conf->server.port );
	require( sock_fd > 0, retry );

	if ( ! is_registered_already() ) {
	    err = process_register( sock_fd );
	    require_noerr(err, retry);
	}

	heartbeat_time = 0;
	periodic_data_time = 0;

	while (1) {
	    int diff, diff_periodic;
	    int diff_heartbeat = time(NULL) - heartbeat_time;
	    if (diff_heartbeat >= HEARTBEAT_INTERVAL || heartbeat_time == 0) {
		err = send_heaertbeat( sock_fd );
		require_noerr(err, retry);
		heartbeat_time = time(NULL);
	    }
	    diff_periodic = time(NULL) - periodic_data_time;
	    if (diff_periodic >= omp_state.content_cycle || periodic_data_time == 0) {
		err = send_periodic_report( sock_fd );
		require_noerr(err, retry);
		periodic_data_time = time(NULL);
	    }

	    diff = Min(HEARTBEAT_INTERVAL - diff_heartbeat, omp_state.content_cycle - diff_periodic);
	    t.tv_sec = diff;
	    t.tv_usec = 0;
	    FD_ZERO(&readfds);
	    FD_SET(sock_fd, &readfds);
	    require(select( Max(sock_fd, sock_fd) + 1 , &readfds, NULL, NULL, &t) >= 0, retry);
	    
	    if ( FD_ISSET(sock_fd, &readfds) ) {
		err = process_recv_message( sock_fd );
		require_noerr(err, retry);
	    }
	}
      retry:
	close( sock_fd );
	sock_fd = -1;
	mico_thread_msleep(2000);
    }
}

OSStatus omp_client_start( fill_json fn )
{
    OSStatus err = kNoErr;

    omp_state.fill_json = fn;

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
