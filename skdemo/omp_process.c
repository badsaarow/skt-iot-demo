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
    

} omp_state_t;


omp_state_t state;

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
	require_string( len > 0 && size == len, exit, "fail to send reg_req" );

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

    size = fill_heartbeat_req( buf );
    len = write( sock_fd, buf, size );
    require_string( len > 0 && size == len, exit, "fail to send GMMP_HEARTBEAT_REQ" );

    free( buf );
  exit:
    return err;
}

static OSStatus process_control_message( char* str, size_t size )
{
    OSStatus err = kNoErr;
    printf("######## %s\n", str);
    omp_log("%s", str);
    return err;
}

static OSStatus process_recv_message( int sock_fd )
{
    void *buf;
    size_t size;
    OSStatus err = kUnknownErr;
    gmmp_header_t *hd;
    buf = malloc( MAX_OMP_FRAME );
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
	ctrl_req_t *body = (ctrl_req_t*)&hd[1];
	char *json_data = (char*)&body[1];
	size_t size = hd->len - sizeof(*hd) - sizeof(*body);
	json_data[size] = '\0';
	omp_log("Recv GMMP_CTRL_REQ: control type=0x%x (json=%u)", body->control_type, size);
	err = process_control_message( json_data, size );
	break;
    }
    default:
	omp_log("Recv not interresting message: type=0x%x", hd->type);
	break;
    }

  exit:
    return err;
    
}

static void omp_thread( mico_thread_arg_t arg )
{
    int sock_fd;
    fd_set readfds;
    struct timeval t;
    OSStatus err = kUnknownErr;
    smarthome_device_user_conf_t* s_conf = get_user_conf();

    while ( 1 ) {
	sock_fd = connect_gmmp( s_conf->server.ip, s_conf->server.port );
	require( sock_fd > 0, retry );

	if ( ! is_registered_already() ) {
	    err = process_register( sock_fd );
	    require_noerr(err, retry);
	}

	while (1) {
	    t.tv_sec = 60;
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

OSStatus omp_client_start( void )
{
    OSStatus err = kNoErr;

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
