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

    omp_log( "connected\n" );
  exit:
    return err;
}

static bool is_registered_already( smarthome_device_user_conf_t* s_conf )
{
    smarhome_server_info_t* server = &s_conf->server;

    if (server->domain_code[0] && server->auth_key[0] && server->gw_id[0])
	return true;
    else
	return false;
}

static OSStatus process_register( int sock_fd, smarthome_device_user_conf_t* s_conf )
{
    OSStatus err = kUnknownErr;
    void *buf;
    size_t size;
    int len;
    gmmp_header_t *hd;
    gw_reg_resp_t *reg_resp;
    ctrl_req_t *ctrl_req;
    
    buf = malloc( MAX_OMP_FRAME );
    require( buf, exit );
    hd = buf;
    reg_resp = (gw_reg_resp_t*)&hd[1];
    ctrl_req = (ctrl_req_t*)&hd[1];

    while (1) {
	/* register request */
	size = fill_reg_req( buf );
	len = write( sock_fd, buf, size );
	require_string( len > 0 && size == len, exit, "fail to send reg_req" );

	size = MAX_OMP_FRAME;
	err = read_gmmp_frame( sock_fd, buf, &size );
	require_noerr_string( err, exit, "fail to recv reg_resp" );
	require_string( hd->type == GMMP_GW_REG_RESP, exit, "no reg_resp message" );

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

    /* waiting device initialize message */
    size = MAX_OMP_FRAME;
    err = read_gmmp_frame( sock_fd, buf, &size );
    require_noerr_string( err, exit, "fail to recv device init message" );
    require_string( hd->type == GMMP_CTRL_REQ, exit, "no control_req message" );
    require_string( ctrl_req->control_type == OMP_INIT, exit, "no OMP_INIT data" );

    /* TODO: 여기서 부터 시작(json parse) */
    

    
    free( buf );
  exit:
    return err;
}

static void omp_thread( mico_thread_arg_t arg )
{
    int sock_fd;
    OSStatus err = kUnknownErr;
    smarthome_device_user_conf_t* s_conf = smarthome_conf_get();

    
    while ( 1 ) {
	sock_fd = connect_gmmp( s_conf->server.ip, s_conf->server.port );
	require( sock_fd > 0, retry );

	if ( ! is_registered_already( s_conf ) )
	    err = process_register( sock_fd, s_conf );
	
	

      retry:
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
