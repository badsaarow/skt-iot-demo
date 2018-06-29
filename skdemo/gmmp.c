/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"

#include "gmmp.h"
#include "smarthome_conf.h"

#define GMMP_VERSION 0x21

static uint32_t next_tid;

static const char* get_type_name(int type)
{
    switch (type) {
    case GMMP_GW_REG_REQ: return "GMMP_GW_REG_REQ";
    case GMMP_GW_REG_RESP: return "GMMP_GW_REG_RESP";
    case GMMP_GW_DEREG_REQ: return "GMMP_GW_DEREG_REQ";
    case GMMP_GW_DEREG_RESP: return "GMMP_GW_DEREG_RESP";
    case GMMP_CTRL_REQ: return "GMMP_CTRL_REQ";
    case GMMP_CTRL_RESP: return "GMMP_CTRL_RESP";
    case GMMP_HEARTBEAT_REQ: return "GMMP_HEARTBEAT_REQ";
    case GMMP_HEARTBEAT_RESP: return "GMMP_HEARTBEAT_RESP";
    case GMMP_CTRL_NOTI: return "GMMP_CTRL_NOTI";
    case GMMP_CTRL_NOTI_RESP: return "GMMP_CTRL_NOTI_RESP";
    case GMMP_ENC_INFO_REQ: return "GMMP_ENC_INFO_REQ";
    case GMMP_ENC_INFO_RESP: return "GMMP_ENC_INFO_RESP";
    case GMMP_SET_ENC_KEY_REQ: return "GMMP_SET_ENC_KEY_REQ";
    case GMMP_SET_ENC_KEY_RESP: return "GMMP_SET_ENC_KEY_RESP";
    default:
	return "GMMP_UNKNOWN";
    }
}

static void ntoh_gmmp_hd(gmmp_header_t* hd)
{
    hd->len = ntohs(hd->len);
    hd->timestamp = ntohl(hd->timestamp);
    hd->total_count = ntohs(hd->total_count);
    hd->current_count = ntohs(hd->current_count);
    hd->tid = ntohl(hd->tid);
}

static void hton_gmmp_hd(gmmp_header_t* hd)
{
    hd->len = htons(hd->len);
    hd->timestamp = htonl(hd->timestamp);
    hd->total_count = htons(hd->total_count);
    hd->current_count = htons(hd->current_count);
    hd->tid = htonl(hd->tid);
}

OSStatus read_gmmp_frame( int fd, void *buf, size_t *size )
{
    int tot;
    int left;
    char *p = buf;
    gmmp_header_t *hd = buf;
    OSStatus err;

    err = read( fd, p, 4 );
    if (err == 0) {
	*size = 0;
	return kNoErr;
    }
    require( err == 4, exit );

    tot = ntohs( hd->len );
    require( *size >= tot, exit);
    left = tot - 4;
    p += 4;
    require( left > 0 , exit );

    while ( left > 0 ) {
	err = read( fd, p, left );
	require( err > 0, exit );
	left -= err;
	p += err;
    }

    ntoh_gmmp_hd(hd);
    *size = tot;
    return kNoErr;
  exit:
    return err;
}

static void fill_gmmp_hd( gmmp_header_t* hd, gmmp_type_t type, size_t total_size, uint32_t tid )
{
    smarthome_device_user_conf_t *conf = get_user_conf();
    hd->ver = GMMP_VERSION;
    hd->len = total_size;
    hd->type = type;
    hd->timestamp = time(NULL);
    hd->total_count = 1;
    hd->current_count = 1;
    memcpy(hd->auth_id, conf->dev_info.device_sn, sizeof(hd->auth_id));
    memcpy(hd->auth_key, conf->server.auth_key, sizeof(hd->auth_key));
    if (tid == 0)
	tid = next_tid++;
    hd->tid = tid;
    hd->encrypted = 0;
    hd->reserved = 0;

    omp_log("Send %s Packet", get_type_name(type));
    omp_log("  size: %u, tid: %lu", total_size, tid);
}

size_t fill_reg_req( void* buf )
{
    size_t size;
    gmmp_header_t *hd = buf;
    gw_reg_req_t *body = (gw_reg_req_t*)&hd[1];
    smarthome_device_user_conf_t *conf = get_user_conf();

    size = sizeof(*hd) + sizeof(*body);
    fill_gmmp_hd( hd, GMMP_GW_REG_REQ, size, 0);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->manufacture_id, conf->dev_info.device_mf_id, sizeof(body->manufacture_id));

    hton_gmmp_hd(hd);
    return size;
}

size_t fill_heartbeat_req( void* buf )
{
    size_t size;
    gmmp_header_t *hd = buf;
    heartbeat_req_t *body = (heartbeat_req_t*)&hd[1];
    smarthome_device_user_conf_t *conf = get_user_conf();

    size = sizeof(*hd) + sizeof(*body);
    fill_gmmp_hd( hd, GMMP_HEARTBEAT_REQ, size, 0);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, conf->server.gw_id, sizeof(body->gw_id));

    hton_gmmp_hd(hd);
    return size;
}

size_t fill_ctrl_resp( void* buf, gmmp_header_t *req)
{
    size_t size;
    gmmp_header_t *hd = buf;
    ctrl_resp_t *body = (ctrl_resp_t*)&hd[1];
    ctrl_req_t *body_req = (ctrl_req_t*)&req[1];

    size = sizeof(*hd) + sizeof(*body);
    hd->type = GMMP_CTRL_RESP;
    hd->len = size;
    hd->total_count = hd->current_count = 1;
    hd->encrypted = 0;

    *((ctrl_req_t*)body) = *body_req;
    body->result_code = 0;

    omp_log("Send %s Packet", get_type_name(hd->type));
    omp_log("  size: %u, tid: %lu", size, hd->tid);

    hton_gmmp_hd(hd);
    return size;
}

size_t fill_ctrl_noti( void* buf, int control_type, int json_size )
{
    size_t size;
    gmmp_header_t *hd = buf;
    ctrl_noti_t *body = (ctrl_noti_t*)&hd[1];
    smarthome_device_user_conf_t *conf = get_user_conf();

    size = sizeof(*hd) + sizeof(*body);
    fill_gmmp_hd( hd, GMMP_CTRL_NOTI, size + json_size, 0);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, conf->server.gw_id, sizeof(body->gw_id));
    memset(body->device_id, 0, sizeof(body->device_id));
    body->control_type = control_type;
    body->result_code = 0;

    hton_gmmp_hd(hd);
    return size;
}
