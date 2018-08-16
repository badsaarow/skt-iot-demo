/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"

#include "gmmp.h"
#include "smarthome_conf.h"
 #include "smarthome.h"

#define GMMP_VERSION 0x21

static uint32_t cur_tid;

static const char* get_type_name(int type)
{
    switch (type) {
    case GMMP_GW_REG_REQ: return "GMMP_GW_REG_REQ";
    case GMMP_GW_REG_RESP: return "GMMP_GW_REG_RESP";
    case GMMP_GW_DEREG_REQ: return "GMMP_GW_DEREG_REQ";
    case GMMP_GW_DEREG_RESP: return "GMMP_GW_DEREG_RESP";
    case GMMP_PROFILE_REQ: return "GMMP_PROFILE_REQ";
    case GMMP_PROFILE_RESP: return "GMMP_PROFILE_RESP";
    case GMMP_DEV_REG_REQ: return "GMMP_DEV_REG_REQ";
    case GMMP_DEV_REG_RESP: return "GMMP_DEV_REG_RESP";
    case GMMP_DEV_DEREG_REQ: return "GMMP_DEV_DEREG_REQ";
    case GMMP_DEV_DEREG_RESP: return "GMMP_DEV_DEREG_RESP";
    case GMMP_DELIVERY_REQ: return "GMMP_DELIVERY_REQ";
    case GMMP_DELIVERY_RESP: return "GMMP_DELIVERY_RESP";
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

#define LOG_STR(_base, _name)		\
    memcpy(buf, _base->_name, sizeof(_base->_name));\
    buf[sizeof(_base->_name)] = '\0';		    \
    omp_log("  %-13s: %s", #_name, buf)

static void *get_body_ptr( gmmp_header_t* hd )
{
    void *body = &hd[1];
    return body;
}

static void dump_gmmp( gmmp_header_t* hd )

{
//#define DEBUG_MESSAGE
#ifdef DEBUG_MESSAGE
    char buf[40];
    omp_log(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    omp_log("%s", get_type_name(hd->type));
    omp_log("  ver          : 0x%x", hd->ver);
    omp_log("  len          : %d", hd->len);
    omp_log("  type         : 0x%x", hd->type);
    omp_log("  timestamp    : 0x%lx", hd->timestamp);
    omp_log("  total_count  : %d", hd->total_count);
    omp_log("  current_count: %d", hd->current_count);
    LOG_STR(hd, auth_id);
    LOG_STR(hd, auth_key);
    omp_log("  tid          : 0x%lx", hd->tid);
    omp_log("  encrypted    : %d", hd->encrypted);
    omp_log("  reserved     : %d", hd->reserved);

    omp_log("----------------------------------------");
    
    switch( hd->type ) {
    case GMMP_GW_REG_REQ:
    case GMMP_GW_DEREG_REQ:
    {
	gw_reg_req_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, manufacture_id);
	break;
    }
    case GMMP_GW_REG_RESP:
    case GMMP_GW_DEREG_RESP:
    {
	gw_reg_resp_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	omp_log("  result_code  : 0x%x", body->result_code);
	break;
    }
    case GMMP_PROFILE_REQ:
    case GMMP_ENC_INFO_REQ:
    {
	profile_req_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	break;
    }
    case GMMP_DEV_DEREG_REQ:
    case GMMP_PROFILE_RESP:
    {
	profile_resp_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	omp_log("  result_code  : 0x%x", body->result_code);
	omp_log("  heartbeat_period: %lu", body->heartbeat_period);
	omp_log("  report_period: %lu", body->report_period);
	omp_log("  report_offset: %lu", body->report_offset);
	omp_log("  response_timeout: %lu", body->response_timeout);
	LOG_STR(body, model);
	LOG_STR(body, firmware_version);
	LOG_STR(body, software_version);
	LOG_STR(body, hardware_version);
	break;
    }
    case GMMP_DEV_REG_REQ:
    {
	dev_reg_req_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, manufacture_id);
	break;
    }
    case GMMP_DEV_DEREG_RESP:
    case GMMP_DEV_REG_RESP:
    case GMMP_SET_ENC_KEY_RESP:
    {
	dev_reg_resp_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	omp_log("  result_code  : 0x%x", body->result_code);
	break;
    }
    case GMMP_DELIVERY_REQ:
    {
	delivery_req_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	omp_log("  report_type  : 0x%x", body->report_type);
	omp_log("  media_type   : 0x%x", body->media_type);
	break;
    }
    case GMMP_DELIVERY_RESP:
    {
	delivery_resp_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	omp_log("  result_code  : 0x%x", body->result_code);
	omp_log("  backoff_time : %lu", body->backoff_time);
	break;
    }
    case GMMP_CTRL_REQ:
    {
	ctrl_req_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	omp_log("  control_type : 0x%x", body->control_type);
	break;
    }
    case GMMP_CTRL_RESP:
    case GMMP_CTRL_NOTI:
    case GMMP_CTRL_NOTI_RESP:
    {
	ctrl_resp_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	omp_log("  control_type : 0x%x", body->control_type);
	omp_log("  result_code  : 0x%x", body->result_code);
	break;
    }
    case GMMP_HEARTBEAT_REQ:
    case GMMP_HEARTBEAT_RESP:
    {
	heartbeat_req_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	break;
    }
    case GMMP_ENC_INFO_RESP:
    {
	enc_info_resp_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	omp_log("  result_code  : 0x%x", body->result_code);
	omp_log("  enc_flag     : 0x%x", body->enc_flag);
	omp_log("  enc_algorithm: 0x%x", body->enc_algorithm);
	break;
    }
    case GMMP_SET_ENC_KEY_REQ:
    {
	set_enc_key_req_t* body = get_body_ptr( hd );
	LOG_STR(body, domain_code);
	LOG_STR(body, gw_id);
	LOG_STR(body, device_id);
	LOG_STR(body, enc_key);
	break;
    }
    }
    omp_log("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
#endif
}

static size_t encrypt_json(void *dest, const void *src, int json_size)
{
    size_t enc_size;
    uint16_t *org_size = dest;
    smarthome_state_t *state = get_smarthome_state();

    *org_size = htons(json_size);
    enc_size = ((json_size + kAES_ECB_Size -  1) / kAES_ECB_Size) * kAES_ECB_Size;
    AES_ECB_Update(&state->enc_context, src, enc_size, &org_size[1]);
    return enc_size + sizeof(uint16_t);
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
    switch ( hd->type ) {
    case GMMP_PROFILE_RESP: {
	    profile_resp_t *body = (profile_resp_t*)&hd[1];
	    body->heartbeat_period = ntohl(body->heartbeat_period);
	    body->report_period = ntohl(body->report_period);
	    body->report_offset = ntohl(body->report_offset);
	    body->response_timeout = ntohl(body->response_timeout);
	    break;
    }
    case GMMP_DELIVERY_RESP: {
	    delivery_resp_t *body = (delivery_resp_t*)&hd[1];
	    body->backoff_time = ntohl(body->backoff_time);
	    break;
    }
    default:
	    break;
    }
    
    dump_gmmp(hd);
    *size = tot;
    return kNoErr;
  exit:
    return err;
}

static void fill_gmmp_hd( gmmp_header_t* hd, gmmp_type_t type, size_t total_size, uint32_t tid, bool encrypted )
{
    smarthome_device_user_conf_t *conf = get_user_conf();
    smarthome_state_t *state = get_smarthome_state();

    hd->ver = GMMP_VERSION;
    hd->len = total_size;
    hd->type = type;
    hd->timestamp = time(NULL);
    hd->total_count = 1;
    hd->current_count = 1;
    memcpy(hd->auth_id, conf->dev_info.device_sn, sizeof(hd->auth_id));
    memcpy(hd->auth_key, state->auth_key, sizeof(hd->auth_key));
    if (tid == 0)
	tid = ++cur_tid;
    hd->tid = tid;
    hd->encrypted = encrypted;
    hd->reserved = 0;

    omp_log("Send %s Packet", get_type_name(type));
    omp_log("  size: %u, tid: %lu", total_size, tid);
}

#define PREPARE_HD(hd_type, data_type, tid, use_enc)	\
    size_t size;\
    gmmp_header_t *hd = buf;\
    data_type *body;\
    smarthome_state_t *state = get_smarthome_state();\
    smarthome_device_user_conf_t *conf = get_user_conf();\
    size = sizeof(*hd) + sizeof(*body);\
    fill_gmmp_hd( hd, hd_type, size, tid, (use_enc) ? state->use_aes128: 0); \
    body = get_body_ptr( hd );
    
#define POST_PROCESS()\
    dump_gmmp(hd);\
    hton_gmmp_hd(hd);\
    return ntohs(hd->len);

size_t fill_gw_reg_req( void* buf )
{
    PREPARE_HD(GMMP_GW_REG_REQ, gw_reg_req_t, 0, false);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->manufacture_id, conf->dev_info.device_mf_id, sizeof(body->manufacture_id));
    POST_PROCESS();
}

size_t fill_dev_reg_req( void* buf )
{
    PREPARE_HD(GMMP_DEV_REG_REQ, dev_reg_req_t, 0, false);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, state->gw_id, sizeof(body->gw_id));
    memcpy(body->manufacture_id, conf->dev_info.device_mf_id, sizeof(body->manufacture_id));
    POST_PROCESS();
}

size_t fill_enc_info_req( void* buf )
{
    PREPARE_HD(GMMP_ENC_INFO_REQ, enc_info_req_t, 0, false);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, smarthome_state.gw_id, sizeof(body->gw_id));
    memset(body->device_id, 0, sizeof(body->device_id));
    POST_PROCESS();
}

size_t fill_set_enc_key_req( void* buf )
{
    PREPARE_HD(GMMP_SET_ENC_KEY_REQ, set_enc_key_req_t, 0, false);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, state->gw_id, sizeof(body->gw_id));
    memset(body->device_id, 0, sizeof(body->device_id));
    memset(body->enc_key, 0, sizeof(body->enc_key));
    memcpy(body->enc_key, state->aes128_key, sizeof(state->aes128_key));
    POST_PROCESS();
}

size_t fill_heartbeat_req( void* buf )
{
    PREPARE_HD(GMMP_HEARTBEAT_REQ, heartbeat_req_t, 0, false);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, state->gw_id, sizeof(body->gw_id));
    POST_PROCESS();
}

size_t fill_profile_req( void* buf )
{
    PREPARE_HD(GMMP_PROFILE_REQ, profile_req_t, 0, false);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, state->gw_id, sizeof(body->gw_id));
    memset(body->device_id, 0, sizeof(body->device_id)); /* no device id */
    POST_PROCESS();
}

size_t fill_ctrl_resp( void* buf, gmmp_header_t *req)
{
    size_t size;
    gmmp_header_t *hd = buf;
    ctrl_resp_t *body;
    ctrl_req_t *body_req = get_body_ptr( req );

    size = sizeof(*hd) + sizeof(*body);
    *hd = *req;
    hd->type = GMMP_CTRL_RESP;
    hd->len = size;
    hd->total_count = hd->current_count = 1;
    hd->encrypted = 0;

    body = get_body_ptr( hd );
    *((ctrl_req_t*)body) = *body_req;
    body->result_code = 0;

    omp_log("Send %s Packet", get_type_name(hd->type));
    omp_log("  size: %u, tid: %lu", size, hd->tid);
    POST_PROCESS();
}

size_t fill_delivery_req( void* buf, gmmp_report_type_t report_type, const void* json, int json_size )
{
    PREPARE_HD(GMMP_DELIVERY_REQ, delivery_req_t, 0, true);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, state->gw_id, sizeof(body->gw_id));
    memset(body->device_id, 0, sizeof(body->device_id));
    body->report_type = report_type;
    body->media_type = MEDIA_TYPE_APPLICATION_JSON;

    omp_log("Json: %s", (char*)json);
    hd->len += encrypt_json(&body[1], json, json_size);
    POST_PROCESS();
}

size_t fill_ctrl_noti( void* buf, int control_type, const void* json, int json_size, uint32_t tid )
{
    PREPARE_HD(GMMP_CTRL_NOTI, ctrl_noti_t, tid, true);
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->gw_id, state->gw_id, sizeof(body->gw_id));
    memset(body->device_id, 0, sizeof(body->device_id));
    body->control_type = control_type;
    body->result_code = 0;

    omp_log("Json: %s", (char*)json);
    hd->len += encrypt_json(&body[1], json, json_size);
    POST_PROCESS();
}

void set_tid( uint32_t tid )
{
	cur_tid = tid;
}
