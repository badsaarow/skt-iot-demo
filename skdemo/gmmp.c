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

static void fill_gmmp_hd( gmmp_header_t* hd,
		     gmmp_type_t type, size_t total_size, uint32_t tid )
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
}

size_t fill_reg_req( void* buf )
{
    size_t size;
    gmmp_header_t *hd = buf;
    gw_reg_req_t *body = (gw_reg_req_t*)&hd[1];
    smarthome_device_user_conf_t *conf = get_user_conf();

    size = sizeof(*hd) + sizeof(*body);
    fill_gmmp_hd( hd, GMMP_GW_REG_REQ, size, 0 );
    memcpy(body->domain_code, conf->server.domain_code, sizeof(body->domain_code));
    memcpy(body->manufacture_id, conf->dev_info.device_mf_id, sizeof(body->manufacture_id));
    hton_gmmp_hd(hd);
    return size;
}

