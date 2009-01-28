/*
 * Hyenae
 *   Advanced Network Packet Generator
 *
 * Copyright (C) 2009  Robin Richter
 *
 *   Contact  : richterr@users.sourceforge.net
 *   Homepage : http://sourceforge.net/projects/hyenae/
 *
 * This file is part of Hyenae.
 *
 * Hyenae is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Hyenae is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Hyenae.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "hyenae-protocol.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_remote_attack_request
    (
      hy_attack_t* params,
      unsigned char** buffer
    ) {

  /*
   * USAGE:
   *   Builds a send-ready remote attack request
   *   based on the given arguments.
   */

  int len = sizeof(hy_ra_request_h_t) +
            params->pay_len;
  hy_ra_request_h_t* ra_req_h = NULL;

  if (len > HY_MAX_RA_PKT_LEN) {
    return HY_ER_MAX_RA_PKT_LEN_EXCEED;
  }
  *buffer = malloc(len);
  memset(*buffer, 0, len);
  ra_req_h = (hy_ra_request_h_t*) *buffer;
  ra_req_h->att_type = params->type;
  memcpy(&ra_req_h->src_pat, &params->src_pat, sizeof(hy_pattern_t));
  memcpy(&ra_req_h->dst_pat, &params->dst_pat, sizeof(hy_pattern_t));
  memcpy(&ra_req_h->snd_pat, &params->snd_pat, sizeof(hy_pattern_t));
  memcpy(&ra_req_h->trg_pat, &params->trg_pat, sizeof(hy_pattern_t));
  ra_req_h->min_cnt = params->min_cnt;
  ra_req_h->max_cnt = params->max_cnt;
  ra_req_h->min_del = params->min_del;
  ra_req_h->max_del = params->max_del;
  ra_req_h->min_dur = params->min_dur;
  ra_req_h->max_dur = params->max_dur;
  ra_req_h->ip_ttl = params->ip_ttl;
  ra_req_h->tcp_flgs = params->tcp_flgs;
  ra_req_h->tcp_seq = params->tcp_seq;
  ra_req_h->tcp_seq_ins = params->tcp_seq_ins;
  ra_req_h->tcp_ack = params->tcp_ack;
  ra_req_h->tcp_wnd = params->tcp_wnd;
  ra_req_h->ip_v_asm = params->ip_v_asm;
  ra_req_h->ign_mtu = params->ign_mtu;
  ra_req_h->cld_run = params->cld_run;
  ra_req_h->pay_len = params->pay_len;
  if (ra_req_h->pay_len > 0) {
    memcpy(
      *buffer + sizeof(hy_ra_request_h_t),
      params->pay,
      params->pay_len);
  }
  return HY_ER_OK;
} /* hy_build_remote_attack_request */

/* -------------------------------------------------------------------------- */

int
  hy_parse_remote_attack_request
    (
      unsigned char* buffer,
      int len,
      hy_attack_t** params
    ) {

  /*
   * USAGE:
   *   Parses a received remote attack request.
   */

  hy_attack_t* att_par = NULL;
  hy_ra_request_h_t* ra_req_h = (hy_ra_request_h_t*) buffer;

  if (len < sizeof(hy_ra_request_h_t) ||
      len > HY_MAX_RA_PKT_LEN) {
    return HY_ER_PR_MALFORMED_RAR_H;
  }
  *params = malloc(sizeof(hy_attack_t));
  memset(*params, 0, sizeof(hy_attack_t));
  att_par = (hy_attack_t*) *params;
  memset(att_par, 0, sizeof(hy_attack_t));
  att_par->type = ra_req_h->att_type;
  memcpy(&att_par->src_pat, &ra_req_h->src_pat, sizeof(hy_pattern_t));
  memcpy(&att_par->dst_pat, &ra_req_h->dst_pat, sizeof(hy_pattern_t));
  memcpy(&att_par->snd_pat, &ra_req_h->snd_pat, sizeof(hy_pattern_t));
  memcpy(&att_par->trg_pat, &ra_req_h->trg_pat, sizeof(hy_pattern_t));
  att_par->min_cnt = ra_req_h->min_cnt;
  att_par->max_cnt = ra_req_h->max_cnt;
  att_par->min_del = ra_req_h->min_del;
  att_par->max_del = ra_req_h->max_del;
  att_par->min_dur = ra_req_h->min_dur;
  att_par->max_dur = ra_req_h->max_dur;
  att_par->ip_ttl = ra_req_h->ip_ttl;
  att_par->tcp_flgs = ra_req_h->tcp_flgs;
  att_par->tcp_seq = ra_req_h->tcp_seq;
  att_par->tcp_seq_ins = ra_req_h->tcp_seq_ins;
  att_par->tcp_ack = ra_req_h->tcp_ack;
  att_par->tcp_wnd = ra_req_h->tcp_wnd;
  att_par->ip_v_asm = ra_req_h->ip_v_asm;
  att_par->ign_mtu = ra_req_h->ign_mtu;
  att_par->cld_run = ra_req_h->cld_run;
  att_par->pay_len = ra_req_h->pay_len;
  if (len != (att_par->pay_len + sizeof(hy_ra_request_h_t))) {
    return HY_ER_PR_MALFORMED_RAR_H;
  }
  if (att_par->pay_len > 0) {
    att_par->pay = malloc(att_par->pay_len);
    memset(att_par->pay, 0, att_par->pay_len);
    memcpy(
      att_par->pay,
      (buffer + sizeof(hy_ra_request_h_t)),
      att_par->pay_len);
  } else {
    att_par->pay = NULL;
  }
  return HY_ER_OK;
} /* hy_parse_remote_attack_request */

/* -------------------------------------------------------------------------- */
