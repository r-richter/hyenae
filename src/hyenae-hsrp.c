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

#include "hyenae-hsrp.h"

/* -------------------------------------------------------------------------- */

/* HSRP default authentification */
const
  char HY_HSRP_DEF_AUTH_DAT[8] =
  {
    0x63, 0x69, 0x73, 0x63, 0x6F, 0x00, 0x00, 0x00
  };

/* -------------------------------------------------------------------------- */

int
  hy_build_hsrp_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* vir_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned int ip_ttl,
      unsigned int hsrp_opcode,
      unsigned int hsrp_state,
      unsigned char* hsrp_auth,
      unsigned int hsrp_hello_tm,
      unsigned char hsrp_prio,
      unsigned char hsrp_group
    ) {

  /*
   * USAGE:
   *   Builds an HSRP packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int hsrp_pkt_len =
    sizeof(hy_hsrp_h_t);
  unsigned char hsrp_pkt[hsrp_pkt_len];
  hy_hsrp_h_t* hsrp_h = NULL;
  hy_pattern_t src_pat;
  hy_pattern_t dst_pat;

  /* Check for HSRP priority */
  if (hsrp_prio == 0) {
    return HY_ER_HSRP_PRIO_ZERO;
  }
  /* Check for HSRP state code */
  if (hsrp_state == HY_AT_OC_NONE) {
    return HY_ER_HSRP_CODE_ZERO;
  }
  /* Parse address patterns */
  if (strcmp(vir_pattern->src, "%") == 0) {
    strncpy(
      vir_pattern->src,
      "%-%",
      HY_PT_BUFLEN);
  }
  if ((ret =
         hy_parse_pattern(
           src_pattern,
           ip_v_assumption)) != HY_ER_OK ||
      (ret =
         hy_parse_pattern(
           vir_pattern,
           ip_v_assumption)) != HY_ER_OK) {
      return ret;
  }
  /* Overwrite ports with HSRP
     default ports and destination
     IP-Address with HSRP multicast
     address */
  memset(&src_pat, 0, sizeof(hy_pattern_t));
  memset(&dst_pat, 0, sizeof(hy_pattern_t));
  memcpy(&src_pat, src_pattern, sizeof(hy_pattern_t));
  sprintf(
    src_pat.src,
    "%s-%s@%i",
    src_pattern->hw_addr,
    src_pattern->ip_addr,
    HY_HSRP_PORT);
  sprintf(
    dst_pat.src,
    "%s-%s@%i",
    HY_HSRP_MC_HW_ADDR,
    HY_HSRP_MC_IP_ADDR,
    HY_HSRP_PORT);
  /* Validate pattern format */
  if (strlen(src_pat.hw_addr) == 0 ||
      strlen(src_pat.ip_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_SRC;
  }
  if (src_pat.ip_v != vir_pattern->ip_v) {
    return HY_ER_MULTIPLE_IP_V;
  }
  if (src_pat.ip_v != HY_AD_T_IP_V4) {
    return HY_ER_WRONG_IP_V;
  }
  memset(hsrp_pkt, 0, hsrp_pkt_len);
  /* Build HSRP header */
  hsrp_h = (hy_hsrp_h_t*) hsrp_pkt;
  hsrp_h->ver = 0;
  hsrp_h->op = hsrp_opcode;
  hsrp_h->state = hsrp_state;
  hsrp_h->hello_tm = hsrp_hello_tm;
  hsrp_h->hold_tm = hsrp_hello_tm * 3;
  hsrp_h->prio = hsrp_prio;
  hsrp_h->grp = hsrp_group;
  if (strlen(hsrp_auth) == 0) {
    strncpy(
      hsrp_h->auth,
      HY_HSRP_DEF_AUTH_DAT,
      HY_HSRP_AUTH_LEN);
  } else {
    strncpy(
      hsrp_h->auth,
      hsrp_auth,
      HY_HSRP_AUTH_LEN);
  }
  ip_pton(vir_pattern->ip_addr, &hsrp_h->v_ip);
  /* Wrap UDP-Layer */
  ret = hy_build_udp_packet(
          &src_pat,
          &dst_pat,
          ip_v_assumption,
          packet,
          packet_len,
          hsrp_pkt,
          hsrp_pkt_len,
          ip_ttl);
} /* hy_build_hsrp_packet */

/* -------------------------------------------------------------------------- */
