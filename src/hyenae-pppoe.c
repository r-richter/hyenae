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

#include "hyenae-pppoe.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_pppoe_discover_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned int pppoe_sid,
      unsigned int pppoe_code
    ) {

  /*
   * USAGE:
   *   Builds a PPPoE-Discover packet
   *   based on the given arguments.
   */

  int ret = HY_ER_OK;
  int pppoe_pkt_len =
    sizeof(hy_pppoe_h_t) + 
    sizeof(hy_pppoe_tag_t); /* Service Name*/
  unsigned char pppoe_pkt[pppoe_pkt_len];
  hy_pppoe_h_t* pppoe_h = NULL;
  hy_pppoe_tag_t* tag_sn = NULL;

   /* Parse address patterns */
  if ((ret =
         hy_parse_pattern(
           src_pattern,
           ip_v_assumption)) != HY_ER_OK ||
      (ret =
         hy_parse_pattern(
           dst_pattern,
           ip_v_assumption)) != HY_ER_OK) {
      return ret;
  }
  /* Validate pattern format */
  if (strlen(src_pattern->hw_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_SRC;
  }
  if (strlen(dst_pattern->hw_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_DST;
  }
  memset(pppoe_pkt, 0, pppoe_pkt_len);
  /* Build PPPoE header */
  pppoe_h = (hy_pppoe_h_t*) pppoe_pkt;
  pppoe_h->ver = 1;
  pppoe_h->type = 1;
  pppoe_h->code = pppoe_code;
  pppoe_h->sid = pppoe_sid;
  /* Add service name tag on active discovery initiation */
  if (pppoe_code == HY_PPPOE_CODE_PADI) {
    tag_sn = (hy_pppoe_tag_t*) (pppoe_pkt + sizeof(hy_pppoe_h_t));
    tag_sn->type = HY_PPOE_TAG_T_SERVICE_NAME;
    tag_sn->len = htons(0); /* Zero length to accept any service */    
    pppoe_h->len = htons(sizeof(hy_pppoe_tag_t));
  }
  /* Wrap Ethernet-Layer */
  return hy_build_eth_packet(
           src_pattern,
           dst_pattern,
           ip_v_assumption,
           packet,
           packet_len,
           pppoe_pkt,
           pppoe_pkt_len,
           ETH_TYPE_PPPOEDISC);
  return HY_ER_OK;
} /* hy_build_pppoe_discover_packet */

/* -------------------------------------------------------------------------- */
