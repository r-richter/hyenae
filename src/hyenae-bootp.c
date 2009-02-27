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

#include "hyenae-bootp.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_bootp_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned char* data,
      int data_len,
      unsigned int ip_ttl,
      unsigned int opcode
    ) {

  /*
   * USAGE:
   *   Builds a BOOTP packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int bootp_pkt_len =
    sizeof(hy_bootp_h_t) +
    data_len;
  unsigned char bootp_pkt[bootp_pkt_len];
  hy_bootp_h_t* bootp_h = NULL;

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
  /* Overwrite ports with BOOTP
     default ports */
  memset(src_pattern->src, 0, HY_PT_BUFLEN);
  memset(dst_pattern->src, 0, HY_PT_BUFLEN);
  if (opcode == HY_BOOTP_OP_BOOTREQUEST) {
    sprintf(
      src_pattern->src,
      "%s-%s@%i",
      src_pattern->hw_addr,
      src_pattern->ip_addr,
      HY_BOOTP_PORT_CLIENT);
    sprintf(
      dst_pattern->src,
      "%s-%s@%i",
      dst_pattern->hw_addr,
      dst_pattern->ip_addr,
      HY_BOOTP_PORT_SERVER);
  } else {
    sprintf(
      src_pattern->src,
      "%s-%s@%i",
      src_pattern->hw_addr,
      src_pattern->ip_addr,
      HY_BOOTP_PORT_SERVER);
    sprintf(
      dst_pattern->src,
      "%s-%s@%i",
      dst_pattern->hw_addr,
      dst_pattern->ip_addr,
      HY_BOOTP_PORT_CLIENT);
  }
  /* Validate pattern format */
  if (strlen(src_pattern->hw_addr) == 0 ||
      strlen(src_pattern->ip_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_SRC;
  }
  if (strlen(dst_pattern->hw_addr) == 0 ||
      strlen(dst_pattern->ip_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_DST;
  }
  if (src_pattern->ip_v != dst_pattern->ip_v) {
    return HY_ER_MULTIPLE_IP_V;
  }
  if (src_pattern->ip_v != HY_AD_T_IP_V4) {
    return HY_ER_WRONG_IP_V;
  }
  memset(bootp_pkt, 0, bootp_pkt_len);
  /* Build BOOTP header */
  bootp_h = (hy_bootp_h_t*) bootp_pkt;
  bootp_h->op = opcode;
  bootp_h->htype = HY_HTYPE_ETHERNET;
  bootp_h->hlen = ETH_ADDR_LEN;
  bootp_h->xid =
    htonl(
      (hy_random(1, 32000) * 1000000000) +
      hy_random(1, 32000));
  ip_pton(src_pattern->ip_addr, &bootp_h->ciaddr);
  eth_pton(src_pattern->hw_addr, &bootp_h->chaddr);
  /* Add data */
  if (data_len > 0) {
    memcpy(
      bootp_pkt + sizeof(hy_bootp_h_t),
      data,
      data_len);
  }
  /* Wrap IP-Layer */
  return hy_build_udp_packet(
            src_pattern,
            dst_pattern,
            ip_v_assumption,
            packet,
            packet_len,
            bootp_pkt,
            bootp_pkt_len,
            ip_ttl);
} /* hy_build_bootp_packet */

/* -------------------------------------------------------------------------- */
