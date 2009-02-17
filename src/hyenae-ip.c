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

#include "hyenae-ip.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_ip_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned char* data,
      int data_len,
      unsigned int ip_proto,
      unsigned int ip_ttl
    ) {

  /*
   * USAGE:
   *   Builds an IP packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int ip_pkt_len = sizeof(ip_v6_h_t) + data_len;
  unsigned char ip_pkt[ip_pkt_len];
  ip_v4_h_t* ip_v4_h = NULL;
  ip_v6_h_t* ip_v6_h = NULL;

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
  memset(ip_pkt, 0, ip_pkt_len);
  if (src_pattern->ip_v == HY_AD_T_IP_V4) {
    /* Build IP header (IPv4) */
    ip_pkt_len = sizeof(ip_v4_h_t) + data_len;
    ip_v4_h = (ip_v4_h_t*) ip_pkt;
    ip_v4_h->ip_v = 4;
    ip_v4_h->ip_hl = 5;
    ip_v4_h->ip_len = htons(ip_pkt_len);
    ip_v4_h->ip_id = htons(hy_random(10000, 32000));
    ip_v4_h->ip_ttl = ip_ttl;
    ip_v4_h->ip_p = ip_proto;
    ip_pton(src_pattern->ip_addr, &ip_v4_h->ip_src);
    ip_pton(dst_pattern->ip_addr, &ip_v4_h->ip_dst);
  } else {
    /* Build IP header (IPv6) */
    ip_pkt_len = sizeof(ip_v6_h_t) + data_len;
    ip_v6_h = (ip_v6_h_t*) ip_pkt;
    ip_v6_h->ip6_ctlun.ip6_un2_vfc = IP6_VERSION;
    ip_v6_h->ip6_ctlun.ip6_un1.ip6_un1_plen =
      ip_pkt_len - sizeof(ip_v6_h_t);
    ip_v6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt = ip_proto;
    ip_v6_h->ip6_ctlun.ip6_un1.ip6_un1_hlim = ip_ttl;
    ip6_pton(src_pattern->ip_addr, &ip_v6_h->ip6_src);
    ip6_pton(dst_pattern->ip_addr, &ip_v6_h->ip6_dst);
  }
  /* Add data */
  if (data_len > 0) {
    if (src_pattern->ip_v == HY_AD_T_IP_V4) {
      memcpy(
        ip_pkt + sizeof(ip_v4_h_t),
        data,
        data_len);
    } else {
      memcpy(
        ip_pkt + sizeof(ip_v6_h_t),
        data,
        data_len);
    }
  }
  /* Calculate the checksums */
  if (src_pattern->ip_v == HY_AD_T_IP_V4) {
    ip_checksum(ip_v4_h, ip_pkt_len);
  } else {
    ip6_checksum(ip_v6_h, ip_pkt_len);
  }
  /* Wrap Ethernet-Layer */
  return hy_build_eth_packet(
           src_pattern,
           dst_pattern,
           ip_v_assumption,
           packet,
           packet_len,
           ip_pkt,
           ip_pkt_len,
           ETH_TYPE_IP);
} /* hy_build_ip_packet */

/* -------------------------------------------------------------------------- */
