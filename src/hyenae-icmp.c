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

#include "hyenae-icmp.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_icmp_echo_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned char* data,
      int data_len,
      unsigned int ip_ttl
    ) {

  /*
   * USAGE:
   *   Builds an ICMP-Echo packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  eth_h_t* eth_h = NULL;
  ip_v4_h_t* ip_v4_h = NULL;
  icmp_h_t* icmp_h = NULL;
  icmp_echo_t* icmp_echo = NULL;

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
  if (src_pattern->ip_v != HY_AD_T_IP_V4) {
    return HY_ER_WRONG_IP_V;
  }
  if (*packet == NULL) {
    *packet_len =
      sizeof(eth_h_t) +
      sizeof(icmp_h_t) +
      sizeof(icmp_echo_t) +
      data_len;
    *packet_len = *packet_len + sizeof(ip_v4_h_t);
    *packet = malloc(*packet_len);
  }
  memset(*packet, 0, *packet_len);
  eth_h = (eth_h_t*) *packet;
  ip_v4_h = (ip_v4_h_t*) (*packet + sizeof(eth_h_t));
  icmp_h = (icmp_h_t*)
    (*packet + sizeof(eth_h_t) + sizeof(ip_v4_h_t));
  icmp_echo = (icmp_echo_t*)
    (*packet +
      sizeof(eth_h_t) +
      sizeof(ip_v4_h_t) +
      sizeof(icmp_echo_t));
  /* Build Ethernet header */
  eth_pton(dst_pattern->hw_addr, &eth_h->eth_dst);
  eth_pton(src_pattern->hw_addr, &eth_h->eth_src);
  eth_h->eth_type = htons(ETH_TYPE_IP);
  /* Build IP header (IPv4) */
  ip_v4_h->ip_v = 4;
  ip_v4_h->ip_hl = 5;
  ip_v4_h->ip_len = htons(*packet_len - sizeof(eth_h_t));
  ip_v4_h->ip_id = htons(hy_random(10000, 32000));
  ip_v4_h->ip_ttl = ip_ttl;
  ip_v4_h->ip_p = IP_PROTO_ICMP;
  ip_pton(src_pattern->ip_addr, &ip_v4_h->ip_src);
  ip_pton(dst_pattern->ip_addr, &ip_v4_h->ip_dst);
  /* Build ICMP header */
  icmp_h->icmp_type = ICMP_ECHO;
  /* Build ICMP echo block */
  icmp_echo->icmp_id = htons(hy_random(1, 200));
  icmp_echo->icmp_seq = htons(hy_random(1, 200));
  /* Add data */
  if (data_len > 0) {
    memcpy(
      *packet + (*packet_len - data_len),
      data,
      data_len);
  }
  /* Calculate the checksums */
  ip_checksum(ip_v4_h, *packet_len - sizeof(eth_h_t));
  return HY_ER_OK;
} /* hy_build_icmp_echo_packet */

/* -------------------------------------------------------------------------- */
