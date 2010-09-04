/*
 * Hyenae
 *   Advanced Network Packet Generator
 *
 * Copyright (C) 2009 - 2010 Robin Richter
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

#include "hyenae-udp.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_udp_packet
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
   *   Builds an UDP packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int udp_pkt_len =
    sizeof(udp_h_t) +
    data_len;
  unsigned char udp_pkt[udp_pkt_len];
  udp_h_t* udp_h = NULL;

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
  if (strlen(src_pattern->hw_addr) == 0 ||
      strlen(src_pattern->ip_addr) == 0 ||
      src_pattern->port == 0) {
    return HY_ER_WRONG_PT_FMT_SRC;
  }
  if (strlen(dst_pattern->hw_addr) == 0 ||
      strlen(dst_pattern->ip_addr) == 0 ||
      dst_pattern->port == 0) {
    return HY_ER_WRONG_PT_FMT_DST;
  }
  if (src_pattern->ip_v != dst_pattern->ip_v) {
    return HY_ER_MULTIPLE_IP_V;
  }
  memset(udp_pkt, 0, udp_pkt_len);
  /* Build UDP header */
  udp_h = (udp_h_t*) udp_pkt;
  udp_h->uh_sport = htons(src_pattern->port);
  udp_h->uh_dport = htons(dst_pattern->port);
  udp_h->uh_ulen = htons(sizeof(udp_h_t) + data_len);
  /* Add data */
  if (data_len > 0) {
    memcpy(
      udp_pkt + sizeof(udp_h_t),
      data,
      data_len);
  }
  /* Wrap IP-Layer */
  return hy_build_ip_packet(
            src_pattern,
            dst_pattern,
            ip_v_assumption,
            packet,
            packet_len,
            udp_pkt,
            udp_pkt_len,
            IP_PROTO_UDP,
            ip_ttl);
} /* hy_build_udp_packet */

/* -------------------------------------------------------------------------- */
