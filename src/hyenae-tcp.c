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

#include "hyenae-tcp.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_tcp_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned char* data,
      int data_len,
      unsigned int ip_ttl,
      unsigned int tcp_flags,
      unsigned int tcp_seq_number,
      unsigned int tcp_ack_number,
      unsigned int tcp_window
    ) {

  /*
   * USAGE:
   *   Builds a TCP packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int tcp_pkt_len =
    sizeof(tcp_h_t) +
    data_len;
  unsigned char tcp_pkt[tcp_pkt_len];
  tcp_h_t* tcp_h = NULL;

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
  if (tcp_flags == 0) {
    return HY_ER_NO_TCP_FLAGS;
  }
  memset(tcp_pkt, 0, tcp_pkt_len);
  /* Build TCP header */
  tcp_h = (tcp_h_t*) tcp_pkt;
  tcp_h->th_sport = htons(src_pattern->port);
  tcp_h->th_dport = htons(dst_pattern->port);
  tcp_h->th_seq = htonl(tcp_seq_number);
  tcp_h->th_ack = htonl(tcp_ack_number);
  tcp_h->th_off = 5;
  tcp_h->th_flags = tcp_flags;
  tcp_h->th_win = htons(tcp_window);
  /* Add data */
  if (data_len > 0) {
    memcpy(
      tcp_pkt + sizeof(tcp_h_t),
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
            tcp_pkt,
            tcp_pkt_len,
            IP_PROTO_TCP,
            ip_ttl);
} /* hy_build_tcp_packet */

/* -------------------------------------------------------------------------- */
