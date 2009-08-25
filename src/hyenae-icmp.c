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
  int icmp_echo_pkt_len =
    sizeof(icmp_h_t) +
    sizeof(icmp_echo_t) +
    data_len;
  unsigned char icmp_echo_pkt[icmp_echo_pkt_len];
  icmp_h_t* icmp_h = NULL;
  icmp_echo_t* icmp_echo = NULL;

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
  memset(icmp_echo_pkt, 0, icmp_echo_pkt_len);
  /* Build ICMP header */
  icmp_h = (icmp_h_t*) icmp_echo_pkt;
  if (src_pattern->ip_v == HY_AD_T_IP_V4) {
    icmp_h->icmp_type = ICMP_ECHO;
  } else {
    icmp_h->icmp_type = HY_ICMP_V6_TYPE_ECHO;
  }
  /* Build ICMP-Echo block */
  icmp_echo = (icmp_echo_t*) (icmp_echo_pkt + sizeof(icmp_h_t));
  icmp_echo->icmp_id = htons(hy_random(1, 200));
  icmp_echo->icmp_seq = htons(hy_random(1, 200));
  /* Add data */
  if (data_len > 0) {
    memcpy(
      icmp_echo_pkt +
      sizeof(icmp_h_t) +
      sizeof(icmp_echo_t),
      data,
      data_len);
  }
  /* Wrap IP layer */
  if (src_pattern->ip_v == HY_AD_T_IP_V4) {
    return hy_build_ip_packet(
              src_pattern,
              dst_pattern,
              ip_v_assumption,
              packet,
              packet_len,
              icmp_echo_pkt,
              icmp_echo_pkt_len,
              IP_PROTO_ICMP,
              ip_ttl);
  } else {
    return hy_build_ip_packet(
              src_pattern,
              dst_pattern,
              ip_v_assumption,
              packet,
              packet_len,
              icmp_echo_pkt,
              icmp_echo_pkt_len,
              IP_PROTO_ICMPV6,
              ip_ttl);
  }
} /* hy_build_icmp_echo_packet */

/* -------------------------------------------------------------------------- */

int
  hy_build_icmp_unreach_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned char* data,
      int data_len,
      unsigned int ip_proto,
      unsigned int ip_ttl,
      unsigned int icmp_unr_code
    ) {

  /*
   * USAGE:
   *   Builds an ICMP "Destination
   *   Unreachable" packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int icmp_unr_pkt_len =
    sizeof(icmp_h_t) +
    sizeof(icmp_unreach_t) +
    sizeof(ip_v4_h_t) + 8;
  unsigned char icmp_unr_pkt[icmp_unr_pkt_len];
  unsigned char proto_buf[1024];
  icmp_h_t* icmp_h = NULL;
  icmp_unreach_t* icmp_unr = NULL;

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
  memset(icmp_unr_pkt, 0, icmp_unr_pkt_len);
  /* Build ICMP header */
  icmp_h = (icmp_h_t*) icmp_unr_pkt;
  icmp_h->icmp_type = ICMP_UNREACH;
  icmp_h->icmp_code = icmp_unr_code;
  /* Build ICMP "Destination Unreachable" block */
  icmp_unr = (icmp_unreach_t*)
    (icmp_unr_pkt + sizeof(icmp_h_t));
  memcpy(
    icmp_unr->icmp_ip,
    data, sizeof(ip_v4_h_t) + 8);
  /* Wrap IP layer */
  return hy_build_ip_packet(
            src_pattern,
            dst_pattern,
            ip_v_assumption,
            packet,
            packet_len,
            icmp_unr_pkt,
            icmp_unr_pkt_len,
            IP_PROTO_ICMP,
            ip_ttl);
} /* hy_build_icmp_unreach_packet */

/* -------------------------------------------------------------------------- */
