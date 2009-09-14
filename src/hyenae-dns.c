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

#include "hyenae-dns.h"

/* -------------------------------------------------------------------------- */

  int
    hy_encode_domain_name
    (
      const char* name,
      char** enc_name,
      int* len
    ) {

  /*
   * USAGE:
   *   Encodes the given domain name.
   */

  int i = 0;
  int enc_n_i = 0;
  int s_len = 0;
  int s_cnt = 0;

  *len = strlen(name) + 1;
  *enc_name = malloc(*len);
  memset(*enc_name, 0, *len);
  while (1) {
    if (i + 1 == *len ||
        *(name + i) == DNS_N_SC) {
      if (*(name + i) == DNS_N_SC) {
        s_cnt = s_cnt + 1;
      }
      *(*enc_name + enc_n_i) = s_len;
      enc_n_i = enc_n_i + 1;
      strncpy(*enc_name + enc_n_i, name + i - s_len, s_len);
      enc_n_i = enc_n_i + s_len;
      s_len = 0;
      i = i + 1;
    }
    if (i < *len) {
      i = i + 1;
      s_len = s_len + 1;
    } else {
      break;
    }
  }
  return HY_ER_OK;
} /* hy_encode_dns_name */

/* -------------------------------------------------------------------------- */

int
  hy_dns_parse_add_queries
    (
      unsigned char* packet,
      int* packet_len,
      const char* queries,
      int* query_count,
      int ip_v_asm
    ) {

  /*
   * USAGE:
   *   Parses a string of DNS-Queries
   *   and adds them to the given DNS-Packet.
   */

  int ret = HY_ER_OK;
  int i = 0;
  int tmp_len = 0;
  int qry_len = 0;
  int enc_n_len = 0;
  uint16_t* type = NULL;
  uint16_t* class = NULL;
  char tmp[HY_DNS_N_BUFLEN];
  char* enc_n = NULL;

  qry_len = strlen(queries);
  if (qry_len > HY_DNS_QRY_BUFLEN) {
    return HY_ER_DNS_QRY_BUFLEN_EXCEED;
  }
  memset(tmp, 0, HY_DNS_N_BUFLEN);
  tmp_len = 0;
  while (1) {
    if (i == qry_len ||
        *(queries + i) == HY_DNS_QA_SC) {
      /* Add DNS-Query to packet */
      if ((ret =
             hy_encode_domain_name(
               tmp, &enc_n, &enc_n_len)) != HY_ER_OK) {
        return ret;
      }
      memcpy(packet + *packet_len, enc_n, enc_n_len);
      free(enc_n);
      *packet_len = *packet_len + enc_n_len + 1;
      type = (uint16_t*) (packet + *packet_len);
      class = (uint16_t*) (packet + *packet_len + 2);
      if (ip_v_asm == HY_AD_T_IP_V4) {
        *type = htons(1);
      } else {
        *type = htons(28);
      }
      *class = htons(1);
      *packet_len = *packet_len + 4;
      *query_count = *query_count + 1;
      memset(tmp, 0, HY_DNS_N_BUFLEN);
      tmp_len = 0;
    } else {
      *(tmp + tmp_len) = *(queries + i);
      if ((tmp_len + 1) > HY_DNS_N_BUFLEN) {
        return HY_ER_DNS_QRY_N_BUFLEN_EXCEED;
      }
      tmp_len = tmp_len + 1;
    }
    if (i < qry_len) {
      i = i + 1;
    } else {
      break;
    }
  }
  return ret;
} /* hy_dns_parse_add_queries */

/* -------------------------------------------------------------------------- */

int
  hy_build_dns_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned int ip_ttl,
      const char* dns_queries
    ) {

  /*
   * USAGE:
   *   Builds a DNS packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int dns_pkt_len =
    sizeof(hy_dns_h_t);
  int qry_cnt = 0;
  unsigned char dns_pkt[HY_DNS_PACKET_BUFLEN];
  hy_dns_h_t* dns_h = NULL;
  hy_pattern_t src_pat;
  hy_pattern_t dst_pat;

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
  /* Overwrite ports with DNS
     default ports */
  memset(&src_pat, 0, sizeof(hy_pattern_t));
  memset(&dst_pat, 0, sizeof(hy_pattern_t));
  memcpy(&src_pat, src_pattern, sizeof(hy_pattern_t));
  memcpy(&dst_pat, dst_pattern, sizeof(hy_pattern_t));
  sprintf(
    src_pat.src,
    "%s-%s@%i",
    src_pattern->hw_addr,
    src_pattern->ip_addr,
    hy_random(1023, 6000));
  sprintf(
    dst_pat.src,
    "%s-%s@%i",
    dst_pattern->hw_addr,
    dst_pattern->ip_addr,
    HY_DNS_PORT);
  /* Validate pattern format */
  if (strlen(src_pat.hw_addr) == 0 ||
      strlen(src_pat.ip_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_SRC;
  }
  if (strlen(dst_pat.hw_addr) == 0 ||
      strlen(dst_pat.ip_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_DST;
  }
  if (src_pat.ip_v != dst_pattern->ip_v) {
    return HY_ER_MULTIPLE_IP_V;
  }
  /* Validate parameters */
  if (dns_queries == NULL ||
      strlen(dns_queries) == 0) {
    return HY_ER_DNS_NO_QUERIES;
  }
  memset(dns_pkt, 0, HY_DNS_PACKET_BUFLEN);
  /* Build DNS header */
  dns_h = (hy_dns_h_t*) dns_pkt;
  dns_h->flags = 1;
  dns_h->id = htons(hy_random(1, 65000));
  if ((ret =
         hy_dns_parse_add_queries(
           dns_pkt,
           &dns_pkt_len,
           dns_queries,
           &qry_cnt,
           ip_v_assumption)) != HY_ER_OK) {
    return ret;
  }
  dns_h->qdcount = htons(qry_cnt);
  dns_h->nscount = htons(0);
  /* Wrap IP-Layer */
  ret = hy_build_udp_packet(
          &src_pat,
          &dst_pat,
          ip_v_assumption,
          packet,
          packet_len,
          dns_pkt,
          dns_pkt_len,
          ip_ttl);
  return ret;
} /* hy_build_dns_packet */

/* -------------------------------------------------------------------------- */
