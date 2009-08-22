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

  void
    hy_encode_domain_name
    (
      unsigned char* name,
      unsigned char** enc_name,
      int* len
    ) {

  /*
   * USAGE:
   *   Encodes the given domain name.
   */

  int i = 0;
  int enc_n_i = 0;
  int s_len = 0;

  *len = strlen(name) + 2;
  *enc_name = malloc(*len);
  memset(*enc_name, 0, *len);
  while (1) {
    if (i + 1 == *len ||
        *(name + i) == DNS_N_SC) {
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

  int i = 0;
  int tmp_len = 0;
  int qry_len = 0;
  int enc_n_len = 0;
  uint16_t* type = NULL;
  uint16_t* class = NULL;
  char tmp[HY_DNS_N_BUFLEN];
  unsigned char* enc_n = NULL;
  
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
      hy_encode_domain_name(tmp, &enc_n, &enc_n_len);
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
  return HY_ER_OK;
} /* hy_dns_parse_add_queries */

/* -------------------------------------------------------------------------- */

int
  hy_dns_parse_add_answers
    (
      unsigned char* packet,
      int* packet_len,
      const char* answers,
      int* answer_count,
      int ip_v_asm
    ) {

  /*
   * USAGE:
   *   Parses a string of DNS-Answers
   *   and adds them to the given DNS-Packet.
   */

  int ret = HY_ER_OK;
  int i = 0;
  int tmp_len = 0;
  int dns_n_len = 0;
  int ans_len = 0;
  int enc_n_len = 0;
  uint16_t* type = NULL;
  uint16_t* class = NULL;
  uint32_t* ttl = NULL;
  uint16_t* data_len = NULL;
  char tmp[HY_DNS_ANS_PT_BUFLEN];
  char dns_n[HY_DNS_N_BUFLEN];
  unsigned char* enc_n = NULL;
  ip_addr_t* ip_addr = NULL;
  ip6_addr_t* ip6_addr = NULL;
  hy_pattern_t ver_pat;

  ans_len = strlen(answers);
  if (ans_len > HY_DNS_ANS_BUFLEN) {
    return HY_ER_DNS_ANS_BUFLEN_EXCEED;
  }
  memset(tmp, 0, HY_DNS_ANS_PT_BUFLEN);
  tmp_len = 0;
  while (1) {
    if (i == ans_len ||
        *(answers + i) == HY_DNS_QA_SC) {
      while (dns_n_len < tmp_len) {
        if (*(tmp + dns_n_len) == HY_DNS_A_NA_SC) {
          break;
        }
        if (dns_n_len > HY_DNS_N_BUFLEN) {
          return HY_ER_DNS_ANS_N_BUFLEN_EXCEED;
        }
        dns_n_len = dns_n_len + 1;
      }
      /* Verify answer pattern */
      if (dns_n_len < 1 ||
          dns_n_len == tmp_len) {
        return HY_ER_DNS_ANS_FMT_ERROR;
      }
      *(ver_pat.src) = HY_PT_WCC;
      *(ver_pat.src + 1) = HY_PT_EOA_HW;
      strncpy(
        ver_pat.src + 2, (tmp + dns_n_len + 1), HY_PT_BUFLEN);
      if ((ret =
             hy_parse_pattern(
              &ver_pat, ip_v_asm)) != HY_ER_OK) {
        return ret;
      }
      /* Add DNS-Answer to packet */
      memset(dns_n, 0, HY_DNS_N_BUFLEN);
      strncpy(dns_n, tmp, dns_n_len);
      hy_encode_domain_name(dns_n, &enc_n, &enc_n_len);
      memcpy(packet + *packet_len, enc_n, enc_n_len);
      free(enc_n);
      *packet_len = *packet_len + enc_n_len + 1;
      type = (uint16_t*) (packet + *packet_len);
      class = (uint16_t*) (packet + *packet_len + 2);
      ttl = (uint32_t*) (packet + *packet_len + 4);
      data_len = (uint16_t*) (packet + *packet_len + 9);
      ip_addr = (ip_addr_t*) (packet + *packet_len + 10);
      ip6_addr = (ip6_addr_t*) (packet + *packet_len + 10);
      if (ip_v_asm == HY_AD_T_IP_V4) {
        *type = htons(1);
      } else {
        *type = htons(28);
      }
      *class = htons(1);
      *ttl = htons(hy_random(1, 24));
      *data_len = 4;
      *packet_len = *packet_len + 10;
      if (ip_v_asm == HY_AD_T_IP_V4) {
        ip_pton(ver_pat.ip_addr, ip_addr);
        *packet_len = *packet_len + sizeof(ip_addr_t);
      } else {
        ip6_pton(ver_pat.ip_addr, ip6_addr);
        *packet_len = *packet_len + sizeof(ip6_addr_t);
      }
      *answer_count = *answer_count + 1;
      memset(tmp, 0, HY_DNS_ANS_PT_BUFLEN);
      tmp_len = 0;
    } else {
      *(tmp + tmp_len) = *(answers + i);
      if ((tmp_len + 1) > (HY_DNS_ANS_PT_BUFLEN - 2)) {
        return HY_ER_DNS_ANS_PT_BUFLEN_EXCEED;
      }
      tmp_len = tmp_len + 1;
    }
    if (i < ans_len) {
      i = i + 1;
    } else {
      break;
    }
  }
  return ret;
} /* hy_dns_parse_add_answers */

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
      const char* dns_queries,
      const char* dns_answers
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
  int ans_cnt = 0;
  unsigned char dns_pkt[HY_DNS_PACKET_BUFLEN];
  hy_dns_h_t* dns_h = NULL;

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
  memset(src_pattern->src, 0, HY_PT_BUFLEN);
  memset(dst_pattern->src, 0, HY_PT_BUFLEN);
  sprintf(
    src_pattern->src,
    "%s-%s@%i",
    src_pattern->hw_addr,
    src_pattern->ip_addr,
    HY_DNS_PORT);
  sprintf(
    dst_pattern->src,
    "%s-%s@%i",
    dst_pattern->hw_addr,
    dst_pattern->ip_addr,
    HY_DNS_PORT);
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
  /* Validate parameters */
  if (dns_queries == NULL ||
      strlen(dns_queries) == 0) {
    return HY_ER_DNS_NO_QUERIES;
  }
  if (dns_answers != NULL &&
      strlen(dns_answers) == 0) {
    return HY_ER_DNS_NO_ANSWERS;
  }
  memset(dns_pkt, 0, HY_DNS_PACKET_BUFLEN);
  /* Build DNS header */
  dns_h = (hy_dns_h_t*) dns_pkt;
  dns_h->id = htons(hy_random(1, 65000));
  if (dns_answers != NULL) {
    dns_h->flags1 = HY_DNS_FLAG1_RESPONSE;
  }
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
  if (dns_answers != NULL) {
    if ((ret =
           hy_dns_parse_add_answers(
             dns_pkt,
             &dns_pkt_len,
             dns_answers,
             &ans_cnt,
             ip_v_assumption)) != HY_ER_OK) {
      return ret;
    }
    dns_h->ancount = htons(ans_cnt);
  }
  dns_h->nscount = htons(0);
  dns_h->arcount = htons(0);
  /* Wrap IP-Layer */
  ret = hy_build_udp_packet(
          src_pattern,
          dst_pattern,
          ip_v_assumption,
          packet,
          packet_len,
          dns_pkt,
          dns_pkt_len,
          ip_ttl);
  return ret;
} /* hy_build_dns_packet */

/* -------------------------------------------------------------------------- */
