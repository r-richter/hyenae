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

#include "hyenae-arp.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_arp_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      hy_pattern_t* snd_pattern,
      hy_pattern_t* trg_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      int opcode
    ) {

  /*
   * USAGE:
   *   Builds an ARP-Reply packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  eth_h_t* eth_h = NULL;
  arp_h_t* arp_h = NULL;
  arp_eth_ip_t* arp_eth_ip = NULL;
  addr_t addr;
  if ((ret =
         hy_parse_pattern(
           src_pattern,
           ip_v_assumption)) != HY_ER_OK ||
      (ret =
         hy_parse_pattern(
           dst_pattern,
           ip_v_assumption)) != HY_ER_OK ||
      (ret =
        hy_parse_pattern(
          snd_pattern,
          ip_v_assumption)) != HY_ER_OK ||
      (ret =
        hy_parse_pattern(
          trg_pattern,
          ip_v_assumption)) != HY_ER_OK) {
      return ret;
  }
  if (strlen(src_pattern->hw_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_SRC;
  }
  if (strlen(dst_pattern->hw_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_DST;
  }
  if (strlen(snd_pattern->hw_addr) == 0 ||
      strlen(snd_pattern->ip_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_SND;
  }
  if (strlen(trg_pattern->hw_addr) == 0 ||
      strlen(trg_pattern->ip_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_TRG;
  }
  if (snd_pattern->ip_v != trg_pattern->ip_v) {
    return HY_ER_MULTIPLE_IP_V;
  }
  if (snd_pattern->ip_v != HY_AD_T_IP_V4) {
    return HY_ER_WRONG_IP_V;
  }
  if (*packet == NULL) {
    *packet_len =
      sizeof(eth_h_t) +
      sizeof(arp_h_t) +
      sizeof(arp_eth_ip_t);
    *packet = malloc(*packet_len);
  }
  memset(*packet, 0, *packet_len);
  eth_h = (eth_h_t*) *packet;
  arp_h = (arp_h_t*) (*packet + sizeof(eth_h_t));
  arp_eth_ip =
    (arp_eth_ip_t*)
      (*packet + sizeof(eth_h_t) + sizeof(arp_h_t));
  /* Build Ethernet header */
  eth_pton(dst_pattern->hw_addr, &eth_h->eth_dst);
  eth_pton(src_pattern->hw_addr, &eth_h->eth_src);
  eth_h->eth_type = htons(ETH_TYPE_ARP);
  /* Build ARP header */
  arp_h->ar_hrd = htons(ARP_HRD_ETH);
  arp_h->ar_pro = htons(ARP_PRO_IP);
  arp_h->ar_hln = ETH_ADDR_LEN;
  arp_h->ar_pln = IP_ADDR_LEN;
  arp_h->ar_op = htons(opcode);
  /* Build ARP-Repy block */
  eth_pton(
    snd_pattern->hw_addr,
    (eth_addr_t*) &arp_eth_ip->ar_sha);
  addr_pton(snd_pattern->ip_addr, &addr);
  memcpy(
    &arp_eth_ip->ar_spa,
    &addr.__addr_u.__ip,
    IP_ADDR_LEN);
  eth_pton(
    trg_pattern->hw_addr,
    (eth_addr_t*) &arp_eth_ip->ar_tha);
  addr_pton(trg_pattern->ip_addr, &addr);
  memcpy(
    &arp_eth_ip->ar_tpa,
    &addr.__addr_u.__ip,
    IP_ADDR_LEN);
  return HY_ER_OK;
} /* hy_build_arp_reply_packet */

/* -------------------------------------------------------------------------- */
