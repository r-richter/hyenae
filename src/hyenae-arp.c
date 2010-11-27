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
      unsigned int opcode
    ) {

  /*
   * USAGE:
   *   Builds an ARP packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int arp_pkt_len =
    sizeof(arp_h_t) +
    sizeof(arp_eth_ip_t);
  if (opcode == ARP_OP_REPLY) {
    /* Padding bytes to reach at least
       60 Bytes on ARP-Replys*/
    arp_pkt_len = arp_pkt_len + 18;
  }
  int src_hw_len = 0;
  int snd_hw_len = 0;
  unsigned char arp_pkt[arp_pkt_len];
  arp_h_t* arp_h = NULL;
  arp_eth_ip_t* arp_eth_ip = NULL;
  addr_t addr;

   /* Parse address patterns */
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
  /* Validate pattern format */
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
  /* If source and sender HW-Address strip
     is completely random, make shure they're
     equally randomized */
  if (strchr(src_pattern->src, HY_PT_EOA_HW) != NULL) {
    src_hw_len =
      strchr(src_pattern->src, HY_PT_EOA_HW) -
      src_pattern->src;
  } else {
    src_hw_len = strlen(src_pattern->src);
  }
  if (strchr(snd_pattern->src, HY_PT_EOA_HW) != NULL) {
    snd_hw_len =
      strchr(snd_pattern->src, HY_PT_EOA_HW) -
      snd_pattern->src;
  } else {
    snd_hw_len = strlen(snd_pattern->src);
  }
  if (src_hw_len == snd_hw_len &&
      strncmp(
        src_pattern->src,
        snd_pattern->src,
        src_hw_len) == 0) {
    strncpy(
      src_pattern->src,
      snd_pattern->hw_addr,
      HY_AD_BUFLEN);
  }
  memset(arp_pkt, 0, arp_pkt_len);
  /* Build ARP header */
  arp_h = (arp_h_t*) arp_pkt;
  arp_h->ar_hrd = htons(ARP_HRD_ETH);
  arp_h->ar_pro = htons(ARP_PRO_IP);
  arp_h->ar_hln = ETH_ADDR_LEN;
  arp_h->ar_pln = IP_ADDR_LEN;
  arp_h->ar_op = htons(opcode);
  /* Build ARP Data-Blockk */
  arp_eth_ip = (arp_eth_ip_t*) (arp_pkt + sizeof(arp_h_t));
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
  /* Wrap Ethernet-Layer */
  return hy_build_eth_packet(
           src_pattern,
           dst_pattern,
           ip_v_assumption,
           packet,
           packet_len,
           arp_pkt,
           arp_pkt_len,
           ETH_TYPE_ARP);
} /* hy_build_arp_packet */

/* -------------------------------------------------------------------------- */
