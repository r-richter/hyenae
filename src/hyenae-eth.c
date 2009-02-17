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

#include "hyenae-eth.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_eth_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned char* data,
      int data_len,
      unsigned int eth_type
    ) {

  /*
   * USAGE:
   *   Builds an Ethernet packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  eth_h_t* eth_h = NULL;

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
  if (strlen(src_pattern->hw_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_SRC;
  }
  if (strlen(dst_pattern->hw_addr) == 0) {
    return HY_ER_WRONG_PT_FMT_DST;
  }
  *packet_len = sizeof(eth_h_t) + data_len;
  *packet = malloc(*packet_len);
  memset(*packet, 0, *packet_len);
  /* Build Ethernet header */
  eth_h = (eth_h_t*) *packet;
  eth_pton(dst_pattern->hw_addr, &eth_h->eth_dst);
  eth_pton(src_pattern->hw_addr, &eth_h->eth_src);
  eth_h->eth_type = htons(eth_type);
  /* Add data */
  if (data_len > 0) {
    memcpy(
      *packet + sizeof(eth_h_t),
      data,
      data_len);
  }
  return HY_ER_OK;
} /* hy_build_eth_packet */

/* -------------------------------------------------------------------------- */
