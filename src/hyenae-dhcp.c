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

#include "hyenae-dhcp.h"

/* -------------------------------------------------------------------------- */

unsigned char*
  hy_set_dhcp_option
    (
      unsigned char* option,
      unsigned char optcode,
      unsigned char optlen,
      void* optval
    ) {

  /*
   * USAGE:
   *   Sets a DHCP option and returns the end
   *   pointer for future write operations.
   */

  int i = 0;

  *option = optcode;
  *(option + 1) = optlen;
  option = option + 2;
  while (i < optlen) {
    *(option + i) = *((unsigned char*) (optval + i));
    i = i + 1;
  }
  *(option + i) = HY_DHCP_OPT_END;
  return option + i;
} /* hy_set_dhcp_option */

/* -------------------------------------------------------------------------- */

int
  hy_build_dhcp_request_packet
    (
      hy_pattern_t* src_pattern,
      hy_pattern_t* dst_pattern,
      hy_pattern_t* ip_request_pattern,
      int ip_v_assumption,
      unsigned char** packet,
      int* packet_len,
      unsigned int ip_ttl,
      unsigned int dhcp_msg
    ) {

  /*
   * USAGE:
   *   Builds a DHCP-Request packet based
   *   on the given arguments.
   */

  int ret = HY_ER_OK;
  int dhcp_pkt_len =
    sizeof(hy_dhcp_h_t) +
    512 /* Variable DHCP option length */;
  int dhcp_opt_len = 0;
  unsigned char dhcp_pkt[dhcp_pkt_len];
  unsigned char* opt_ptr = NULL;
  unsigned char opt_val[255];
  hy_dhcp_h_t* dhcp_h = NULL;

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
  if (dhcp_msg != HY_DHCP_MSG_DISCOVER) {
    if (strlen(ip_request_pattern->src) > 0) {
      /* Ensure that when the user passes "%",
         the pattern is recongnized as an
         IP-Address */
      if (strcmp(ip_request_pattern->src, "%") == 0) {
        strncpy(
          ip_request_pattern->src,
          "%-%",
          HY_PT_BUFLEN);
      }
      if ((ret =
             hy_parse_pattern(
               ip_request_pattern,
               ip_v_assumption)) != HY_ER_OK) {
          return ret;
      }
    }
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
  if (dhcp_msg != HY_DHCP_MSG_DISCOVER) {
    if (strlen(ip_request_pattern->src) > 0) {
      if (strlen(ip_request_pattern->ip_addr) == 0) {
        return HY_ER_WRONG_PT_FMT_IP_REQ;
      }
    }
  }
  if (src_pattern->ip_v != dst_pattern->ip_v ||
      (dhcp_msg != HY_DHCP_MSG_DISCOVER &&
       (strlen(ip_request_pattern->src) > 0 &&
        src_pattern->ip_v != ip_request_pattern->ip_v))) {
    return HY_ER_MULTIPLE_IP_V;
  }
  if (src_pattern->ip_v != HY_AD_T_IP_V4) {
    return HY_ER_WRONG_IP_V;
  }
  memset(dhcp_pkt, 0, dhcp_pkt_len);
  /* Build DHCP header */
  dhcp_h = (hy_dhcp_h_t*) dhcp_pkt;
  dhcp_h->cookie = htonl(HY_DHCP_COOKIE);
  /* Set option pointer */
  opt_ptr = dhcp_h->options;
  /* DHCP-Message type */
  memset(opt_val, 0, 255);
  *opt_val = dhcp_msg;
  opt_ptr =
    hy_set_dhcp_option(
      opt_ptr,
      HY_DHCP_OPT_DHCPMSGTYPE,
      1,
      opt_val);
  dhcp_opt_len = dhcp_opt_len + 2 + 1;
  if (dhcp_msg != HY_DHCP_MSG_DISCOVER) {
    /* Parameter request list */
    memset(opt_val, 0, 255);
    *opt_val = HY_DHCP_OPT_NETMASK;
    *(opt_val + 1) = HY_DHCP_OPT_ROUTERS;
    *(opt_val + 2) = HY_DHCP_OPT_DNSSERVERS;
    *(opt_val + 3) = HY_DHCP_OPT_DOMAINNAME;
    opt_ptr =
      hy_set_dhcp_option(
        opt_ptr,
        HY_DHCP_OPT_PARAMREQLIST,
        4,
        opt_val);
    dhcp_opt_len = dhcp_opt_len + 2 + 4;
    /* Client identifier */
    memset(opt_val, 0, 255);
    *opt_val = HY_HTYPE_ETHERNET;
    eth_pton(src_pattern->hw_addr, (eth_addr_t*) (opt_val + 1));
    opt_ptr =
      hy_set_dhcp_option(
        opt_ptr,
        HY_DHCP_OPT_CLIENT_IDENT,
        1 + ETH_ADDR_LEN,
        opt_val);
    dhcp_opt_len = dhcp_opt_len + 2 + 1 + ETH_ADDR_LEN;
    /* Requested IP-Address */
    if (strlen(ip_request_pattern->src) > 0) {
      memset(opt_val, 0, 255);
      ip_pton(ip_request_pattern->ip_addr, (ip_addr_t*) opt_val);
      opt_ptr =
        hy_set_dhcp_option(
          opt_ptr,
          HY_DHCP_OPT_REQUESTEDIP,
          4,
          opt_val);
      dhcp_opt_len = dhcp_opt_len + 2 + 4;
    }
  }
  /* Set DHCP end option */
  memset(opt_val, 0, 255);
  opt_ptr =
    hy_set_dhcp_option(
      opt_ptr,
      HY_DHCP_OPT_END,
      1,
      opt_val);
  dhcp_opt_len = dhcp_opt_len + 1;
  /* Wrap BOOTP-Layer */
  return hy_build_bootp_packet(
            src_pattern,
            dst_pattern,
            ip_v_assumption,
            packet,
            packet_len,
            dhcp_pkt,
            sizeof(hy_dhcp_h_t) + dhcp_opt_len,
            ip_ttl,
            HY_BOOTP_OP_BOOTREQUEST);
} /* hy_build_dhcp_request_packet */

/* -------------------------------------------------------------------------- */
