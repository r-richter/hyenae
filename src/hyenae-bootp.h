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

#ifndef HYENAE_BOOTP_H
  #define HYENAE_BOOTP_H

#include "hyenae-base.h"
#include "hyenae-patterns.h"
#include "hyenae-attack.h"

/* BOOTP Op-Codes */
#define HY_BOOTP_OP_BOOTREQUEST 1
#define HY_BOOTP_OP_BOOTREPLY   2

/* BOOTP hardware types */
#define HY_HTYPE_ETHERNET 1

/* BOOTP port definitions */
#define HY_BOOTP_PORT_SERVER 67
#define HY_BOOTP_PORT_CLIENT 68

/* -------------------------------------------------------------------------- */

typedef
  struct hy_bootp_h {

  /*
   * USAGE:
   *   Represents a BOOTP header.
   */

  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  ip_addr_t ciaddr;
  ip_addr_t yiaddr;
  ip_addr_t siaddr;
  ip_addr_t giaddr;
  eth_addr_t chaddr;
  uint8_t zero[16 - ETH_ADDR_LEN];
  uint8_t sname[64];
  uint8_t file[128];

} hy_bootp_h_t;

/* -------------------------------------------------------------------------- */

int
  hy_build_bootp_request_packet
    (
      hy_pattern_t*,
      hy_pattern_t*,
      int,
      unsigned char**,
      int*,
      unsigned char**,
      int*,
      unsigned int,
      unsigned int
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_BOOTP_H */
