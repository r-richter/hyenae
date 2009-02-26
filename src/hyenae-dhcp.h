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

#ifndef HYENAE_DHCP_H
  #define HYENAE_DHCP_H

#include "hyenae-base.h"
#include "hyenae-patterns.h"
#include "hyenae-attack.h"

/* DHCP magic cookie */
#define HY_DHCP_COOKIE 0x63825363

/* DHCP options */
#define HY_DHCP_OPT_NETMASK      1
#define HY_DHCP_OPT_ROUTERS      3
#define HY_DHCP_OPT_DNSSERVERS   6
#define HY_DHCP_OPT_DOMAINNAME   15
#define HY_DHCP_OPT_REQUESTEDIP  50
#define HY_DHCP_OPT_DHCPMSGTYPE  53
#define HY_DHCP_OPT_SERVERID     54
#define HY_DHCP_OPT_PARAMREQLIST 55
#define HY_DHCP_OPT_CLIENT_IDENT 61
#define HY_DHCP_OPT_END          255

/* DHCP messages */
#define DHCP_MSG_DHCPREQUEST 3

/* -------------------------------------------------------------------------- */

typedef
  struct hy_dhcp_h {

  /*
   * USAGE:
   *   Represents a DHCP header.
   */

  uint32_t cookie;
  uint8_t options[];

} hy_dhcp_h_t;

/* -------------------------------------------------------------------------- */

unsigned char*
  hy_set_dhcp_option
    (
      unsigned char*,
      unsigned char,
      unsigned char,
      void* optval
    );

/* -------------------------------------------------------------------------- */

int
  hy_build_dhcp_request_packet
    (
      hy_pattern_t*,
      hy_pattern_t*,
      hy_pattern_t*,
      hy_pattern_t*,
      int,
      unsigned char**,
      int*,
      unsigned int,
      unsigned int
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_DHCP_H */
