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

#ifndef HYENAE_DNS_H
  #define HYENAE_DNS_H

#include "hyenae-base.h"
#include "hyenae-patterns.h"
#include "hyenae-attack.h"

/* Domain name sep. character */
#define DNS_N_SC '.'

/* DNS question/answer list sep. character */
#define HY_DNS_QA_SC ','

/* DNS name buffer length */
#define HY_DNS_N_BUFLEN 255

/* DNS packet buffer length */
#define HY_DNS_PACKET_BUFLEN (HY_MTU_LIMIT - sizeof(eth_h_t) - sizeof(udp_h_t))

/* DNS port definitions */
#define HY_DNS_PORT 53

/* -------------------------------------------------------------------------- */

typedef
  struct hy_dns_h {

  /*
   * USAGE:
   *   Represents a DNS header.
   */

  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;

} hy_dns_h_t;

/* -------------------------------------------------------------------------- */

  void
    hy_encode_domain_name
    (
      unsigned char*,
      unsigned char**,
      int*
    );

/* -------------------------------------------------------------------------- */

int
  hy_dns_parse_add_queries
    (
      unsigned char*,
      int*,
      const char*,
      int*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_build_dns_packet
    (
      hy_pattern_t*,
      hy_pattern_t*,
      int,
      unsigned char**,
      int*,
      unsigned int,
      const char*
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_DNS_H */
