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

#ifndef HYENAE_HSRP_H
  #define HYENAE_HSRP_H

/* HSRP authentification data length */
#define HY_HSRP_AUTH_LEN 8

#include "hyenae-base.h"
#include "hyenae-patterns.h"
#include "hyenae-attack.h"

/* HSRP opcode definitions */
#define HY_HSRP_OP_HELLO  0
#define HY_HSRP_OP_COUP   1
#define HY_HSRP_OP_RESIGN 2

/* HSRP state definitions */
#define HY_HSRP_STATE_INIT    0
#define HY_HSRP_STATE_LEARN   1
#define HY_HSRP_STATE_LISTEN  2
#define HY_HSRP_STATE_SPEAK   4
#define HY_HSRP_STATE_STANDBY 8
#define HY_HSRP_STATE_ACTIVE  16

/* HSRP port definitions*/
#define HY_HSRP_PORT 1985

/* HSRP multicast IP-Address */
#define HY_HSRP_MC_IP_ADDR "224.0.0.2"

/* HSRP multicast HW-Address */
#define HY_HSRP_MC_HW_ADDR "01:00:5e:00:00:02"

/* -------------------------------------------------------------------------- */

typedef
  struct hy_hsrp_h {

  /*
   * USAGE:
   *   Represents an HSRP header.
   */

  uint8_t ver;
  uint8_t op;
  uint8_t state;
  uint8_t hello_tm;
  uint8_t hold_tm;
  uint8_t prio;
  uint8_t grp;
  uint8_t zero;
  uint8_t auth[HY_HSRP_AUTH_LEN];
  ip_addr_t v_ip;

} hy_hsrp_h_t;

/* -------------------------------------------------------------------------- */

int
  hy_build_hsrp_packet
    (
      hy_pattern_t*,
      hy_pattern_t*,
      int,
      unsigned char**,
      int*,
      unsigned int,
      unsigned int,
      unsigned int,
      unsigned char*,
      unsigned int,
      unsigned char,
      unsigned char
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_HSRP_H */
