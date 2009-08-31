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

#ifndef HYENAE_PPPOE_H
  #define HYENAE_PPPOE_H

#include "hyenae-base.h"
#include "hyenae-patterns.h"
#include "hyenae-attack.h"

/* PPPoE code definitions */
#define HY_PPPOE_CODE_PADI 0x09
#define HY_PPPOE_CODE_PADT 0xa7

/* PPoE tag type definitions */
#define HY_PPOE_TAG_T_SERVICE_NAME 0x0101

/* -------------------------------------------------------------------------- */

typedef
  struct hy_pppoe_h {

  /*
   * USAGE:
   *   Represents a PPPoE header.
   */

  #if DNET_BYTESEX == DNET_BIG_ENDIAN
    uint8_t ver:4;
    uint8_t type:4;
  #elif DNET_BYTESEX == DNET_LIL_ENDIAN
    uint8_t type:4;
    uint8_t ver:4;
  #else
    # error "need to include <dnet.h>"
  #endif /* DNET_BYTESEX == DNET_BIG_ENDIAN */
  uint8_t code;
  uint16_t sid;
  uint16_t len;

} hy_pppoe_h_t;

/* -------------------------------------------------------------------------- */

typedef
  struct hy_pppoe_tag {

  /*
   * USAGE:
   *   Represents a PPPoE tag.
   */

  uint16_t type;
  uint16_t len;

} hy_pppoe_tag_t;

/* -------------------------------------------------------------------------- */

int
  hy_build_pppoe_discover_packet
    (
      hy_pattern_t*,
      hy_pattern_t*,
      int,
      unsigned char**,
      int*,
      unsigned int,
      unsigned int
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_PPPOE_H */
