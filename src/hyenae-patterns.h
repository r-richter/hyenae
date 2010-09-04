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

#ifndef HYENAE_PATTERHY_H
  #define HYENAE_PATTERHY_H

#include "hyenae-base.h"

/* Address types */
#define HY_AD_T_HW      1
#define HY_AD_T_IP_V4   4
#define HY_AD_T_IP_V6   6
#define HY_AD_T_UNKNOWN 0

/* End-Of-Address characters */
#define HY_PT_EOA_HW '-'
#define HY_PT_EOA_IP '@'

/* Wildcard character */
#define HY_PT_WCC '%'

/* Default address patterns */
#define HY_PT_D_HW "%%:%%:%%:%%:%%:%%"
#define HY_PT_D_IP_V4 "%%%.%%%.%.%"
#define HY_PT_D_IP_V6 "%%%%:%%%%:%%%%:%%%%:%%%%:%%%%:%%%%:%%%%"

/* Pattern buffer length */
#define HY_PT_BUFLEN 255

/* Uniform address buffer length */
#define HY_AD_BUFLEN 255

/* -------------------------------------------------------------------------- */

typedef
  struct hy_pattern {

  /*
   * USAGE:
   *   Stores pattern informations
   *   and parse results.
   */

  char src[HY_PT_BUFLEN];
  char hw_addr[HY_AD_BUFLEN];
  char ip_addr[HY_AD_BUFLEN];
  int ip_v;
  int port;

} hy_pattern_t;

/* -------------------------------------------------------------------------- */

int
  hy_get_address_type
    (
      const char*,
      int
    );

/* -------------------------------------------------------------------------- */

void
  hy_replace_wildcards
    (
      char*,
      int,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_parse_copy_address
    (
      const char*,
      int,
      hy_pattern_t*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_parse_copy_port
    (
      const char*,
      int,
      hy_pattern_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_parse_pattern
    (
      hy_pattern_t*,
      int
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_PATTERHY_H */
