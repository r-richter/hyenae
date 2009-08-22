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

#include "hyenae-patterns.h"

/* -------------------------------------------------------------------------- */

int
  hy_get_address_type
    (
      const char* address,
      int len
    ) {

  /*
   * USAGE:
   *   Determines the type of an address,
   *   not the validity!
   */

  int i = 0;
  int c = 0;
  int dot_cnt = 0;
  int col_cnt = 0;
  int min_oct_len = -1;
  int max_oct_len = 0;
  int cur_oct_len = 0;

  while (i < len) {
    c = *(address + i);
    if (c == '.' || c == ':' ||
        ((i + 1) == len)) {
      if (c == '.') {
        dot_cnt = dot_cnt + 1;
      } else if (c == ':') {
        col_cnt = col_cnt + 1;
      } else {
        cur_oct_len = cur_oct_len + 1;
      }
      if (min_oct_len == -1 ||
          cur_oct_len < min_oct_len) {
        min_oct_len = cur_oct_len;
      }
      if (cur_oct_len > max_oct_len) {
        max_oct_len = cur_oct_len;
      }
      cur_oct_len = 0;
    } else {
      cur_oct_len = cur_oct_len + 1;
    }
    i = i + 1;
  }
  if (dot_cnt == 3 &&
      col_cnt == 0 &&
      min_oct_len >= 1 &&
      max_oct_len <= 3) {
    return HY_AD_T_IP_V4;
  } else if (dot_cnt == 0 &&
             col_cnt == 7 &&
             min_oct_len == 4 &&
             max_oct_len == 4) {
    return HY_AD_T_IP_V6;
  } else if (dot_cnt == 0 &&
             col_cnt == 5 &&
             min_oct_len == 2 &&
             max_oct_len == 2) {
    return HY_AD_T_HW;
  }
  return HY_AD_T_UNKNOWN;
} /* hy_get_address_type */

/* -------------------------------------------------------------------------- */

void
  hy_replace_wildcards
    (
      char* address,
      int type,
      int len
    ) {

  /*
   * USAGE:
   *   Replaces all wildcard characters within an
   *   address with adequate random values.
   */

  int i = 0;
  int rnd_val = 0;
  int rnd_chrs[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  while (i < len) {
    if (*(address + i) == HY_PT_WCC) {
      if (type == HY_AD_T_IP_V4) {
        /* Adequate wildcard based octet
           randomization in IPv4 addresses
           is a bit more complicated */
        rnd_val = hy_random(0, 9);
        if ((i == 0 ||
             *(address + i - 1) == '.') &&
            (i + 2) < len &&
            *(address + i + 1) != '.' &&
            *(address + i + 2) != '.') {
          rnd_val = hy_random(1, 2);
          if (*(address + i + 1) != HY_PT_WCC &&
              (*(address + i + 1) > '5' ||
               (*(address + i + 1) == '5' &&
                *(address + i + 2) > '5'))) {
            rnd_val = 1;
          }
        } else if ((i == 1 ||
                    *(address + i - 2) == '.') &&
                  (i + 1) < len &&
                    *(address + i + 1) != '.') {
          if (*(address + i - 1) > '1') {
            rnd_val = hy_random(0, 5);
            if (*(address + i + 1) != HY_PT_WCC &&
                *(address + i + 1) > '5') {
              rnd_val = hy_random(0, 4);
            }
          }
        } else if ((i == 2 ||
                    *(address + i - 3) == '.')) {
          if (*(address + i - 2) > '1' &&
              *(address + i - 1) > '4'){
            rnd_val = hy_random(0, 5);
          }
        }
        if (rnd_val == 0 &&
            (i == 0 ||
             ((*(address + i - 1) == '.') &&
              *(address + i + 1) != '.'))) {
          rnd_val = rnd_val + 1;
        }
        *(address + i) = *(rnd_chrs + rnd_val);
      } else {
        if (type == HY_AD_T_HW || type == HY_AD_T_IP_V6) {
          *(address + i) = *(rnd_chrs + hy_random(0, 16));
        } else {
          /* Useful when passing port values
             to this function */
          *(address + i) = *(rnd_chrs + hy_random(0, 9));
        }
      }
    }
    i = i + 1;
  }
} /* hy_replace_wildcards */

/* -------------------------------------------------------------------------- */

int
  hy_parse_copy_address
    (
      const char* address,
      int len,
      hy_pattern_t* pattern,
      int ip_version_asm
    ) {

  /*
   * USAGE:
   *   Parses and copies an address to
   *   the given pattern structure.
   */

  int type = 0;

  if (len < 1) {
    return HY_ER_AD_EMPTY;
  }
  if (len > HY_AD_BUFLEN) {
    return HY_ER_AD_BUFLEN_EXCEED;
  }
  if (len == 1 && *(address) == HY_PT_WCC) {
    switch (ip_version_asm) {
      case HY_AD_T_HW:
        len = strlen(HY_PT_D_HW);
        memset(pattern->hw_addr, 0, HY_AD_BUFLEN);
        strncpy(pattern->hw_addr, HY_PT_D_HW, len);
        hy_replace_wildcards(
          pattern->hw_addr,
          HY_AD_T_HW,
          len);
        break;
      case HY_AD_T_IP_V4:
        len = strlen(HY_PT_D_IP_V4);
        pattern->ip_v = HY_AD_T_IP_V4;
        memset(pattern->ip_addr, 0, HY_AD_BUFLEN);
        strncpy(pattern->ip_addr, HY_PT_D_IP_V4, len);
        hy_replace_wildcards(
          pattern->ip_addr,
          HY_AD_T_IP_V4,
          len);
        break;
      case HY_AD_T_IP_V6:
        len = strlen(HY_PT_D_IP_V6);
        pattern->ip_v = HY_AD_T_IP_V6;
        memset(pattern->ip_addr, 0, HY_AD_BUFLEN);
        strncpy(pattern->ip_addr, HY_PT_D_IP_V6, len);
        hy_replace_wildcards(
          pattern->ip_addr,
          HY_AD_T_IP_V6,
          len);
        break;
      default:
        return HY_ER_IP_V_UNKNOWN;
    }
    return HY_ER_OK;
  }
  type = hy_get_address_type(address, len);
  if (type == HY_AD_T_HW) {
    memset(pattern->hw_addr, 0, HY_AD_BUFLEN);
    strncpy(pattern->hw_addr, address, len);
    hy_replace_wildcards(pattern->hw_addr, type, len);
  } else if (type == HY_AD_T_IP_V4 ||
             type == HY_AD_T_IP_V6) {
    pattern->ip_v = type;
    memset(pattern->ip_addr, 0, HY_AD_BUFLEN);
    strncpy(pattern->ip_addr, address, len);
    hy_replace_wildcards(pattern->ip_addr, type, len);
  } else {
    return HY_ER_AD_T_UNKNOWN;
  }
  return HY_ER_OK;
} /* hy_parse_copy_address */

/* -------------------------------------------------------------------------- */

int
  hy_parse_copy_port
    (
      const char* port,
      int len,
      hy_pattern_t* pattern
    ) {

  /*
   * USAGE:
   *   Parses and copies a port to the
   *   given pattern structure.
   */

  char* tmp = malloc(len + 1);

  if (len < 1) {
    return HY_ER_PORT_EMPTY;
  }
  memset(tmp, 0, len + 1);
  strncpy(tmp, port, len);
  hy_replace_wildcards(tmp, HY_AD_T_UNKNOWN, len);
  pattern->port = atoi(tmp);
  if (pattern->port  < 1) {
    pattern->port = 1;
  }
  free(tmp);
  return HY_ER_OK;
} /* hy_parse_copy_port */

/* -------------------------------------------------------------------------- */

int
  hy_parse_pattern
    (
      hy_pattern_t* pattern,
      int ip_v_assumption
    ) {

  /*
   * USAGE:
   *   Parses an address pattern by automatically
   *   detecting format and address versions.
   */

  int i = 0;
  int c = 0;
  int len = strlen(pattern->src);
  int ret = HY_ER_OK;
  int hw_eoa_i = -1;
  int ip_eoa_i = -1;

  memset(pattern->hw_addr, 0, HY_AD_BUFLEN);
  memset(pattern->ip_addr, 0, HY_AD_BUFLEN);
  pattern->ip_v = HY_AD_T_UNKNOWN;
  pattern->port = 0;
  while (i < len) {
    c = *(pattern->src + i);
    if (c == HY_PT_EOA_HW) {
      if (hw_eoa_i != -1) {
        return HY_ER_AMBIG_EOA_HW;
      }
      hw_eoa_i = i;
    } else if (c == HY_PT_EOA_IP) {
      if (ip_eoa_i != -1) {
        return HY_ER_AMBIG_EOA_IP;
      }
      ip_eoa_i = i;
    }
    i = i + 1;
  }
  if (hw_eoa_i != -1 && ip_eoa_i != -1) {
    /* Assume format: HW/IP/Port */
    if ((ret =
           hy_parse_copy_address(
             pattern->src,
             hw_eoa_i,
             pattern,
             HY_AD_T_HW)) != HY_ER_OK ||
        (ret =
           hy_parse_copy_address(
             pattern->src + hw_eoa_i + 1,
             ip_eoa_i - hw_eoa_i - 1,
             pattern,
             ip_v_assumption)) != HY_ER_OK ||
        (ret =
           hy_parse_copy_port(
             pattern->src + ip_eoa_i + 1,
            len - ip_eoa_i - 1,
            pattern)) != HY_ER_OK) {
      return ret;
    }
  } else if (hw_eoa_i != -1) {
    /* Assume format: HW/IP */
    if ((ret =
           hy_parse_copy_address(
             pattern->src,
             hw_eoa_i,
             pattern,
             HY_AD_T_HW)) != HY_ER_OK ||
        (ret =
           hy_parse_copy_address(
             pattern->src + hw_eoa_i + 1,
             len - hw_eoa_i - 1,
             pattern,
             ip_v_assumption)) != HY_ER_OK) {
      return ret;
    }
  } else if (ip_eoa_i != -1) {
    /* Assume format: IP/Port */
    if ((ret =
           hy_parse_copy_address(
             pattern->src,
             ip_eoa_i,
             pattern,
             ip_v_assumption)) != HY_ER_OK ||
        (ret =
           hy_parse_copy_port(
             pattern->src + ip_eoa_i + 1,
            len - ip_eoa_i - 1,
            pattern)) != HY_ER_OK) {
      return ret;
    }
  } else {
    /* Assume format: HW */
    if ((ret =
           hy_parse_copy_address(
             pattern->src,
             len,
             pattern,
             HY_AD_T_HW)) != HY_ER_OK) {
      return ret;
    }
  }
  return HY_ER_OK;
} /* hy_parse_pattern */

/* -------------------------------------------------------------------------- */
