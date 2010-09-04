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

#include "hyenae-protocol.h"

/* -------------------------------------------------------------------------- */

int
  hy_build_remote_attack_request_buffer
    (
      hy_attack_t* params,
      unsigned char** buffer
    ) {

  /*
   * USAGE:
   *   Builds a send-ready remote attack request
   *   buffer based on the given arguments.
   */

  int len = sizeof(hy_attack_t) +
            params->pay_len;
  if (len > HY_MAX_RA_PKT_LEN) {
    return HY_ER_MAX_RA_PKT_LEN_EXCEED;
  }
  *buffer = malloc(len);
  memset(*buffer, 0, len);
  memcpy(*buffer, params, sizeof(hy_attack_t));
  if (params->pay_len > 0) {
    memcpy(
      (*buffer + sizeof(hy_attack_t)),
      params->pay,
      params->pay_len);
    ((hy_attack_t*) (*buffer))->pay = NULL;
  }
  return HY_ER_OK;
} /* hy_build_remote_attack_request_buffer */

/* -------------------------------------------------------------------------- */

int
  hy_parse_remote_attack_request_buffer
    (
      unsigned char* buffer,
      int len,
      hy_attack_t** params
    ) {

  /*
   * USAGE:
   *   Parses a received remote attack
   *   request buffer.
   */

  if (len < sizeof(hy_attack_t) ||
      len > HY_MAX_RA_PKT_LEN) {
    return HY_ER_PR_MALFORMED_RAR_H;
  }
  *params = malloc(sizeof(hy_attack_t));
  memset(*params, 0, sizeof(hy_attack_t));
  memcpy(*params, buffer, sizeof(hy_attack_t));
  if ((*params)->pay_len > 0) {
    (*params)->pay = malloc((*params)->pay_len);
    memset((*params)->pay, 0, (*params)->pay_len);
    memcpy(
      buffer + sizeof(hy_attack_t),
      (*params)->pay,
      (*params)->pay_len);
  } else {
    (*params)->pay = NULL;
  }
  return HY_ER_OK;
} /* hy_parse_remote_attack_request_buffer */

/* -------------------------------------------------------------------------- */
