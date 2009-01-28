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

#ifndef HYENAE_REMOTE_H
  #define HYENAE_REMOTE_H

/* Pattern / Password seperation character */
#define HY_SRV_PT_PWD_SC '+'

/* Remote attack receive timeout in seconds */
#define HY_RA_RCV_TIMEOUT 120

#include "hyenae-base.h"
#include "hyenae-config.h"
#include "hyenae-attack.h"
#include "hyenae-protocol.h"

/* -------------------------------------------------------------------------- */

typedef
  struct hy_socket_list {

  /*
   * USAGE:
   *   Represents a list of sockets.
   */

  int s;
  char pwd[HY_MAX_PWD_LEN];
  char ip_addr[HY_AD_BUFLEN];
  struct hy_socket_list* next;

} hy_socket_list_t;

/* -------------------------------------------------------------------------- */

typedef
  struct hy_server_list {

  /*
   * USAGE:
   *   Represents a list of servers.
   */

  char pwd[HY_MAX_PWD_LEN];
  char ip_addr[HY_AD_BUFLEN];
  int ip_v;
  int port;
  struct hy_server_list* next;

} hy_server_list_t;

/* -------------------------------------------------------------------------- */

int
  hy_set_server_list_item
    (
      const char*,
      hy_server_list_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_load_server_list
    (
      const char*,
      hy_server_list_t**
    );

/* -------------------------------------------------------------------------- */

void
  hy_send_remote_attack_request
    (
      hy_attack_t*,
      hy_server_list_t*,
      hy_attack_result_t*
    );

/* -------------------------------------------------------------------------- */

void
  hy_free_socket_list
    (
      hy_socket_list_t*
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_REMOTE_H */
