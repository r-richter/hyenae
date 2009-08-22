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

#ifndef HYENAE_ASSISTENT_H
  #define HYENAE_ASSISTENT_H

#include "hyenae-common.h"
#include "hyenae-remote.h"

/* Max. input buffer length */
#define HY_INPUT_BUFLEN 1024

/* -------------------------------------------------------------------------- */

int
  hy_assistant_input_yes_no
    (
      const char*,
      int *
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_input_numeric
    (
      const char*,
      int *,
      int,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_input_address_pattern
    (
      const char*,
      const char*,
      int,
      char*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_input_text
    (
      const char*,
      char*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_arp_request_flood
    (
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_arp_cache_poisoning
    (
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_icmp_echo_flood
    (
      hy_attack_t*,
      int,
      const char*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_icmp_tcp_reset
    (
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_tcp_syn_flood
    (
      hy_attack_t*,
      int,
      const char*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_blind_tcp_reset
    (
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_udp_flood
    (
      hy_attack_t*,
      int,
      const char*
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_dns_query_flood
    (
      hy_attack_t*,
      int,
      const char*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_spoofed_dns_redirection
    (
      hy_attack_t*,
      int,
      const char*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_dhcp_discover_flood
    (
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_dhcp_starvation
    (
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_dhcp_release_forcing
    (
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_assistant_start
    (
      int*,
      hy_server_list_t**,
      hy_attack_t*,
      int*
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_ASSISTENT_H */
