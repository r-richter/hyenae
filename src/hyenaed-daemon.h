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

#ifndef HYENAED_DAEMON_H
  #define HYENAED_DAEMON_H

/* Daemon receive timeout in seconds */
#define HY_DMN_RCV_TIMEOUT 3

/* Log file buffer length */
#define HY_DMN_LOG_FILE_BUFLEN 1024

#include "hyenae-base.h"
#include "hyenae-config.h"
#include "hyenae-attack.h"
#include "hyenae-protocol.h"

/* -------------------------------------------------------------------------- */

typedef
  struct hy_ip_list {

  /*
   * USAGE:
   *   Represents a list of IP addresses.
   */

  char ip_addr[HY_AD_BUFLEN];
  struct hy_ip_list* next;

} hy_ip_list_t;

/* -------------------------------------------------------------------------- */

typedef
  struct hy_daemon {

  /*
   * USAGE:
   *   Represents the daemon configuration.
   */

  char* if_n;
  char pwd[HY_MAX_PWD_LEN];
  char ip_addr[HY_AD_BUFLEN];
  int port;
  int bcklog;
  int ip_v;
  int max_cli;
  unsigned long cli_pkt_lmt;
  unsigned long cli_dur_lmt;
  char log_file[HY_DMN_LOG_FILE_BUFLEN];
  hy_ip_list_t* tru_ip_lst;
  hy_ip_list_t* none_tru_ip_lst;

} hy_daemon_t;

/* -------------------------------------------------------------------------- */

typedef
  struct hy_handle_client {

  /*
   * USAGE:
   *   Represents the parameters for the
   *   hy_handle_client function.
   */

  int s_cli;
  int* cli_cnt;
  FILE* log_f;
  pcap_t* pcap_dsc;
  sockaddr_in_t sa_in;
  sockaddr_in6_t sa_in6;
  hy_daemon_t dmn_cfg;

} hy_handle_client_t;

/* -------------------------------------------------------------------------- */

int
  hy_load_ip_list
    (
      const char*,
      hy_ip_list_t**
    );

/* -------------------------------------------------------------------------- */

int
  hy_is_ip_in_list
    (
      const char*,
      hy_ip_list_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_start_daemon
    (
      hy_daemon_t*
    );

/* -------------------------------------------------------------------------- */

#ifdef OS_WINDOWS
  DWORD WINAPI
    hy_win32_handle_client
      (
        LPVOID
      );
#else
  void*
    hy_unix_handle_client
      (
        void*
      );
#endif /* OS_WINDOWS */

/* -------------------------------------------------------------------------- */

void
  hy_handle_client
    (
      hy_handle_client_t*
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAED_DAEMON_H */
