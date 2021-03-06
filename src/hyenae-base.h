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

#ifndef HYENAE_BASE_H
  #define HYENAE_BASE_H

/* Required by autoconf */
#include "config.h"

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#ifdef OS_WINDOWS
  #include <conio.h>
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #ifndef FIONREAD
    #define FIONREAD (('f'<<8)|3)
  #endif /* FIONREAD */
  #include <unistd.h>
  #include <termios.h>
  #include <pthread.h>
  #include <sys/time.h>
  #include <sys/types.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <sys/un.h>
  #include <netinet/in.h>
#endif /* OS_WINDOWS */

#include <pcap.h>
#ifdef HAVE_LIBDUMBNET
  #include <dumbnet.h>
#else
  #include <dnet.h>
#endif /* HAVE_LIBDUMBNET */

/* Common errors */
#define HY_ER_OK                0
#define HY_ER_UNKNOWN          -1
#define HY_ER_NOT_ROOT         -2
#define HY_ER_FOPEN            -3
#define HY_ER_DELETE_FILE      -4
#define HY_ER_FILE_EMPTY       -5
#define HY_ER_PCAP_FINDALLDEVS -6
#define HY_ER_WSA_STARTUP      -7
#define HY_ER_SOCK_CREATE      -8
#define HY_ER_SOCK_SETOPT      -9
#define HY_ER_SOCK_BIND        -10
#define HY_ER_SOCK_LISTEN      -11
#define HY_ER_SOCK_ACCEPT      -12
#define HY_ER_CREATE_THREAD    -13

/* Config based errors */
#define HY_ER_CF_KEY_BUFLEN_EXCEED -1001
#define HY_ER_CF_VAL_BUFLEN_EXCEED -1002
#define HY_ER_CF_EMPTY_KEY         -1003
#define HY_ER_CF_NO_KEYS           -1004

/* Pattern based errors */
#define HY_ER_AMBIG_EOA_HW      -2001
#define HY_ER_AMBIG_EOA_IP      -2002
#define HY_ER_AD_T_UNKNOWN      -2003
#define HY_ER_IP_V_UNKNOWN      -2004
#define HY_ER_AD_EMPTY          -2005
#define HY_ER_AD_BUFLEN_EXCEED  -2006
#define HY_ER_PORT_EMPTY        -2007
#define HY_ER_PT_BUFLEN_EXCEED  -2008
#define HY_ER_SRV_PT_WCC_PERMIT -2009

/* Attack based errors */
#define HY_ER_NO_SUCH_IF              -3001
#define HY_ER_PCAP_OPEN_LIVE          -3002
#define HY_ER_NO_SRC_PT_GIVEN         -3003
#define HY_ER_NO_DST_PT_GIVEN         -3004
#define HY_ER_NO_SND_PT_GIVEN         -3005
#define HY_ER_NO_TCP_SRC_PT_GIVEN     -3006
#define HY_ER_NO_VIR_PT_GIVEN         -3007
#define HY_ER_NO_IP_REQ_GIVEN         -3008
#define HY_ER_NO_TRG_PT_GIVEN         -3009
#define HY_ER_NO_TCP_DST_PT_GIVEN     -3010
#define HY_ER_NO_SRV_IP_GIVEN         -3011
#define HY_ER_PKT_PAY_UNSUPPORTED     -3012
#define HY_ER_AT_T_UNKNOWN            -3013
#define HY_MTU_LIMIT_EXCEED           -3014
#define HY_ER_PCAP_WRITE              -3015
#define HY_ER_MULTIPLE_IP_V           -3016
#define HY_ER_WRONG_IP_V              -3017
#define HY_ER_WRONG_PT_FMT_SRC        -3018
#define HY_ER_WRONG_PT_FMT_DST        -3019
#define HY_ER_WRONG_PT_FMT_SND        -3020
#define HY_ER_WRONG_PT_FMT_TCP_SRC    -3021
#define HY_ER_WRONG_PT_FMT_IP_REQ     -3022
#define HY_ER_WRONG_PT_FMT_TRG        -3023
#define HY_ER_WRONG_PT_FMT_TCP_DST    -3024
#define HY_ER_WRONG_PT_FMT_SRV_IP     -3025
#define HY_ER_SND_DEL_WITHOUT_AT_T    -3026
#define HY_ER_CODE_WITHOUT_AT_T       -3027
#define HY_ER_PPPOE_CODE_UNKNOWN      -3028
#define HY_ER_ICMP_UNR_CODE_UNKNOWN   -3029
#define HY_ER_NO_TCP_FLAGS            -3030
#define HY_ER_TCP_FLG_UNKNOWN         -3031
#define HY_ER_DNS_NO_QUERIES          -3032
#define HY_ER_DNS_QRY_N_BUFLEN_EXCEED -3033
#define HY_ER_DNS_QRY_BUFLEN_EXCEED   -3034
#define HY_ER_DHCP_MSG_UNSUPPORTED    -3035
#define HY_ER_HSRP_PRIO_ZERO          -3036
#define HY_ER_HSRP_CODE_UNKNOWN       -3037
#define HY_ER_HSRP_AUTH_LEN_EXCEED    -3038
#define HY_ER_HSRP_MAX_PRIO_EXCEEDED  -3039
#define HY_ER_HSRP_MAX_GROUP_EXCEEDED -3040
#define HY_ER_HSRP_DEL_EXCEEDED       -3041

/* Protocol based errors */
#define HY_ER_MAX_RA_PKT_LEN_EXCEED -4001
#define HY_ER_PR_MALFORMED_RAR_H    -4002

/* Remote attack based error */
#define HY_ER_UNKNOWN_SL_KEY      -5001
#define HY_ER_WRONG_PT_FMT_SRV    -5002
#define HY_ER_RA_INVALID_SRV_AD_T -5003

/* Daemon based errors */
#define HY_ER_PWD_BUFLEN_EXCEED          -6001
#define HY_ER_TO_SHORT_PWD               -6002
#define HY_ER_EMPTY_PWD_STRIP            -6003
#define HY_ER_UNKNOWN_IP_KEY             -6004
#define HY_ER_INVALID_IP_LST_ADDR        -6005
#define HY_ER_DMN_LOG_FILE_BUFLEN_EXCEED -6006
#define HY_ER_PORT_ZERO                  -6007
#define HY_ER_BACKLOG_ZERO               -6008
#define HY_ER_MAX_CL_ZERO                -6009
#define HY_ER_MAX_CL_PKT_DUR_LMT_ZERO    -6010
#define HY_ER_CLI_PKT_LMT_EXCEED         -6011
#define HY_ER_CLI_DUR_LMT_EXCEED         -6012

/* Assistant based errors */
#define HY_ER_INP_BUFLEN_EXCEED -7001
#define HY_ER_WRONG_PT_FMT      -7002

/* Thread run states */
#define HY_RUN_STAT_RUNNING        0
#define HY_RUN_STAT_REQUESTED_STOP 1
#define HY_RUN_STAT_STOPPED        2

/* Output buffer length */
#define HY_OUT_BUFLEN 10240

/* Temporary output buffer lengths (internal use) */
#define HY_OUT_TMP_TS_BUFLEN 1024
#define HY_OUT_TMP_TYPE_BUFLEN 1024

/* Output time stamp format */
#define HY_OUT_TS_FMT "%m/%d/%y %I:%M:%S%p"

/* Output type definitions */
#define HY_OUT_T_NONE     0
#define HY_OUT_T_TASK     1
#define HY_OUT_T_NOTE     2
#define HY_OUT_T_WARNING  3
#define HY_OUT_T_ERROR    4
#define HY_OUT_T_RESULT   5
#define HY_OUT_T_FINISHED 6

/* Type definitions (dnet) */
typedef struct addr addr_t;
typedef struct eth_hdr eth_h_t;
typedef struct arp_hdr arp_h_t;
typedef struct arp_ethip arp_eth_ip_t;
typedef struct ip_hdr ip_v4_h_t;
typedef struct ip6_hdr ip_v6_h_t;
typedef struct icmp_hdr icmp_h_t;
typedef struct icmp_msg_echo icmp_echo_t;
typedef struct icmp_msg_needfrag icmp_unreach_t;
typedef struct tcp_hdr tcp_h_t;
typedef struct udp_hdr udp_h_t;

/* Type definitions (sockets) */
typedef struct timeval timeval_t;
#ifndef OS_WINDOWS
  typedef struct timezone timezone_t;
#endif /* OS_WINDOWS */
typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef struct sockaddr_in6 sockaddr_in6_t;
typedef struct sockaddr_un sockaddr_un_t;

/* -------------------------------------------------------------------------- */

int
  hy_initialize();

/* -------------------------------------------------------------------------- */

void
  hy_output
  (
    FILE*,
    int,
    int,
    const char*,
    ...
  );

/* -------------------------------------------------------------------------- */

extern void
  hy_handle_output
    (
      FILE*,
      int,
      const char*,
      const char*
    );

/* -------------------------------------------------------------------------- */

void
  hy_handle_output_default
    (
      FILE*,
      int,
      const char*,
      const char*
    );

/* -------------------------------------------------------------------------- */

int
  hy_was_key_pressed();

/* -------------------------------------------------------------------------- */

char*
  hy_str_to_lower
    (
      char*,
      int
    );

/* -------------------------------------------------------------------------- */

char*
  hy_str_to_upper
    (
      char*,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_random
    (
      int,
      int
    );

/* -------------------------------------------------------------------------- */

void
  hy_randomize_buffer
    (
      unsigned char*,
      unsigned int
    );

/* -------------------------------------------------------------------------- */

int
  hy_file_exist
    (
      const char*
    );

/* -------------------------------------------------------------------------- */

int
  hy_load_file_to_buffer
    (
      const char*,
      unsigned char**,
      unsigned int*
    );

/* -------------------------------------------------------------------------- */

unsigned long
  hy_get_milliseconds_of_day();

/* -------------------------------------------------------------------------- */

void
  hy_sleep
    (
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_get_if_name_by_index
    (
      int,
      char**
    );

/* -------------------------------------------------------------------------- */

void
  hy_shutdown_close_socket
    (
      int
    );

/* -------------------------------------------------------------------------- */

const char*
  hy_get_error_msg
    (
      int
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_BASE_H */
