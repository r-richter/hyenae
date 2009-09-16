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

#ifndef HYENAE_ATTACK_H
  #define HYENAE_ATTACK_H

#include "hyenae-base.h"
#include "hyenae-config.h"
#include "hyenae-patterns.h"
#include "hyenae-eth.h"
#include "hyenae-arp.h"
#include "hyenae-pppoe.h"
#include "hyenae-ip.h"
#include "hyenae-icmp.h"
#include "hyenae-tcp.h"
#include "hyenae-udp.h"
#include "hyenae-dns.h"
#include "hyenae-bootp.h"
#include "hyenae-dhcp.h"

/* MTU limit */
#define HY_MTU_LIMIT 1500

/* Attack types */
#define HY_AT_T_UNKNOWN         -1
#define HY_AT_T_ARP_REQUEST      1
#define HY_AT_T_ARP_REPLY        2
#define HY_AT_T_PPPOE_DISCOVER   3
#define HY_AT_T_ICMP_ECHO        4
#define HY_AT_T_ICMP_UNREACH_TCP 5
#define HY_AT_T_TCP              6
#define HY_AT_T_UDP              7
#define HY_AT_T_DNS_QUERY        8
#define HY_AT_T_DHCP_DISCOVER    9
#define HY_AT_T_DHCP_REQUEST     10
#define HY_AT_T_DHCP_RELEASE     11

/* Opcode initialization value */
#define HY_AT_OC_NONE -1

/* Turncation flags */
#define HY_TC_NONE    0
#define HY_TC_PKT_CNT 0x00000001
#define HY_TC_TOT_BYT 0x00000010

/* Max. result string buffer length */
#define HY_RES_LINE_BUFLEN 1024

/* Max. DNS query pattern length */
#define HY_DNS_QRY_BUFLEN (1024)

/* -------------------------------------------------------------------------- */

typedef
  struct hy_attack {

  /*
   * USAGE:
   *   Stores attack parameters.
   */

  int type;
  hy_pattern_t src_pat;
  hy_pattern_t dst_pat;
  hy_pattern_t sec_src_pat;
  hy_pattern_t sec_dst_pat;
  unsigned char* pay;
  unsigned int pay_len;
  unsigned long min_cnt;
  unsigned long max_cnt;
  unsigned int min_del;
  unsigned int max_del;
  unsigned long min_dur;
  unsigned long max_dur;
  unsigned int ip_ttl;
  unsigned int opcode;
  char dns_qry[HY_DNS_QRY_BUFLEN];
  unsigned int tcp_flgs;
  unsigned long seq_sid;
  unsigned long seq_sid_ins;
  unsigned long tcp_ack;
  unsigned int tcp_wnd;
  unsigned int ip_v_asm;
  unsigned int ign_mtu;
  unsigned int cld_run;

} hy_attack_t;

/* -------------------------------------------------------------------------- */

typedef
  struct hy_attack_result {

  /*
   * USAGE:
   *   Stores the results of an attack.
   */

  int ret;
  unsigned long pkt_cnt;
  unsigned long tot_byt;
  unsigned char tc_flg;
  unsigned long dur_msec;

} hy_attack_result_t;

/* -------------------------------------------------------------------------- */

typedef
  struct hy_attack_loop {

  /*
   * USAGE:
   *   Stores parameters of the attack loop.
   */

  pcap_t* dsc;
  hy_attack_t* att;
  hy_attack_result_t* res;
  unsigned long pkt_lmt;
  unsigned char* pkt_buf;
  int run_stat;

} hy_attack_loop_t;

/* -------------------------------------------------------------------------- */

void
  hy_init_attack_params
    (
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_get_attack_type_value
    (
      const char*
    );

/* -------------------------------------------------------------------------- */

const char*
  hy_get_attack_name
    (
      int
    );

/* -------------------------------------------------------------------------- */

char*
  hy_get_attack_result_string
    (
      hy_attack_result_t*
    );

/* -------------------------------------------------------------------------- */

void
  hy_attack
    (
      hy_attack_t*,
      pcap_t*,
      int,
      hy_attack_result_t*
    );

/* -------------------------------------------------------------------------- */

extern void
  hy_handle_attack_blocking
    (
      hy_attack_loop_t*
    );

/* -------------------------------------------------------------------------- */

#ifdef OS_WINDOWS
  DWORD WINAPI
    hy_win32_attack_loop
      (
        LPVOID
      );
#else
  void*
    hy_unix_attack_loop
      (
        void*
      );
#endif /* OS_WINDOWS */

/* -------------------------------------------------------------------------- */

void
  hy_attack_loop
    (
      hy_attack_loop_t*
    );

/* -------------------------------------------------------------------------- */

void
  hy_local_attack
    (
      const char*,
      hy_attack_t*,
      hy_attack_result_t*
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_ATTACK_H */
