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

#ifndef HYENAE_PROTOCOL_H
  #define HYENAE_PROTOCOL_H

#include "hyenae-base.h"
#include "hyenae-attack.h"

/* Min / Max password length */
#define HY_MIN_PWD_LEN 8
#define HY_MAX_PWD_LEN 128

/* Max remote attack packet length */
#define HY_MAX_RA_PKT_LEN 5000

/* Remote attack handshake messages */
#define HY_RAH_MSG_HELLO       0
#define HY_RAH_MSG_OK          1
#define HY_RAH_MSG_BAD_VERSION 2
#define HY_RAH_MSG_WRONG_PWD   3
#define HY_RAH_MSG_SRV_FULL    4

/* Remote attack handshake version buffer length */
#define HY_RAH_VER_BUFLEN 255

/* -------------------------------------------------------------------------- */

typedef
  struct hy_ra_handshake {

  /*
   * USAGE:
   *   Represents a remote attack handshake.
   */

  char ver[HY_RAH_VER_BUFLEN];
  char pwd[HY_MAX_PWD_LEN];
  int msg;

} hy_ra_handshake_t;

/* -------------------------------------------------------------------------- */

typedef
  struct hy_ra_request_h {

  /*
   * USAGE:
   *   Represents a remote attack request header.
   */

  int att_type;
  hy_pattern_t src_pat;
  hy_pattern_t dst_pat;
  hy_pattern_t snd_pat;
  hy_pattern_t trg_pat;
  unsigned long min_cnt;
  unsigned long max_cnt;
  unsigned int min_del;
  unsigned int max_del;
  unsigned long min_dur;
  unsigned long max_dur;
  unsigned int ip_ttl;
  unsigned int tcp_flgs;
  unsigned long tcp_seq;
  unsigned long tcp_seq_ins;
  unsigned long tcp_ack;
  unsigned int tcp_wnd;
  unsigned int ip_v_asm;
  unsigned int ign_mtu;
  unsigned int cld_run;
  unsigned int pay_len;

} hy_ra_request_h_t;

/* -------------------------------------------------------------------------- */

int
  hy_build_remote_attack_request
    (
      hy_attack_t*,
      unsigned char**
    );

/* -------------------------------------------------------------------------- */

int
  hy_parse_remote_attack_request
    (
      unsigned char*,
      int len,
      hy_attack_t**
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_PROTOCOL_H */
