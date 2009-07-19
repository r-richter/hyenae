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

#include "hyenae-attack-assistent.h"

/* -------------------------------------------------------------------------- */

int
  hy_enter_yes_no
    (
      const char* question
    ) {

  /*
   * USAGE:
   *   Requests the user to enter either
   *   yes or no.
   */

  char str[HY_INPUT_BUFLEN];

  printf("\n%s [y/n]? ", question);
  while(1) {
    if (scanf("%s", str) > 0) {
      if (strcmp(str, "y") == 0) {
        return 1;
      } else {
        if (strcmp(str, "n") == 0) {
          break;
        }
      }
    }
  }
  return 0;
} /* hy_enter_yes_no */

/* -------------------------------------------------------------------------- */

int
  hy_enter_numeric_option
    (
      int min_opt,
      int max_opt
    ) {

  /*
   * USAGE:
   *   Requests the user to enter a numeric
   *   option value.
   */

  int opt = 0;
  char str[HY_INPUT_BUFLEN];

  printf(
    "\nEnter option number [%d-%d]: ",
    min_opt,
    max_opt);
  while(1) {
    if (scanf("%s", str) > 0) {
      opt = atoi(str);
      if (opt >= min_opt && opt <= max_opt) {
        break;
      }
    }
  }
  return opt;
} /* hy_enter_numeric_option */

/* -------------------------------------------------------------------------- */

int
  hy_start_attack_assistent
    (
      int* if_index,
      hy_attack_t* attack,
      hy_server_list_t** server_lst
    ) {

  /*
   * USAGE:
   *   Fills the given network interface index
   *   and attack parameter structure by executing
   *   an interactive text based assistent.
   */

  int ret = HY_ER_OK;
  int if_cnt = 0;
  int att_mode = 0;
  char srv_pat[HY_INPUT_BUFLEN];
  char srv_file[HY_INPUT_BUFLEN];

  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Starting attack assistent");
  memset(attack, 0, sizeof(hy_attack_t));
  printf("\nHyenae Attack Assistent (BETA)\n");
  printf("====================================================\n");
  /* Determine attack mode (local/remote) */
  printf("\nWhere do you want to start the attack from?\n");
  printf("> 1. Attack from local machine\n");
  printf("> 2. Attack from a remote daemon\n");
  if ((att_mode = hy_enter_numeric_option(1, 2)) == 1) {
    /* Select network interface */
    printf("\nSelect network interface:\n");
    if ((ret = hy_print_if_list(&if_cnt, 1)) != HY_ER_OK) {
      return ret;
    }
    *if_index = hy_enter_numeric_option(1, if_cnt);
  } else {
    /* Enter server file path */
    if (hy_enter_yes_no("Do you want to load an existing server file") == 1) {
      printf("\nEnter server file path\n");
      printf("ex. \"/home/user/server.lst\" or \"c:\\server.lst\":\n> ");
      scanf("%s", srv_file);
      if (*server_lst != NULL) {
        free(*server_lst);
      }
      if ((ret =
             hy_load_server_list(
               srv_file, server_lst)) != HY_ER_OK) {
        return ret;
      }
    } else {
      /* Enter server address pattern */
      printf("\nEnter server address pattern\n");
      printf("ex. [IP-Address]@[Port] or [IP-Address]@[Port]+[Password]:\n> ");
      scanf("%s", srv_pat);
      if (*server_lst != NULL) {
        free(*server_lst);
      }
      *server_lst = malloc(sizeof(hy_server_list_t));
      (*server_lst)->next = NULL;
      if ((ret =
             hy_set_server_list_item(
               srv_pat,
               *server_lst)) != HY_ER_OK) {
        return ret;
      }
    }
  }
  /* Select attack scenario */
  printf("\nSelect attack scenario:\n");
  printf("> 1.  ARP-Request Flood (DoS)\n");
  printf("> 2.  ARP-Cache Poisoning (MITM)\n");
  printf("> 3.  ICMP-Echo Flood (DoS)\n");
  printf("> 4.  ICMP Based TCP-Reset (DoS)\n");
  printf("> 5.  TCP-SYN Flood (DoS)\n");
  printf("> 6.  Blind TCP-Reset (DoS)\n");
  printf("> 7.  UDP-Flood (DoS)\n");
  printf("> 8.  DHCP-Discover Flood (DoS)\n");
  printf("> 9.  DHCP-Starvation (DoS)\n");
  printf("> 10. DHCP-Release Forcing (DoS)\n");
  switch (hy_enter_numeric_option(1, 10)) {
    case 1:
      /* ARP-Request Flood */
      attack->type = HY_AT_T_ARP_REQUEST;
      // TODO...
      break;
    case 2:
      /* ARP-Cache Poisoning */
      attack->type = HY_AT_T_ARP_REPLY;
      // TODO...
      break;
    case 3:
      /* ICMP-Echo Flood */
      attack->type = HY_AT_T_ICMP_ECHO;
      printf("\nEnter source address pattern\n");
      printf("ex. [HW-Address]-[IP-Address]:\n> ");
      scanf("%s", attack->src_pat.src);
      printf("\nEnter destination address pattern\n");
      printf("ex. [HW-Address]-[IP-Address]:\n> ");
      scanf("%s", attack->dst_pat.src);
      break;
    case 4:
      /* ICMP Based TCP-Reset */
      attack->type = HY_AT_T_ICMP_UNREACH_TCP;
      attack->min_cnt = 1;
      // TODO...
      break;
    case 5:
      /* TCP-SYN Flood */
      attack->type = HY_AT_T_TCP;
      attack->tcp_flgs = TH_SYN;   
      printf("\nEnter source address pattern\n");
      printf("ex. [HW-Address]-[IP-Address]@[Port]:\n> ");
      scanf("%s", attack->src_pat.src);
      printf("\nEnter destination address pattern\n");
      printf("ex. [HW-Address]-[IP-Address]@[Port]:\n> ");
      scanf("%s", attack->dst_pat.src);
      break;
    case 6:
      /* Blind TCP-Reset */
      attack->type = HY_AT_T_TCP;
      attack->tcp_flgs = TH_RST;
      attack->tcp_seq = 0;
      attack->tcp_seq_ins = 1;
      printf("\nEnter source address pattern\n");
      printf("ex. [HW-Address]-[IP-Address]@[Port]:\n> ");
      scanf("%s", attack->src_pat.src);
      printf("\nEnter destination address pattern\n");
      printf("ex. [HW-Address]-[IP-Address]@[Port]:\n> ");
      scanf("%s", attack->dst_pat.src);
      break;
    case 7:
      /* UDP-Flood */
      attack->type = HY_AT_T_UDP;
      printf("\nEnter source address pattern\n");
      printf("ex. [HW-Address]-[IP-Address]@[Port]:\n> ");
      scanf("%s", attack->src_pat.src);
      printf("\nEnter destination address pattern\n");
      printf("ex. [HW-Address]-[IP-Address]@[Port]:\n> ");
      scanf("%s", attack->dst_pat.src);
      break;
    case 8:
      /* DHCP-Discover Flood */
      attack->type = HY_AT_T_DHCP_DISCOVER;
      // TODO...
      break;
    case 9:
      /* DHCP-Starvation */
      attack->type = HY_AT_T_DHCP_REQUEST;
      // TODO...
      break;
    case 10:
      /* DHCP-Release Forcing */
      attack->type = HY_AT_T_DHCP_RELEASE;
      // TODO...
      break;
  }
  printf("\n");
  return ret;
} /* hy_start_attack_assistent */

/* -------------------------------------------------------------------------- */
