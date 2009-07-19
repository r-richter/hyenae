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
  char str[1];

  printf(
    "\nEnter option number [%d-%d]:\n",
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
      hy_attack_t* attack
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

  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Starting attack assistent");
  printf("\nHyenae Attack Assistent\n");
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
    /* Enter remote daemon address */
    printf("\nEnter remote daemon address:\n");

    // TODO...

  }
  /* Determine attack type */
  printf("\nSelect attack type:\n");
  printf("> 1.  ARP-Request Flood (DoS)\n");
  printf("> 2.  ARP-Cache Poisoning (MITM)\n");
  printf("> 3.  ICMP-Echo Flood (DoS)\n");
  printf("> 4.  ICMP Based TCP-Reset (DoS)\n");
  printf("> 5.  TCP-SYN Flood (DoS)\n");
  printf("> 6.  Blind TCP-Reset (DoS)\n");
  printf("> 7.  UDP-Flood (DoS)\n");
  printf("> 8.  DHCP-Discover Flood (DoS)\n");
  printf("> 10. DHCP-Starvation (DoS)\n");
  printf("> 11. DHCP-Release Forcing (DoS)\n");
  switch (hy_enter_numeric_option(1, 11) == 1) {
    case 1:

      // TODO...

      break;
  }
  printf("\n");
  return ret;
} /* hy_start_attack_assistent */

/* -------------------------------------------------------------------------- */
