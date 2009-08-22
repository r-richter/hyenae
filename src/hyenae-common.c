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

#include "hyenae-common.h"

/* -------------------------------------------------------------------------- */

int
  hy_print_if_list
    (
      int* if_count,
      int is_assistent_call
    ) {

  /*
   * USAGE:
   *   Prints a list of all available network
   *   interfaces on this machine.
   */

  int ret = HY_ER_OK;
  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_if_t* if_n = NULL;
  pcap_if_t* if_lst = NULL;

  if (is_assistent_call != 1) {
    hy_output(
      stdout,
      HY_OUT_T_TASK,
      0,
      "Obtaining network interfaces");
  }
  if (pcap_findalldevs(&if_lst, err_buf) == -1) {
    return HY_ER_PCAP_FINDALLDEVS;
  }
  for(if_n = if_lst; if_n; if_n = if_n->next) {
    *if_count = *if_count + 1;
    printf("  > %i. %s\n", *if_count, if_n->name);
  }
  if (is_assistent_call != 1) {
    hy_output(
      stdout,
      HY_OUT_T_FINISHED,
      0,
      "%i network interfaces found",
      *if_count);
  }
  return ret;
} /* hy_print_if_list */

/* -------------------------------------------------------------------------- */

void
  hy_print_attack_list() {

  /*
   * USAGE:
   *   Prints a list of all available attacks.
   */

  int i = 1;
  const char* att_n = NULL;

  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Obtaining available attacks");
  while (strcmp((att_n = hy_get_attack_name(i)), "Unknown")){
    printf("  > %s\n", att_n);
    i = i + 1;
  }
  hy_output(
    stdout,
    HY_OUT_T_FINISHED,
    0,
    "%i attack protocols available",
    i - 1);
} /* hy_print_attack_list */

/* -------------------------------------------------------------------------- */
