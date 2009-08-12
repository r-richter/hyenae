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

#include "hyenaed.h"

/* -------------------------------------------------------------------------- */

void
  hy_handle_output
    (
      FILE* file,
      int type,
      const char* timestamp,
      const char* output
    ) {

  /*
   * USAGE:
   *   Handles the output behavior of hyenaed
   */

  /* Use default handler */
  hy_handle_output_default(
    file,
    type,
    timestamp,
    output);
} /* hy_handle_output */

/* -------------------------------------------------------------------------- */

int
  main
    (
      int argc,
      char** argv
    ) {

  /*
   * USAGE:
   *   Main function of hyenaed
   */

  int opt = 0;
  int ret = HY_ER_OK;
  int if_cnt = 0;
  char err_buf[PCAP_ERRBUF_SIZE];
  hy_daemon_t dmn;

  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Initializing");
  memset(&dmn, 0, sizeof(hy_daemon_t));
  dmn.if_n = NULL;
  strcpy(dmn.ip_addr, "127.0.0.1");
  dmn.port = 666;
  dmn.bcklog = 5;
  dmn.max_cli = 10;
  dmn.ip_v = HY_AD_T_IP_V4;
  dmn.tru_ip_lst = NULL;
  dmn.none_tru_ip_lst = NULL;
  strncpy(
    dmn.log_file,
    HY_ER_LF_FILEPATH,
    HY_DMN_LOG_FILE_BUFLEN);
  if ((ret = hy_initialize()) != HY_ER_OK) {
    hy_output(
      stdout,
      HY_OUT_T_ERROR,
      0,
      "%s",
      hy_get_error_msg(ret));
    return -1;
  }
  while ((opt = getopt(argc, argv, "i:I:a:p:b:A:c:u:m:t:T:k:f:lV")) != -1) {
    switch (opt) {
      case 'i':
        dmn.if_n = malloc(strlen(optarg) + 1);
        memset(dmn.if_n, 0, strlen(optarg) + 1);
        strncpy(dmn.if_n, optarg, strlen(optarg));
        break;
      case 'I':
        if (dmn.if_n != NULL) {
          free(dmn.if_n);
          dmn.if_n = NULL;
        }
        if ((ret =
               hy_get_if_name_by_index(
                 atoi(optarg),
                 &dmn.if_n)) != HY_ER_OK) {
          hy_output(
            stdout,
            HY_OUT_T_ERROR,
            0,
            "%s",
            hy_get_error_msg(ret));
          return -1;
        }
        break;
      case 'a':
        if (strlen(optarg) > HY_ER_AD_BUFLEN_EXCEED) {
          hy_output(
            stdout,
            HY_OUT_T_ERROR,
            0,
            "%s",
            hy_get_error_msg(HY_ER_AD_BUFLEN_EXCEED));
        }
        strncpy(dmn.ip_addr, optarg, strlen(optarg));
        break;
      case 'p':
        dmn.port = atoi(optarg);
        break;
      case 'b':
        dmn.bcklog = atoi(optarg);
        break;
      case 'A':
        dmn.ip_v = atoi(optarg);
        break;
      case 'c':
        dmn.cli_pkt_lmt = atol(optarg);
        break;
      case 'u':
        dmn.cli_dur_lmt = atol(optarg);
        break;
      case 'm':
        dmn.max_cli = atoi(optarg);
        break;
      case 'k':
        if (strlen(optarg) > HY_MAX_PWD_LEN) {
          hy_output(
            stdout,
            HY_OUT_T_ERROR,
            0,
            "%s",
            hy_get_error_msg(HY_ER_PWD_BUFLEN_EXCEED));
          return -1;
        }
        strncpy(dmn.pwd, optarg, HY_MAX_PWD_LEN);
        break;
      case 't':
        hy_output(
          stdout,
          HY_OUT_T_TASK,
          0,
          "Loading IP list (trusted)");
        if (dmn.tru_ip_lst != NULL) {
          free(dmn.tru_ip_lst);
        }
        if ((ret =
               hy_load_ip_list(
                 optarg, &dmn.tru_ip_lst)) != HY_ER_OK) {
          hy_output(
            stdout,
            HY_OUT_T_ERROR,
            0,
            "%s",
            hy_get_error_msg(ret));
          return -1;
        }
        break;
      case 'T':
        hy_output(
          stdout,
          HY_OUT_T_TASK,
          0,
          "Loading IP list (none-trusted)");
        if (dmn.none_tru_ip_lst != NULL) {
          free(dmn.none_tru_ip_lst);
        }
        if ((ret =
               hy_load_ip_list(
                 optarg, &dmn.none_tru_ip_lst)) != HY_ER_OK) {
          hy_output(
            stdout,
            HY_OUT_T_ERROR,
            0,
            "%s",
            hy_get_error_msg(ret));
          return -1;
        }
        break;
      case 'f':
        if (strlen(optarg) > HY_DMN_LOG_FILE_BUFLEN) {
          hy_output(
            stdout,
            HY_OUT_T_ERROR,
            0,
            "%s",
            hy_get_error_msg(HY_ER_DMN_LOG_FILE_BUFLEN_EXCEED));
          return -1;
        }
        memset(dmn.log_file, 0, HY_DMN_LOG_FILE_BUFLEN);
          strncpy(
          dmn.log_file,
          optarg,
          HY_DMN_LOG_FILE_BUFLEN);
        break;
      case 'l':
        if ((ret =
               hy_print_if_list(
                 &if_cnt,
                 0)) != HY_ER_OK) {
          hy_output(
            stdout,
            HY_OUT_T_ERROR,
            0,
            "%s",
            hy_get_error_msg(ret));
          return -1;
        }
        return 0;
      case 'V':
        printf(
          "\n%s Daemon v%s\nCopyright (C) %s\n\nContact  : %s\nHomepage : %s\n\n",
          PACKAGE_NAME,
          PACKAGE_VERSION,
          HY_COPYRIGHT,
          HY_CONTACT,
          HY_HOMEPAGE);
        return 0;
      default:
        printf(
          "usage: hyenaed [-i if-n] [-I if-i] [-a bind-ip] [-p port] [-b bcklog]\n"
          "               [-t tru-ip-lst] [-T none-tru-ip-lst] [-A ip-v]\n"
          "               [-c cli-pkt-lmt] [-u cli-dur-lmt] [-m max-cl]\n"
          "               [-k pwd] [-flV]\n");
        return -1;
    }
  }
  if (dmn.if_n == NULL) {
    hy_output(
      stdout,
      HY_OUT_T_ERROR,
      0,
      "No network interface given");
    return -1;
  }
  ret = hy_start_daemon(&dmn);
  if (ret != HY_ER_OK) {
    hy_output(
      stdout,
      HY_OUT_T_ERROR,
      0,
      "%s",
      hy_get_error_msg(ret));
    return -1;
  }
  return 0;
} /* main */

/* -------------------------------------------------------------------------- */
