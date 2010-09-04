/*
 * Hyenae Daemon
 *   Advanced Network Packet Generator Daemon
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
   *   Handles the output behavior
   *   of the Hyenae-Daemon.
   */

  /* Use default handler */
  hy_handle_output_default(
    file,
    type,
    timestamp,
    output);
} /* hy_handle_output */

/* -------------------------------------------------------------------------- */

void
  hy_handle_attack_blocking
    (
      hy_attack_loop_t* params
    ) {

  /*
   * USAGE:
   *   Handles the blocking behaviour
   *   of the Hyenae-Daemon during an
   *   attack.
   */

  while (1) {
    fflush(stdin);
    if (params->run_stat == HY_RUN_STAT_STOPPED) {
      break;
    }
  }
} /* hy_handle_attack_blocking */

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
  int opt_i = 0;
  int ret = HY_ER_OK;
  int if_cnt = 0;
  char err_buf[PCAP_ERRBUF_SIZE];
  hy_daemon_t dmn;

  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Initializing");
  hy_init_daemon_params(&dmn);
  if ((ret = hy_initialize()) != HY_ER_OK) {
    hy_output(
      stdout,
      HY_OUT_T_ERROR,
      0,
      "%s",
      hy_get_error_msg(ret));
    return -1;
  }
  /* Proccess command line arguments */
  while (1) {
    static struct option opts[] = {
      {"if-n", required_argument, 0, 'i'},
      {"if-i", required_argument, 0, 'I'},
      {"bind-ip", required_argument, 0, 'a'},
      {"port", required_argument, 0, 'p'},
      {"backlog", required_argument, 0, 'b'},
      {"tru-ip-lst", required_argument, 0, 't'},
      {"untru-ip-lst", required_argument, 0, 'T'},
      {"ip-v", required_argument, 0, 'A'},
      {"cli-pkt-lmt", required_argument, 0, 'c'},
      {"cli-dur-lmt", required_argument, 0, 'u'},
      {"cli-max", required_argument, 0, 'm'},
      {"pwd", required_argument, 0, 'k'},
      {"log-file", required_argument, 0, 'f'},
      {"ls-if", no_argument, 0, 'l'},
      {"version", no_argument, 0, 'V'}
    };
    opt =
      getopt_long(
        argc,
        argv,
        "i:I:a:p:b:A:c:u:m:t:T:k:f:lV",
        opts,
        &opt_i);
    if (opt == -1) {
      break;
    }
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
          "usage: hyenaed -l (Prints all available network interfaces and exits)\n"
          "\n"
          "       hyenaed -V (Prints daemon version and exits)\n"
          "\n"
          "       hyenaed -i | -I [Network interface name | index]\n"
          "               -c &| -u [Packet count limit &| Attack duration limit]\n"
          "\n"
          "               OPTIONAL:\n"
          "               -a [IP-Address to bind to]\n"
          "               -p [Port to listen on]\n"
          "               -b [Max backlog connections]\n"
          "               -t [Trusted IP-Address list file]\n"
          "               -T [Untrusted IP-Address list file]\n"
          "               -A [Assumed IP-Address version on random address strips]\n"
          "               -m [Max client connections]\n"
          "               -k [Deamon password]\n"
          "               -f [log file]\n");
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
