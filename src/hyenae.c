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

#include "hyenae.h"

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
   *   of Hyenae.
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
   *   of Hyenae during an attack.
   */

  int stop_msg_init = 0;

  while (1) {
    fflush(stdin);
    if (params->run_stat == HY_RUN_STAT_STOPPED) {
      break;
    }
    if (params->run_stat == HY_RUN_STAT_RUNNING) {
      if (stop_msg_init == 0) {
        printf("\n  Press any key to stop\n\n");
        stop_msg_init = 1;
      }
      if (hy_was_key_pressed() != 0) {
        params->run_stat = HY_RUN_STAT_REQUESTED_STOP;
      }
    }
  }
} /* hy_handle_attack_blocking */

/* -------------------------------------------------------------------------- */

int
  hy_parse_ppoe_discover_code
    (
      unsigned int* code,
      char* code_string
    ) {

  /*
   * USAGE:
   *   Parses the given PPPoE-Discover
   *   code string and applies it to the
   *   given integer buffer.
   */

  int ret = HY_ER_OK;
  int len = strlen(code_string);

  if (strcmp(hy_str_to_lower(
               (char*) code_string,
               len),
               "padi") == 0) {
    *code = HY_PPPOE_CODE_PADI;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "padt") == 0) {
    *code = HY_PPPOE_CODE_PADT;
  } else {
    ret = HY_ER_PPPOE_CODE_UNKNOWN;
  }
  return ret;
} /* hy_parse_ppoe_discover_code */

/* -------------------------------------------------------------------------- */

int
  hy_parse_icmp_unreach_code
    (
      unsigned int* code,
      char* code_string
    ) {

  /*
   * USAGE:
   *   Parses the given ICMP "Destination
   *   Unreachable" code string and applies
   *   it to the given integer buffer.
   */

  int ret = HY_ER_OK;
  int len = strlen(code_string);

  if (strcmp(
        hy_str_to_lower(
          code_string,
          len),
        "network") == 0) {
    *code = ICMP_UNREACH_NET;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "host") == 0) {
    *code = ICMP_UNREACH_HOST;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "protocol") == 0) {
    *code = ICMP_UNREACH_PROTO;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "port") == 0) {
    *code = ICMP_UNREACH_PORT;
  } else {
    ret = HY_ER_ICMP_UNR_CODE_UNKNOWN;
  }
  return ret;
} /* hy_parse_icmp_unreach_code */

/* -------------------------------------------------------------------------- */

int
  hy_parse_hsrp_state_code
    (
      unsigned int* code,
      char* code_string
    ) {

  /*
   * USAGE:
   *   Parses the given HSRP state code
   *   string and applies it to the
   *   given integer buffer.
   */

  int ret = HY_ER_OK;
  int len = strlen(code_string);

  if (strcmp(
        hy_str_to_lower(
          code_string,
          len),
        "init") == 0) {
    *code = HY_HSRP_STATE_INIT;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "learn") == 0) {
    *code = HY_HSRP_STATE_LEARN;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "listen") == 0) {
    *code = HY_HSRP_STATE_LISTEN;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "speak") == 0) {
    *code = HY_HSRP_STATE_SPEAK;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "standby") == 0) {
    *code = HY_HSRP_STATE_STANDBY;
  } else if (strcmp(
                hy_str_to_lower(
                  (char*) code_string,
                  len),
                "active") == 0) {
    *code = HY_HSRP_STATE_ACTIVE;
  } else {
    ret = HY_ER_HSRP_CODE_UNKNOWN;
  }
  return ret;
} /* hy_parse_hsrp_state_code */

/* -------------------------------------------------------------------------- */

int
  hy_parse_tcp_flags
    (
      unsigned int* tcp_flags,
      const char* tcp_flags_string
    ) {

  /*
   * USAGE:
   *   Parses the given TCP flag string and
   *   applies all occuring flags to the given
   *   integer buffer.
   */

  int i = 0;
  int c = 0;

  *tcp_flags = 0;
  while (i  < strlen(tcp_flags_string)) {
    c = *(tcp_flags_string + i);
    if (c == 'f' || c == 'F') {
      *tcp_flags = *tcp_flags + TH_FIN;
    } else if (c == 's' || c == 'S') {
      *tcp_flags = *tcp_flags + TH_SYN;
    } else if (c == 'r' || c == 'R') {
      *tcp_flags = *tcp_flags + TH_RST;
    } else if (c == 'p' || c == 'P') {
      *tcp_flags = *tcp_flags + TH_PUSH;
    } else if (c == 'a' || c == 'A') {
      *tcp_flags = *tcp_flags + TH_ACK;
    } else {
      return HY_ER_TCP_FLG_UNKNOWN;
    }
    i = i + 1;
  }
  return HY_ER_OK;
} /* hy_parse_tcp_flags */

/* -------------------------------------------------------------------------- */

int
  main
    (
      int argc,
      char** argv
    ) {

  /*
   * USAGE:
   *   Main function of hyenae
   */

  int opt = 0;
  int ret = HY_ER_OK;
  int if_i = -1;
  int if_cnt = 0;
  int exec_att = 0;
  char* if_n = NULL;
  char* fin_line = NULL;
  hy_attack_t att;
  hy_attack_result_t res;
  hy_server_list_t* srv_lst = NULL;

  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Initializing");
  hy_init_attack_params(&att);
  if ((ret = hy_initialize()) != HY_ER_OK) {
    hy_output(
      stdout,
      HY_OUT_T_ERROR,
      0,
      "%s",
      hy_get_error_msg(ret));
    return -1;
  }
  if (argc == 1) {
    if ((ret =
           hy_assistant_start(
             &if_i,
             &srv_lst,
             &att,
             &exec_att)) != HY_ER_OK) {
      hy_output(
        stdout,
        HY_OUT_T_ERROR,
        0,
        "%s",
        hy_get_error_msg(ret));
      return -1;
    }
    if (exec_att == 0) {
      return 0;
    }
  } else {
        /* Proccess command line arguments */
    while ((opt =
              getopt(
                argc,
                argv,
                "s:d:S:D:i:I:r:R:a:A:t:o:f:k:w:q:Q:y:h:z:g:c:C:e:E:u:U:p:P:mNlLXV")) != -1) {
      switch (opt) {
        case 's':
          if (strlen(optarg) > HY_PT_BUFLEN) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "%s",
              hy_get_error_msg(HY_ER_PT_BUFLEN_EXCEED));
            return -1;
          }
          strncpy(att.src_pat.src, optarg, HY_PT_BUFLEN);
          break;
        case 'd':
          if (strlen(optarg) > HY_PT_BUFLEN) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "%s",
              hy_get_error_msg(HY_ER_PT_BUFLEN_EXCEED));
            return -1;
          }
          strncpy(att.dst_pat.src, optarg, HY_PT_BUFLEN);
          break;
        case 'S':
          if (strlen(optarg) > HY_PT_BUFLEN) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "%s",
              hy_get_error_msg(HY_ER_PT_BUFLEN_EXCEED));
            return -1;
          }
          strncpy(att.sec_src_pat.src, optarg, HY_PT_BUFLEN);
          break;
        case 'D':
          if (strlen(optarg) > HY_PT_BUFLEN) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "%s",
              hy_get_error_msg(HY_ER_PT_BUFLEN_EXCEED));
            return -1;
          }
          strncpy(att.sec_dst_pat.src, optarg, HY_PT_BUFLEN);
          break;
        case 'i':
          if (if_n != NULL) {
            free(if_n);
            if_n = NULL;
          }
          if_n = malloc(strlen(optarg) + 1);
          memset(if_n, 0, strlen(optarg) + 1);
          strncpy(if_n, optarg,  strlen(optarg));
          break;
        case 'I':
          if_i = atoi(optarg);
          break;
        case 'r':
          if (srv_lst != NULL) {
            free(srv_lst);
          }
          srv_lst = malloc(sizeof(hy_server_list_t));
          srv_lst->next = NULL;
          if ((ret =
                 hy_set_server_list_item(
                   optarg,
                   srv_lst)) != HY_ER_OK) {
           hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "%s",
              hy_get_error_msg(ret));
            return -1;
          }
          break;
        case 'R':
           hy_output(
              stdout,
              HY_OUT_T_TASK,
              0,
              "Loading server list");
          if (srv_lst != NULL) {
            free(srv_lst);
          }
          if ((ret =
                 hy_load_server_list(
                   optarg, &srv_lst)) != HY_ER_OK) {
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
          att.type = hy_get_attack_type_value(optarg);
          break;
        case 'A':
          att.ip_v_asm = atoi(optarg);
          break;
        case 't':
          att.ip_ttl = atoi(optarg);
          if (att.ip_ttl < 1) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "IP hop limit (TTL) can not be zero");
            return -1;
          } else if (att.ip_ttl > 255) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "IP hop limit (TTL) can not be greater than 255");
            return -1;
          }
          break;
        case 'o':
          if (att.type == HY_AT_T_PPPOE_DISCOVER) {
            if ((ret =
                   hy_parse_ppoe_discover_code(
                     &att.opcode,
                     optarg)) != HY_ER_OK) {
              hy_output(
                stdout,
                HY_OUT_T_ERROR,
                0,
                hy_get_error_msg(ret));
              return -1;
            }
          } else if (att.type == HY_AT_T_ICMP_UNREACH_TCP) {
            if ((ret =
                   hy_parse_icmp_unreach_code(
                     &att.opcode,
                     optarg)) != HY_ER_OK) {
              hy_output(
                stdout,
                HY_OUT_T_ERROR,
                0,
                hy_get_error_msg(ret));
              return -1;
            }
          } else if (att.type == HY_AT_T_HSRP_HELLO ||
                     att.type == HY_AT_T_HSRP_COUP ||
                     att.type == HY_AT_T_HSRP_RESIGN) {
            if ((ret =
                   hy_parse_hsrp_state_code(
                     &att.opcode,
                     optarg)) != HY_ER_OK) {
              hy_output(
                stdout,
                HY_OUT_T_ERROR,
                0,
                hy_get_error_msg(ret));
              return -1;
            }
          } else if (att.type == 0) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              hy_get_error_msg(HY_ER_OPCODE_WITHOUT_AT_T));
            return -1;
          }
          break;
        case 'f':
          if ((ret =
                 hy_parse_tcp_flags(
                   &att.tcp_flgs,
                   optarg)) != HY_ER_OK) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              hy_get_error_msg(ret));
            return -1;
          }
        case 'k':
          att.tcp_ack = atoi(optarg);
          break;
        case 'w':
          att.tcp_wnd = atoi(optarg);
          break;
        case 'q':
          att.seq_sid = atoi(optarg);
          break;
        case 'Q':
          att.seq_sid_ins = atoi(optarg);
          break;
        case 'y':
          strncpy(att.dns_qry, optarg, HY_DNS_QRY_BUFLEN);
          break;
        case 'h':
          if (strlen(optarg) <= HY_HSRP_AUTH_LEN) {
            strncpy(att.hsrp_auth, optarg, HY_HSRP_AUTH_LEN);
          } else {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              hy_get_error_msg(HY_ER_HSRP_AUTH_LEN_EXCEED));
            return -1;
          }
          break;
        case 'z':
          if (atoi(optarg) <= 255) {
            att.hsrp_prio = (char) atoi(optarg);
          } else {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              hy_get_error_msg(HY_ER_HSRP_MAX_PRIO_EXCEEDED));
            return -1;
          }
          break;
        case 'g':
          if (atoi(optarg) <= 255) {
            att.hsrp_group = (char) atoi(optarg);
          } else {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              hy_get_error_msg(HY_ER_HSRP_MAX_GROUP_EXCEEDED));
            return -1;
          }
          break;
        case 'c':
          att.min_cnt = atol(optarg);
          break;
        case 'C':
          att.max_cnt = atol(optarg);
          break;
        case 'e':
          att.min_del = atoi(optarg);
          if (att.type != 0) {
            if ((att.type == HY_AT_T_HSRP_HELLO ||
                 att.type == HY_AT_T_HSRP_COUP ||
                 att.type == HY_AT_T_HSRP_RESIGN) &&
                 att.min_del > 255000) {
              hy_output(
                stdout,
                HY_OUT_T_ERROR,
                0,
                hy_get_error_msg(HY_ER_HSRP_DEL_EXCEEDED));
              return -1;
            }
            break;
          } else {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              hy_get_error_msg(HY_ER_SND_DEL_WITHOUT_AT_T));
            return -1;
          }
        case 'E':
          att.max_del = atoi(optarg);
          if (att.type != 0) {
            if ((att.type == HY_AT_T_HSRP_HELLO ||
                 att.type == HY_AT_T_HSRP_COUP ||
                 att.type == HY_AT_T_HSRP_RESIGN) &&
                 att.max_del > 255000) {
              hy_output(
                stdout,
                HY_OUT_T_ERROR,
                0,
                hy_get_error_msg(HY_ER_HSRP_DEL_EXCEEDED));
              return -1;
            }
          } else {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              hy_get_error_msg(HY_ER_SND_DEL_WITHOUT_AT_T));
            return -1;
          }
          break;
        case 'u':
          att.min_dur = atol(optarg);
          break;
        case 'U':
          att.max_dur= atol(optarg);
          break;
        case 'p':
          att.pay_len = atoi(optarg);
          if (att.pay_len < 1) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "Payload length can not be zero");
            return -1;
          }
          att.pay = malloc(att.pay_len);
          hy_randomize_buffer(att.pay, att.pay_len);
          break;
        case 'P':
          hy_output(
            stdout,
            HY_OUT_T_TASK,
            0,
            "Loading payload file");
          if ((ret =
                 hy_load_file_to_buffer(
                   optarg,
                   &att.pay,
                   &att.pay_len)) != HY_ER_OK) {
            hy_output(
              stdout,
              HY_OUT_T_ERROR,
              0,
              "%s",
              hy_get_error_msg(ret));
            return -1;
          }
          break;
        case 'm':
          att.ign_mtu = 1;
          break;
        case 'N':
          att.cld_run = 1;
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
        case 'L':
          hy_print_attack_list();
          return 0;
        case 'V':
          printf(
            "\n%s v%s\nCopyright (C) %s\n\nContact  : %s\nHomepage : %s\n\n",
            PACKAGE_NAME,
            PACKAGE_VERSION,
            HY_COPYRIGHT,
            HY_CONTACT,
            HY_HOMEPAGE);
          return 0;
        default:
          printf(
            "usage: hyenae (Starts attack assistant...)\n"
            "\n"
            "       hyenae [-s src-pat] [-d dst-pat] [-S sec-src-pat] [-D sec-dst-pat]\n"
            "              [-i if-n] [-I if-i] [-r srv-pat] [-R srv-file] [-a att-type]\n"
            "              [-A ip-v-asm] [-t ip-ttl] [-o opcode] [-f tcp-flags]\n"
            "              [-k tcp-ack] [-w tcp-win] [-q seq-sid] [-Q seq-sid-ins]\n"
            "              [-y dns_qry] [-h hsrp-auth] [-z hsrp-prio] [-g hsrp-group]\n"
            "              [-c min-cnt] [-C max-cnt] [-e min-del] [-E max-del]\n"
            "              [-u min-dur] [-U max-dur] [-p rnd-payload] [-P payload-file]\n"
            "              [-mNlLV]\n"
          );
          return -1;
      }
    }
  }
  if (srv_lst == NULL) {
    /* Execute local attack */
    if (if_i != -1) {
      if ((ret =
             hy_get_if_name_by_index(
             if_i,
             &if_n)) != HY_ER_OK) {
        hy_output(
          stdout,
          HY_OUT_T_ERROR,
          0,
          "%s",
          hy_get_error_msg(ret));
        return -1;
      }
    }
    if (if_n == NULL) {
      hy_output(
        stdout,
        HY_OUT_T_ERROR,
        0,
        "No network interface given");
      return -1;
    }
    hy_local_attack(if_n, &att, &res);
    ret = res.ret;
    if (ret != HY_ER_OK) {
      hy_output(
        stdout,
        HY_OUT_T_ERROR,
        0,
        "%s",
        hy_get_error_msg(ret));
    }
    fin_line =
      hy_get_attack_result_string(&res);
    hy_output(
      stdout,
      HY_OUT_T_FINISHED,
      0,
      "%s",
      fin_line);
  } else {
    /* Execute remote attack */
    hy_send_remote_attack_request(&att, srv_lst, &res);
    ret = res.ret;
    if (ret != HY_ER_OK) {
      hy_output(
        stdout,
        HY_OUT_T_ERROR,
        0,
        "%s",
        hy_get_error_msg(ret));
    }
    fin_line =
      hy_get_attack_result_string(&res);
    hy_output(
      stdout,
      HY_OUT_T_FINISHED,
      0,
      "%s",
      fin_line);
  }
  if (fin_line != NULL) {
    free(fin_line);
  }
  if (ret != HY_ER_OK) {
    return -1;
  }
  return 0;
} /* main */

/* -------------------------------------------------------------------------- */
