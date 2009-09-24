/*
 * Hyenae Daemon
 *   Advanced Network Packet Generator Daemon
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

#include "hyenaed-daemon.h"

/* -------------------------------------------------------------------------- */

void
  hy_init_daemon_params
    (
      hy_daemon_t* config
    ) {

  /*
   * USAGE:
   *   Initializes the given daemon configuration
   *   structure and applies the default values.
   */

  memset(config, 0, sizeof(hy_daemon_t));
  config->if_n = NULL;
  config->port = HY_DMN_DEF_PORT;
  config->bcklog = 5;
  config->max_cli = 10;
  config->ip_v = HY_AD_T_IP_V4;
  config->tru_ip_lst = NULL;
  config->none_tru_ip_lst = NULL;
  strncpy(
    config->log_file,
    HY_ER_LF_FILEPATH,
    HY_DMN_LOG_FILE_BUFLEN);
} /* hy_init_daemon_params */

/* -------------------------------------------------------------------------- */

int
  hy_load_ip_list
    (
      const char* filename,
      hy_ip_list_t** ip_lst
    ) {

  /*
   * USAGE:
   *   Loads an IP address list into the given
   *   IP address list structure.
   */

  int i = 0;
  int ret = HY_ER_OK;
  int ad_type = 0;
  hy_key_list_t* key_list = NULL;
  hy_key_list_t* key = NULL;
  hy_ip_list_t* cur_ip = NULL;

  if ((ret =
        hy_load_config_keys(
          filename,
          &key_list)) != HY_ER_OK) {
    return ret;
  }
  for (key = key_list; key; key = key->next) {
    if (cur_ip == NULL) {
      *ip_lst = malloc(sizeof(hy_ip_list_t));
      memset(*ip_lst, 0, sizeof(hy_ip_list_t));
      ((hy_ip_list_t*) ip_lst)->next = NULL;
      cur_ip = *ip_lst;
    } else {
      cur_ip->next = malloc(sizeof(hy_ip_list_t));
      memset(cur_ip->next, 0, sizeof(hy_ip_list_t));
      cur_ip->next->next = NULL;
      cur_ip = cur_ip->next;
    }
    if (strcmp(key->key, "IP-Address") == 0) {
      if (strlen(key->value) > HY_AD_BUFLEN) {
        return HY_ER_AD_BUFLEN_EXCEED;
      }
      ad_type =
        hy_get_address_type(key->value, strlen(key->value));
      if (ad_type == HY_AD_T_UNKNOWN ||
          (ad_type != HY_AD_T_IP_V4 &&
           ad_type != HY_AD_T_IP_V6)) {
        return HY_ER_INVALID_IP_LST_ADDR;
      }
      strncpy(cur_ip->ip_addr, key->value, HY_AD_BUFLEN);
    } else {
      return HY_ER_UNKNOWN_IP_KEY;
    }
  }
  return ret;
} /* hy_load_ip_list */

/* -------------------------------------------------------------------------- */

int
  hy_is_ip_in_list
    (
      const char* ip_address,
      hy_ip_list_t* ip_lst
    ) {

  /*
   * USAGE:
   *   Checks if the given IP address is in
   *   the provided IP list.
   */

  hy_ip_list_t* ip = NULL;

  for(ip = ip_lst; ip; ip = ip->next) {
    if (strcmp(ip_address, ip->ip_addr) == 0) {
      return 1;
    }
  }
  return 0;
} /* hy_is_ip_in_list */

/* -------------------------------------------------------------------------- */

int
  hy_start_daemon
    (
      hy_daemon_t* config
    ) {

  /*
   * USAGE:
   *   Starts a local Hyenae daemon.
   */

  int s_srv = 0;
  int s_cli = 0;
  int sa_len = 0;
  int cli_cnt = 0;
  int is_auth = 0;
  char* ip_a = NULL;
  char err_buf[PCAP_ERRBUF_SIZE];
  FILE* f = NULL;
  pcap_t* dsc = NULL;
  sockaddr_in_t sa_in;
  sockaddr_in6_t sa_in6;
  sockaddr_in_t sa_in_cli;
  sockaddr_in6_t sa_in6_cli;
  hy_handle_client_t* cli_prm;
  timeval_t tval;
  hy_ra_handshake_t ra_hs;
  #ifdef OS_WINDOWS
    long pid = 0;
    WSADATA wsaData;
    HANDLE cli_thr = NULL;
  #else
    pthread_t cli_thr;
  #endif /* OS_WINDOWS */

  memset(&ra_hs, 0, sizeof(hy_ra_handshake_t));
  memcpy(&ra_hs, PACKAGE_VERSION, HY_RAH_VER_BUFLEN);
  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Starting daemon");
  if (config->port < 1) {
    return HY_ER_PORT_ZERO;
  }
  if (config->bcklog < 1) {
    return HY_ER_BACKLOG_ZERO;
  }
  if (config->max_cli < 1) {
    return HY_ER_MAX_CL_ZERO;
  }
  if (config->cli_pkt_lmt < 1 &&
      config->cli_dur_lmt < 1) {
    return HY_ER_MAX_CL_PKT_DUR_LMT_ZERO;
  }
  if (strlen(config->pwd) > 0 &&
      strlen(config->pwd) < HY_MIN_PWD_LEN) {
    return HY_ER_TO_SHORT_PWD;
  }
  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Opening network interface (%s)",
    config->if_n);
  if ((dsc =
         pcap_open_live(
           config->if_n,
           BUFSIZ,
           0,
           0,
           err_buf)) == NULL) {
    return HY_ER_PCAP_OPEN_LIVE;
  }
  if ((f = fopen(config->log_file, "a")) == NULL) {
    return HY_ER_FOPEN_LOG_FILE;
  }
  #ifdef OS_WINDOWS
    #ifndef WSA_STARTUP
      #define WSA_STARTUP
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
      return HY_ER_WSA_STARTUP;
    }
    #endif /* WSA_STARTUP */
  #endif /* OS_WINDOWS */
  /* Set receive timeout value */
  memset(&tval, 0, sizeof(timeval_t));
  #ifdef OS_WINDOWS
    tval.tv_sec = HY_DMN_RCV_TIMEOUT * 1000;
  #else
    tval.tv_sec = HY_DMN_RCV_TIMEOUT;
  #endif /* OS_WINDOWS */
  /* Initialize */
  if (config->ip_v == HY_AD_T_IP_V4) {
    /* IPv4 */
   if ((s_srv =
          socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP)) < 0) {
      pcap_close(dsc);
      fclose(f);
      return HY_ER_SOCK_CREATE;
    }
    if (setsockopt(
          s_srv,
          SOL_SOCKET,
          SO_RCVTIMEO,
          (const char*) &tval,
          sizeof(timeval_t)) < 0) {
      pcap_close(dsc);
      close(s_srv);
      fclose(f);
      return HY_ER_SOCK_SETOPT;
    }
    memset(&sa_in, 0, sizeof(sockaddr_in_t));
    sa_in.sin_family = AF_INET;
    sa_in.sin_port = htons(config->port);
    if (strlen(config->ip_addr) > 0) {
      hy_output(
        stdout,
        HY_OUT_T_TASK,
        0,
        "Binding server to %s",
        config->ip_addr);
      ip_pton(config->ip_addr, (ip_addr_t*) &sa_in.sin_addr.s_addr);
    } else {
      sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(
          s_srv,
          (sockaddr_t*) &sa_in,
          sizeof(sockaddr_in_t)) < 0) {
      pcap_close(dsc);
      close(s_srv);
      fclose(f);
      return HY_ER_SOCK_BIND;
    }
  } else if (config->ip_v == HY_AD_T_IP_V6) {
    /* IPv6 */
   if ((s_srv =
          socket(
            AF_INET6,
            SOCK_STREAM,
            IPPROTO_TCP)) < 0) {
      pcap_close(dsc);
      fclose(f);
      return HY_ER_SOCK_CREATE;
    }
    if (setsockopt(
          s_srv,
          SOL_SOCKET,
          SO_RCVTIMEO,
          (const char*) &tval,
          sizeof(timeval_t)) < 0) {
      pcap_close(dsc);
      close(s_srv);
      fclose(f);
      return HY_ER_SOCK_SETOPT;
    }
    memset(&sa_in6, 0, sizeof(sockaddr_in6_t));
    sa_in6.sin6_family = AF_INET6;
    sa_in6.sin6_port = htons(config->port);
    if (strlen(config->ip_addr) > 0) {
      hy_output(
        stdout,
        HY_OUT_T_TASK,
        0,
        "Binding server to %s",
        config->ip_addr);
      ip6_pton(config->ip_addr, (ip6_addr_t*) &sa_in6.sin6_addr);
    } else {
      sa_in6.sin6_addr = in6addr_any;
    }
    if (bind(
          s_srv,
          (sockaddr_t*) &sa_in6,
          sizeof(sockaddr_in6_t)) < 0) {
      pcap_close(dsc);
      close(s_srv);
      fclose(f);
      return HY_ER_SOCK_BIND;
    }
  } else {
    pcap_close(dsc);
    close(s_srv);
    fclose(f);
    return HY_ER_IP_V_UNKNOWN;
  }
  if (listen(s_srv, config->bcklog) < 0) {
    pcap_close(dsc);
    close(s_srv);
    fclose(f);
    return HY_ER_SOCK_LISTEN;
  }
  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "%s Daemon v%s: Online",
    PACKAGE_NAME,
    PACKAGE_VERSION);
  hy_output(
    f,
    HY_OUT_T_TASK,
    1,
    "%s Daemon v%s: Online (%s%c%i)",
    PACKAGE_NAME,
    PACKAGE_VERSION,
    config->ip_addr,
    HY_PT_EOA_IP,
    config->port);
  /* Wait for client connections */
  while (1) {
    if (config->ip_v == HY_AD_T_IP_V4) {
      sa_len = sizeof(sockaddr_in_t);
      memset(&sa_in_cli, 0, sa_len);
      while ((s_cli =
                 accept(
                   s_srv,
                   (sockaddr_t*) &sa_in_cli,
                   (socklen_t *) &sa_len)) < 0) {
        if (errno != EAGAIN) {
          pcap_close(dsc);
          hy_shutdown_close_socket(s_srv);
          fclose(f);
          return HY_ER_SOCK_ACCEPT;
        }
      }
    } else if (config->ip_v == HY_AD_T_IP_V6) {
      sa_len = sizeof(sockaddr_in6_t);
      memset(&sa_in6_cli, 0, sa_len);
      while ((s_cli =
                 accept(
                   s_srv,
                   (sockaddr_t*) &sa_in6_cli,
                   (socklen_t *) &sa_len)) < 0) {
        if (errno != EAGAIN) {
          pcap_close(dsc);
          hy_shutdown_close_socket(s_srv);
          fclose(f);
          return HY_ER_SOCK_ACCEPT;
        }
      }
    }
    if (cli_cnt < config->max_cli) {
      cli_cnt = cli_cnt + 1;
      /* Allocate client handler parameters */
      cli_prm = malloc(sizeof(hy_handle_client_t));
      memset(cli_prm, 0, sizeof(hy_handle_client_t));
      cli_prm->s_cli = s_cli;
      cli_prm->log_f = f;
      cli_prm->pcap_dsc = dsc;
      cli_prm->cli_cnt = &cli_cnt;
      memcpy(&cli_prm->dmn_cfg, config, sizeof(hy_daemon_t));
      if (config->ip_v == HY_AD_T_IP_V4) {
        memcpy(
          &cli_prm->sa_in,
          &sa_in_cli,
          sizeof(sockaddr_in_t));
      } else if (config->ip_v == HY_AD_T_IP_V6) {
        memcpy(
          &cli_prm->sa_in6,
          &sa_in6_cli,
          sizeof(sockaddr_in6_t));
      }
      if (config->ip_v == HY_AD_T_IP_V4) {
        ip_a =
          ip_ntoa(
            (const ip_addr_t*) &sa_in_cli.sin_addr);
      } else if (config->ip_v == HY_AD_T_IP_V6) {
        ip_a =
          ip6_ntoa(
            (const ip6_addr_t*) sa_in6_cli.sin6_addr.s6_addr);
      }
      hy_output(
        f,
        HY_OUT_T_TASK,
        1,
        "Client connected from %s (Slot %i of %i)",
        ip_a,
        cli_cnt,
        config->max_cli);
      /* If a trusted IP list was provided,
         check if client is on it */
      is_auth = 0;
      if (config->tru_ip_lst == NULL ||
          hy_is_ip_in_list(ip_a, config->tru_ip_lst) == 1) {
        is_auth = 1;
      }
      /* If a none-trusted IP list was provided,
         check if client is on it */
      if (config->none_tru_ip_lst != NULL &&
          hy_is_ip_in_list(ip_a, config->none_tru_ip_lst) == 1) {
        is_auth = 0;
      }
      if (is_auth == 1) {
        /* Handle client connection */
        #ifdef OS_WINDOWS
          if ((cli_thr =
                 CreateThread(
                   NULL,
                   0,
                   hy_win32_handle_client,
                   cli_prm,
                   0,
                   &pid)) == NULL) {
            pcap_close(dsc);
            hy_shutdown_close_socket(s_srv);
            fclose(f);
            return HY_ER_CREATE_THREAD;
          }
        #else
          if (pthread_create(
                &cli_thr,
                NULL,
                hy_unix_handle_client,
                cli_prm) != 0) {
            pcap_close(dsc);
            hy_shutdown_close_socket(s_srv);
            fclose(f);
            return HY_ER_CREATE_THREAD;
          }
        #endif /* OS_WINDOWS */
      } else {
        cli_cnt = cli_cnt - 1;
        hy_shutdown_close_socket(s_cli);
        hy_output(
          f,
          HY_OUT_T_WARNING,
          1,
          "Client diconnected, not trusted (%s)",
          ip_a);
      }
    } else {
      /* Send server full message */
      ra_hs.msg = HY_RAH_MSG_SRV_FULL;
      send(s_cli, (void*) &ra_hs, sizeof(hy_ra_handshake_t), 0);
      hy_shutdown_close_socket(s_cli);
    }
  }
  pcap_close(dsc);
  hy_shutdown_close_socket(s_srv);
  fclose(f);
  return HY_ER_UNKNOWN;
} /* hy_start_daemon */

/* -------------------------------------------------------------------------- */

void
  hy_attack_to_string
    (
      hy_attack_t* attack,
      char* buffer,
      int len
    ) {

  /*
   * USAGE:
   *   Writes a loggable comparison of the given
   *   attack parameters to the given buffer.
   */

  char tmp[1024];

  memset(buffer, 0, len);
  if (strlen(attack->src_pat.src) > 0) {
    sprintf(
      buffer,
      "%s  > Source-Pattern: \"%s\"\n",
      buffer,
      attack->src_pat.src);
  } else {
    sprintf(
      buffer,
      "%s  > Source-Pattern: <empty>\n",
      buffer);
  }
  if (strlen(attack->dst_pat.src) > 0) {
    sprintf(
      buffer,
      "%s  > Destination-Pattern: \"%s\"\n",
      buffer,
      attack->dst_pat.src);
  } else {
    sprintf(
      buffer,
      "%s  > Destination-Pattern: <empty>\n",
      buffer);
  }
  if (strlen(attack->sec_src_pat.src) > 0) {
    sprintf(
      buffer,
      "%s  > Secondary Source-Pattern: \"%s\"\n",
      buffer,
      attack->sec_src_pat.src);
  } else {
    sprintf(
      buffer,
      "%s  > Secondary Source-Pattern: <empty>\n",
      buffer);
  }
  if (strlen(attack->sec_dst_pat.src) > 0) {
    sprintf(
      buffer,
      "%s  > Secondary Destination-Pattern: \"%s\"\n",
      buffer,
      attack->sec_dst_pat.src);
  } else {
    sprintf(
      buffer,
      "%s  > Secondary Destination-Pattern: <empty>\n",
      buffer);
  }
  sprintf(
    buffer,
    "%s  > Attack-Type: %s\n",
    buffer,
    hy_get_attack_name(attack->type));
  sprintf(
    buffer,
    "%s  > IP-Version-Assumption: %i\n",
    buffer,
    attack->ip_v_asm);
  if (attack->type != HY_AT_T_ARP_REQUEST &&
      attack->type != HY_AT_T_ARP_REPLY) {
    sprintf(
      buffer,
      "%s  > IP Hop Limit (TTL): %i\n",
      buffer,
      attack->ip_ttl);
  }
  if (attack->type == HY_AT_T_PPPOE_DISCOVER) {
    memset(tmp, 0, 1024);
    switch(attack->opcode) {
      case HY_PPPOE_CODE_PADI:
        strncpy(tmp, "Active Discovery Initiation (PADI)", 1024);
        break;
      case HY_PPPOE_CODE_PADT:
        strncpy(tmp, "Active Discovery Termination (PADT)", 1024);
        break;
      default:
        strncpy(tmp, "Unknown", 1024);
        break;
    }
    sprintf(
      buffer,
      "%s  > PPPoE Discover Code: %s\n",
      buffer,
      tmp);
    sprintf(
      buffer,
      "%s  > PPPoE Session ID: %li\n",
      buffer,
      attack->seq_sid);
    sprintf(
      buffer,
      "%s  > PPPoE Session ID Incr. Steps: %li\n",
      buffer,
      attack->seq_sid_ins);
  } else if (attack->type == HY_AT_T_ICMP_UNREACH_TCP) {
    memset(tmp, 0, 1024);
    switch(attack->opcode) {
      case ICMP_UNREACH_NET:
        strncpy(tmp, "Network", 1024);
        break;
      case ICMP_UNREACH_HOST:
        strncpy(tmp, "Host", 1024);
        break;
      case ICMP_UNREACH_PROTO:
        strncpy(tmp, "Protocol", 1024);
        break;
      case ICMP_UNREACH_PORT:
        strncpy(tmp, "Port", 1024);
        break;
      default:
        strncpy(tmp, "Unknown", 1024);
        break;
    }
  sprintf(
    buffer,
    "%s  > ICMP \"Destination Unreachable\" Code: %s\n",
    buffer,
    tmp);
  } else if (attack->type == HY_AT_T_HSRP_HELLO ||
             attack->type == HY_AT_T_HSRP_COUP ||
             attack->type == HY_AT_T_HSRP_RESIGN) {
    memset(tmp, 0, 1024);
    switch(attack->opcode) {
      case HY_HSRP_STATE_INIT:
        strncpy(tmp, "Init", 1024);
        break;
      case HY_HSRP_STATE_LEARN:
        strncpy(tmp, "Learn", 1024);
        break;
      case HY_HSRP_STATE_LISTEN:
        strncpy(tmp, "Listen", 1024);
        break;
      case HY_HSRP_STATE_SPEAK:
        strncpy(tmp, "Speak", 1024);
        break;
      case HY_HSRP_STATE_STANDBY:
        strncpy(tmp, "Standby", 1024);
        break;
      case HY_HSRP_STATE_ACTIVE:
        strncpy(tmp, "Active", 1024);
        break;
      default:
        strncpy(tmp, "Unknown", 1024);
        break;
    }
  sprintf(
    buffer,
    "%s  > HSRP State Code: %s\n",
    buffer,
    tmp);
  }
  if (strlen(attack->hsrp_auth) > 0) {
    sprintf(
      buffer,
      "%s  > HSRP Auth. Data: %s\n",
      buffer,
      attack->hsrp_auth);
  } else {
    sprintf(
      buffer,
      "%s  > HSRP Auth. Data: <Default>\n",
      buffer);
  }
  sprintf(
    buffer,
    "%s  > HSRP Priority: %i\n",
    buffer,
    attack->hsrp_prio);
  sprintf(
    buffer,
    "%s  > HSRP Group Number: %i\n",
    buffer,
    attack->hsrp_group);
  if (attack->type == HY_AT_T_DNS_QUERY) {
    sprintf(
      buffer,
      "%s  > DNS-Queries: %s\n",
      buffer,
      attack->dns_qry);
  }
  if (attack->type == HY_AT_T_TCP ||
      attack->type == HY_AT_T_ICMP_UNREACH_TCP) {
    sprintf(
      buffer,
      "%s  > TCP Seq. Number: %li\n",
      buffer,
      attack->seq_sid);
    sprintf(
      buffer,
      "%s  > TCP Seq. Number Incr. Steps: %li\n",
      buffer,
      attack->seq_sid_ins);
    sprintf(
      buffer,
      "%s  > TCP Ack. Number: %li\n",
      buffer,
      attack->tcp_ack);
    if (attack->type == HY_AT_T_TCP) {
      memset(tmp, 0, 1024);
      if (attack->tcp_flgs & TH_FIN) {
        strcat(tmp, "FIN ");
      }
      if (attack->tcp_flgs & TH_SYN) {
        strcat(tmp, "SYN ");
      }
      if (attack->tcp_flgs & TH_RST) {
        strcat(tmp, "RST ");
      }
      if (attack->tcp_flgs & TH_PUSH) {
        strcat(tmp, "PSH ");
      }
      if (attack->tcp_flgs & TH_ACK) {
        strcat(tmp, "ACK ");
      }
      sprintf(
        buffer,
        "%s  > TCP-Flags: %s\n",
        buffer,
        tmp);
      sprintf(
        buffer,
        "%s  > TCP Window Size: %i\n",
        buffer,
        attack->tcp_wnd);
    }
  }
  sprintf(
    buffer,
    "%s  > Min-Count: %li\n",
    buffer,
    attack->min_cnt);
  sprintf(
    buffer,
    "%s  > Max-Count: %li\n",
    buffer,
    attack->max_cnt);
  sprintf(
    buffer,
    "%s  > Min-Delay: %i\n",
    buffer,
    attack->min_del);
  sprintf(
    buffer,
    "%s  > Max-Delay: %i\n",
    buffer,
    attack->max_del);
  sprintf(
    buffer,
    "%s  > Min-Duration: %li\n",
    buffer,
    attack->min_dur);
  sprintf(
    buffer,
    "%s  > Max-Duration: %li\n",
    buffer,
    attack->max_dur);
  sprintf(
    buffer,
    "%s  > Payload length: %i\n",
    buffer,
    attack->pay_len);
  if (attack->ign_mtu == 1) {
    sprintf(
      buffer,
      "%s  > Ignore MTU limit: Yes\n",
      buffer);
  } else {
    sprintf(
      buffer,
      "%s  > Ignore MTU limit: No\n",
      buffer);
  }
  if (attack->cld_run == 1) {
    sprintf(
      buffer,
      "%s  > Cold Run: Yes",
      buffer);
  } else {
    sprintf(
      buffer,
      "%s  > Cold Run: No",
      buffer);
  }
} /* hy_attack_to_string */

/* -------------------------------------------------------------------------- */

/* Win32 and UNIX thread functions to handle
 * client connections, these functions only
 * delegate their parameters to hy_handle_client
 */

#ifdef OS_WINDOWS
  DWORD WINAPI
    hy_win32_handle_client
    (
      LPVOID params
    ) {

    hy_handle_client((hy_handle_client_t*) params);
    return 0;
  } /* hy_win32_handle_client */
#else
  void*
    hy_unix_handle_client
      (
        void* params
      ) {

    hy_handle_client((hy_handle_client_t*) params);
    return 0;
  } /* hy_unix_handle_client */
#endif /* OS_WINDOWS */

/* -------------------------------------------------------------------------- */

void
  hy_handle_client
    (
      hy_handle_client_t* params
    ) {

  /*
   * USAGE:
   *   Handles a client connection.
   */

  int hs_recv = 0;
  int rcv_len = 0;
  char* fin_line = NULL;
  unsigned char buf[HY_MAX_RA_PKT_LEN];
  char* ip_a = NULL;
  char att_log_buf[10000];
  hy_ra_handshake_t* ra_hs = NULL;
  hy_attack_result_t res;
  hy_attack_t* att = NULL;

  res.ret = HY_ER_OK;
  if (params->dmn_cfg.ip_v == HY_AD_T_IP_V4) {
    ip_a =
      ip_ntoa(
        (const ip_addr_t*) &params->sa_in.sin_addr);
  } else if (params->dmn_cfg.ip_v == HY_AD_T_IP_V6) {
    ip_a =
      ip6_ntoa(
        (const ip6_addr_t*) params->sa_in6.sin6_addr.s6_addr);
  }
  while (1) {
    memset(buf, 0, HY_MAX_RA_PKT_LEN);
    rcv_len =
      recv(
        params->s_cli,
        buf,
        HY_MAX_RA_PKT_LEN,
        0);
    if (rcv_len < 1) {
      if (errno == EAGAIN) {
        hy_output(
          params->log_f,
          HY_OUT_T_ERROR,
          1,
          "Receive timeout (%s)",
          ip_a);
      } else {
        hy_output(
          params->log_f,
          HY_OUT_T_ERROR,
          1,
          "Receive error or timeout (%s)",
          ip_a);
      }
      break;
    }
    if (rcv_len == sizeof(hy_ra_handshake_t)) {
      /* Assume handshake */
      ra_hs = (hy_ra_handshake_t*) buf;
      /* Check version */
      if (strcmp(ra_hs->ver, PACKAGE_VERSION) == 0) {
        /* Check password */
        if (strlen(params->dmn_cfg.pwd) == 0 ||
            strcmp(ra_hs->pwd, params->dmn_cfg.pwd) == 0) {
          hy_output(
            params->log_f,
            HY_OUT_T_TASK,
            1,
            "RA-Handshake OK (%s)",
            ip_a);
          ra_hs->msg = HY_RAH_MSG_OK;
        } else {
          hy_output(
            params->log_f,
            HY_OUT_T_ERROR,
            1,
            "Wrong password (%s)",
            ip_a);
          ra_hs->msg = HY_RAH_MSG_WRONG_PWD;
        }
      } else {
        hy_output(
          params->log_f,
          HY_OUT_T_ERROR,
          1,
          "Bad client version (%s)",
          ip_a);
        ra_hs->msg = HY_RAH_MSG_BAD_VERSION;
      }
      memcpy(ra_hs->ver, PACKAGE_VERSION, HY_RAH_VER_BUFLEN);
      send(params->s_cli, buf, sizeof(hy_ra_handshake_t), 0);
      if (ra_hs->msg == HY_RAH_MSG_BAD_VERSION) {
        break;
      }
      hs_recv = 1;
    } else if (rcv_len >= sizeof(hy_attack_t)) {
      /* Assume remote attack request */
      if (hs_recv != 1) {
        hy_output(
          params->log_f,
          HY_OUT_T_ERROR,
          1,
          "RA-Request without handshake (%s)",
          ip_a);
        break;
      }
      /* Log attack parameters */
      if ((res.ret =
             hy_parse_remote_attack_request_buffer(
               buf,
               rcv_len,
               &att)) == HY_ER_OK) {
        hy_attack_to_string(att, att_log_buf, 10000);
        hy_output(
          params->log_f,
          HY_OUT_T_TASK,
          1,
          "Received RA-Request (%s)\n%s",
          ip_a,
          att_log_buf);
      } else {
        hy_output(
          params->log_f,
          HY_OUT_T_ERROR,
          1,
          "%s (%s)",
          hy_get_error_msg(res.ret),
          ip_a);
        break;
      }
      /* Prevent endless loops */
      if (att->min_cnt < 1) {
        att->min_cnt = params->dmn_cfg.cli_pkt_lmt;
      }
      if (att->min_dur < 1) {
        att->min_dur = params->dmn_cfg.cli_dur_lmt;
      }
      /* Check packet limit */
      if (params->dmn_cfg.cli_pkt_lmt > 0 &&
          (att->min_cnt > params->dmn_cfg.cli_pkt_lmt ||
           att->max_cnt > params->dmn_cfg.cli_pkt_lmt)) {
        res.ret = HY_ER_CLI_PKT_LMT_EXCEED;
      } else {
        /* Check duration limit */
        if (params->dmn_cfg.cli_dur_lmt > 0 &&
            (att->min_dur > params->dmn_cfg.cli_dur_lmt ||
             att->max_dur > params->dmn_cfg.cli_dur_lmt)) {
          res.ret = HY_ER_CLI_DUR_LMT_EXCEED;
        } else {
          hy_output(
            params->log_f,
            HY_OUT_T_TASK,
            1,
            "Executing attack (%s)",
            ip_a);
          hy_attack(att, params->pcap_dsc, 1, &res);
        }
      }
      if (res.ret != HY_ER_OK) {
        hy_output(
          params->log_f,
          HY_OUT_T_ERROR,
          1,
          "%s (%s)",
          hy_get_error_msg(res.ret),
          ip_a);
      }
      fin_line =
        hy_get_attack_result_string(&res);
      hy_output(
        params->log_f,
        HY_OUT_T_TASK,
        1,
        "Remote attack for %s finished: %s",
        ip_a,
        fin_line);
      if (fin_line != NULL) {
        free(fin_line);
      }
      hy_output(
        params->log_f,
        HY_OUT_T_TASK,
        1,
        "Sending result (%s)",
        ip_a);
      send(params->s_cli, (char*) &res, sizeof(hy_attack_result_t), 0);
      break;
    } else {
      hy_output(
        params->log_f,
        HY_OUT_T_ERROR,
        1,
        "Malformed transmission (%s)",
        ip_a);
    }
  }
  hy_shutdown_close_socket(params->s_cli);
  *params->cli_cnt = *params->cli_cnt - 1;
  hy_output(
    params->log_f,
    HY_OUT_T_TASK,
    1,
    "Client %s disconnected",
    ip_a);
  if (att != NULL) {
    free(att);
  }
  free(params);
} /* hy_handle_client */

/* -------------------------------------------------------------------------- */
