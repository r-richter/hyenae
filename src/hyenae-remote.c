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

#include "hyenae-remote.h"

/* -------------------------------------------------------------------------- */

int
  hy_set_server_list_item
    (
      const char* address,
      hy_server_list_t* server_list
    ) {

  /*
   * USAGE:
   *   Sets a server list item by parsing the
   *   provided address pattern.
   */

  int i = 0;
  int c = 0;
  int i_pwd = 0;
  int is_pwd = 0;
  int ret = HY_ER_OK;
  char src_pat[HY_PT_BUFLEN];
  char pwd[HY_MAX_PWD_LEN];
  hy_pattern_t srv_pat;

  if (strlen(address) > HY_PT_BUFLEN) {
    return HY_ER_PT_BUFLEN_EXCEED;
  }
  /* Split address pattern and password strip  */
  memset(src_pat, 0, HY_PT_BUFLEN);
  memset(pwd, 0, HY_MAX_PWD_LEN);
  while (i < strlen(address)) {
    c = *(address + i);
    if (c == HY_SRV_PT_PWD_SC) {
      is_pwd = 1;
    } else {
      if (is_pwd == 1) {
        if ((i_pwd + 1) > HY_MAX_PWD_LEN) {
          return HY_ER_PWD_BUFLEN_EXCEED;
        }
        *(pwd + i_pwd) = c;
        i_pwd = i_pwd + 1;
      } else {
        *(src_pat + i) = c;
      }
    }
    i = i + 1;
  }
  if (is_pwd == 1 &&
      i_pwd == 0) {
    return HY_ER_EMPTY_PWD_STRIP;
  }
  if (is_pwd == 1 &&
      i_pwd < HY_MIN_PWD_LEN) {
    return HY_ER_TO_SHORT_PWD;
  }
  /* Process server address pattern */
  memset(server_list, 0, sizeof(hy_server_list_t));
  memset(&srv_pat, 0, sizeof(hy_pattern_t));
  strncpy(srv_pat.src, src_pat, HY_PT_BUFLEN);
  i = 0;
  while (i < strlen(srv_pat.src)) {
    if (*(srv_pat.src + i) == HY_PT_WCC) {
      return HY_ER_SRV_PT_WCC_PERMIT;
    }
    i = i+ 1;
  }
  if ((ret =
         hy_parse_pattern(
           &srv_pat,
           HY_AD_T_UNKNOWN)) != HY_ER_OK) {
    return ret;
  }
  if (strlen(srv_pat.ip_addr) == 0 ||
      srv_pat.port == 0) {
    return HY_ER_WRONG_PT_FMT_SRV;
  }
  strncpy(server_list->ip_addr, srv_pat.ip_addr, HY_AD_BUFLEN);
  strncpy(server_list->pwd, pwd, HY_MAX_PWD_LEN);
  server_list->ip_v = srv_pat.ip_v;
  server_list->port = srv_pat.port;
  return ret;
} /* hy_set_server_list_item */

/* -------------------------------------------------------------------------- */

int
  hy_load_server_list
    (
      const char* filename,
      hy_server_list_t** server_list
    ) {

  /*
   * USAGE:
   *   Loads a server list into the given server
   *   list structure.
   */

  int i = 0;
  int ret = HY_ER_OK;
  hy_key_list_t* key_list = NULL;
  hy_key_list_t* key = NULL;
  hy_server_list_t* cur_srv = NULL;

  if ((ret =
        hy_load_config_keys(
          filename,
          &key_list)) != HY_ER_OK) {
    return ret;
  }
  for (key = key_list; key; key = key->next) {
    if (cur_srv == NULL) {
      *server_list = malloc(sizeof(hy_server_list_t));
      memset(*server_list, 0, sizeof(hy_server_list_t));
      ((hy_server_list_t*) server_list)->next = NULL;
      cur_srv = *server_list;
    } else {
      cur_srv->next = malloc(sizeof(hy_server_list_t));
      memset(cur_srv->next, 0, sizeof(hy_server_list_t));
      cur_srv->next->next = NULL;
      cur_srv = cur_srv->next;
    }
    if (strcmp(key->key, "Server") == 0) {
      if ((ret =
             hy_set_server_list_item(
               key->value,
               cur_srv)) != HY_ER_OK) {
        return ret;
      }
    } else {
      return HY_ER_UNKNOWN_SL_KEY;
    }
  }
  return ret;
} /* hy_load_server_list */

/* -------------------------------------------------------------------------- */

void
  hy_send_remote_attack_request
    (
      hy_attack_t* attack,
      hy_server_list_t* server_list,
      hy_attack_result_t* result
    ) {

  /*
   * USAGE:
   *   Sends a remote attack request to one
   *   or more hyenae servers, defined
   *   in the given the server file.
   */

  int i = 0;
  int val = 0;
  int rcv_len = 0;
  int snd_buf_len = 0;
  int rcv_buf_len = sizeof(hy_ra_handshake_t);
  unsigned long dur_start = 0;
  unsigned long dur_end = 0;
  hy_server_list_t* srv = NULL;
  char* fin_line = NULL;
  unsigned char* rcv_buf = NULL;
  unsigned char* snd_buf = NULL;
  sockaddr_in_t sa_in;
  sockaddr_in6_t sa_in6;
  hy_socket_list_t* sock_lst = NULL;
  hy_socket_list_t* sock = NULL;
  timeval_t tval;
  hy_ra_handshake_t ra_hs;
  hy_attack_result_t* res_tmp;
  #ifdef OS_WINDOWS
    WSADATA wsaData;
  #endif /* OS_WINDOWS */

  memset(result, 0, sizeof(hy_attack_result_t));
  result->ret = HY_ER_OK;
  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Launching remote attack");
  if (attack->cld_run == 1) {
    hy_output(
      stdout,
      HY_OUT_T_NOTE,
      0,
      "This is a cold run, no data will be sent");
  }
  #ifdef OS_WINDOWS
    #ifndef WSA_STARTUP
      #define WSA_STARTUP
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
      result->ret = HY_ER_WSA_STARTUP;
      return;
    }
    #endif /* WSA_STARTUP */
  #endif /* OS_WINDOWS */
  /* Set receive timeout value */
  memset(&tval, 0, sizeof(timeval_t));
  #ifdef OS_WINDOWS
    tval.tv_sec = HY_RA_RCV_TIMEOUT * 1000;
  #else
    tval.tv_sec = HY_RA_RCV_TIMEOUT;
  #endif /* OS_WINDOWS */
  /* Initialize receive buffer */
  rcv_buf = malloc(rcv_buf_len);
  /* Build remote attack request packet (send buffer) */
  if ((result->ret =
         hy_build_remote_attack_request(
           attack,
           &snd_buf)) != HY_ER_OK) {
    return;
  }
  snd_buf_len = sizeof(hy_ra_request_h_t) + attack->pay_len;
  dur_start = hy_get_milliseconds_of_day();
  for (srv = server_list; srv; srv = srv->next) {
    hy_output(
      stdout,
      HY_OUT_T_TASK,
      0,
      "Acquiring daemon on %s%c%i",
      srv->ip_addr,
      HY_PT_EOA_IP,
      srv->port);
    if (sock_lst == NULL) {
      sock_lst = malloc(sizeof(hy_socket_list_t));
      memset(sock_lst, 0, sizeof(hy_socket_list_t));
      sock_lst->next = NULL;
      sock = sock_lst;
    } else {
      if (sock->s != 0) {
        sock->next = malloc(sizeof(hy_socket_list_t));
        memset(sock->next, 0, sizeof(hy_socket_list_t));
        sock->next->next = NULL;
        sock = sock->next;
      }
    }
    /* Connect to remote host */
    if (srv->ip_v == HY_AD_T_IP_V4) {
      /* IPv4 */
      if ((sock->s =
             socket(
               AF_INET,
               SOCK_STREAM,
               IPPROTO_TCP)) > 0) {
        memset(&sa_in, 0, sizeof(sockaddr_in_t));
        sa_in.sin_family = AF_INET;
        sa_in.sin_port = htons(srv->port);
        ip_pton(srv->ip_addr, (ip_addr_t*) &sa_in.sin_addr);
        val = 1;
        if (
          setsockopt(
            sock->s,
            SOL_SOCKET,
            SO_KEEPALIVE,
            (const char*) &val,
            sizeof(int)) == 0 &&
          setsockopt(
            sock->s,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (const char*) &tval,
            sizeof(timeval_t)) == 0) {
          if (connect(
                sock->s,
                (sockaddr_t*) &sa_in,
                sizeof(sockaddr_in_t)) < 0) {
            close(sock->s);
            sock->s = 0;
            hy_output(
              stdout,
              HY_OUT_T_WARNING,
              0,
              "Failed to connect");
          }
        } else {
          close(sock->s);
          sock->s = 0;
          hy_output(
            stdout,
            HY_OUT_T_WARNING,
            0,
            "Unable to set required socket options");
        }
      } else {
        sock->s = 0;
        hy_output(
          stdout,
          HY_OUT_T_WARNING,
          0,
          "Failed to create socket");
      }
    } else if (srv->ip_v == HY_AD_T_IP_V6) {
      /* IPv6 */
      if ((sock->s =
             socket(
               AF_INET6,
               SOCK_STREAM,
               IPPROTO_TCP)) > 0) {
        memset(&sa_in6, 0, sizeof(sockaddr_in6_t));
        sa_in6.sin6_family = AF_INET6;
        sa_in6.sin6_port = htons(srv->port);
        ip6_pton(srv->ip_addr, (ip6_addr_t*) &sa_in6.sin6_addr);
        val = 1;
        if (
          setsockopt(
            sock->s,
            SOL_SOCKET,
            SO_KEEPALIVE,
            (const char*) &val,
            sizeof(int)) == 0 &&
          setsockopt(
            sock->s,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (const char*) &tval,
            sizeof(timeval_t)) == 0) {
          if (connect(
                sock->s,
                (sockaddr_t*) &sa_in,
                sizeof(sockaddr_in_t)) < 0) {
            close(sock->s);
            sock->s = 0;
            hy_output(
              stdout,
              HY_OUT_T_WARNING,
              0,
              "Failed to connect");
          }
        } else {
          close(sock->s);
          sock->s = 0;
          hy_output(
            stdout,
            HY_OUT_T_WARNING,
            0,
            "Unable to set required socket options");
        }
      } else {
        sock->s = 0;
        hy_output(
          stdout,
          HY_OUT_T_WARNING,
          0,
          "Failed to create socket");
      }
    }
    /* Do remote attack handshake */
    memset(rcv_buf, 0, rcv_buf_len);
    if (sock->s != 0) {
      /* Build remote attack handshake */
      memset(&ra_hs, 0, sizeof(hy_ra_handshake_t));
      strncpy(ra_hs.ver, PACKAGE_VERSION, HY_RAH_VER_BUFLEN);
      strncpy(ra_hs.pwd, srv->pwd, HY_MAX_PWD_LEN);
      ra_hs.msg = HY_RAH_MSG_HELLO;
      /* Send handshake */
      send(sock->s, (void*) &ra_hs, sizeof(hy_ra_handshake_t), 0);
      rcv_len = recv(sock->s, (void*) rcv_buf, rcv_buf_len, 0);
      if (rcv_len == rcv_buf_len) {
        if (((hy_ra_handshake_t*) rcv_buf)->msg == HY_RAH_MSG_OK) {
          i = i + 1;
          strncpy(sock->pwd, srv->pwd, HY_MAX_PWD_LEN);
          strncpy(sock->ip_addr, srv->ip_addr, HY_AD_BUFLEN);
        } else {
          hy_shutdown_close_socket(sock->s);
          sock->s = 0;
          switch(((hy_ra_handshake_t*) rcv_buf)->msg) {
            case HY_RAH_MSG_BAD_VERSION:
              hy_output(
                stdout,
                HY_OUT_T_WARNING,
                0,
                "Bad daemon version (%s)",
                ((hy_ra_handshake_t*) rcv_buf)->ver);
              break;
            case HY_RAH_MSG_WRONG_PWD:
              hy_output(
                stdout,
                HY_OUT_T_WARNING,
                0,
                "Wrong password");
              break;
            case HY_RAH_MSG_SRV_FULL:
              hy_output(
                stdout,
                HY_OUT_T_WARNING,
                0,
                "Server is full");
              break;
            default:
              hy_output(
                stdout,
                HY_OUT_T_WARNING,
                0,
                "Unknown response message");
          }
        }
      } else {
        hy_shutdown_close_socket(sock->s);
        sock->s = 0;
        if (rcv_len < 1) {
          if (errno == EAGAIN) {
            hy_output(
              stdout,
              HY_OUT_T_WARNING,
              0,
              "Handshake failed (timeout)");
          } else {
            hy_output(
              stdout,
              HY_OUT_T_WARNING,
              0,
              "Handshake failed (receive error or timeout)");
          }
        } else {
          hy_output(
            stdout,
            HY_OUT_T_WARNING,
            0,
            "Malformed handshake");
        }
      }
    }
  }
  if (i > 0) {
    memset(rcv_buf, 0, rcv_buf_len);
    hy_output(
      stdout,
      HY_OUT_T_TASK,
      0,
      "Sending remote attack requests");
    for (sock = sock_lst; sock; sock = sock->next) {
      send(sock->s, snd_buf, snd_buf_len, 0);
    }
    hy_output(
      stdout,
      HY_OUT_T_TASK,
      0,
      "Receiving remote attack results");
    memset(result, 0, sizeof(hy_attack_result_t));
    for (sock = sock_lst; sock; sock = sock->next) {
      if (sock->s > 0) {
        hy_output(
          stdout,
          HY_OUT_T_TASK,
          0,
          "Waiting for %s",
          sock->ip_addr);
        rcv_len = recv(sock->s, (void*) rcv_buf, rcv_buf_len, 0);
        if (rcv_len > 0) {
          if (rcv_len == sizeof(hy_attack_result_t)) {
            res_tmp = (hy_attack_result_t*) rcv_buf;
            hy_output(
              stdout,
              HY_OUT_T_RESULT,
              0,
              "%s",
              hy_get_error_msg(res_tmp->ret));
            fin_line =
              hy_get_attack_result_string(res_tmp);
            hy_output(
              stdout,
              HY_OUT_T_RESULT,
              0,
              "Finished: %s",
              fin_line);
            if (fin_line != NULL) {
              free(fin_line);
            }
            result->pkt_cnt = result->pkt_cnt + res_tmp->pkt_cnt;
            result->tot_byt = result->tot_byt + res_tmp->tot_byt;
          } else {
            hy_output(
              stdout,
              HY_OUT_T_WARNING,
              0,
              "Malformed result");
          }
        } else {
          if (errno == EAGAIN) {
            hy_output(
              stdout,
              HY_OUT_T_WARNING,
              0,
              "Receive timeout");
          } else {
            hy_output(
              stdout,
              HY_OUT_T_WARNING,
              0,
              "Receive error or timeout");
          }
        }
        hy_shutdown_close_socket(sock->s);
      }
    }
  }
  /* Calculate ellapsed time */
  dur_end = hy_get_milliseconds_of_day();
  result->dur_msec = dur_end - dur_start;
  if (sock_lst != NULL) {
    hy_free_socket_list(sock_lst);
  }
  if (rcv_buf != NULL) {
    free(rcv_buf);
  }
  if (snd_buf != NULL) {
    free(snd_buf);
  }
} /* hy_send_remote_attack_request */

/* -------------------------------------------------------------------------- */

void
  hy_free_socket_list
    (
      hy_socket_list_t* socket_list
    ) {

  /*
   * USAGE:
   *   Frees a socket list.
   */

  if (socket_list->next != NULL) {
    hy_free_socket_list(socket_list->next);
    socket_list->next = NULL;
  }
  free(socket_list);
} /* hy_free_socket_list */

/* -------------------------------------------------------------------------- */
