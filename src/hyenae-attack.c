/*
 * Hyenae
 *   Advanced Network Packet Generator
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

#include "hyenae-attack.h"

/* -------------------------------------------------------------------------- */

void
  hy_init_attack_params
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Initializes the given attack parameter
   *   structure and applies the default values.
   */

  memset(attack, 0, sizeof(hy_attack_t));
  attack->ip_v_asm = HY_AD_T_IP_V4;
  attack->ip_ttl = 128;
  attack->pay = NULL;
  attack->icmp_unr_code = ICMP_UNREACH_NET;
  attack->pppoe_disc_code = HY_PPPOE_CODE_PADI;
  attack->hsrp_state_code = HY_HSRP_STATE_INIT;
} /* hy_init_attack_params */

/* -------------------------------------------------------------------------- */

int
  hy_get_attack_type_value
    (
      const char* name
    ) {

  /*
   * USAGE:
   *   Returns the type value of the given attack name.
   */

  if (strcmp(name, "arp-request") == 0) {
    return HY_AT_T_ARP_REQUEST;
  } else if (strcmp(name, "arp-reply") == 0) {
    return HY_AT_T_ARP_REPLY;
  } else if (strcmp(name, "pppoe-discover") == 0) {
    return HY_AT_T_PPPOE_DISCOVER;
  } else if (strcmp(name, "icmp-echo") == 0) {
    return HY_AT_T_ICMP_ECHO;
  } else if (strcmp(name, "icmp-unreach-tcp") == 0) {
    return HY_AT_T_ICMP_UNREACH_TCP;
  } else if (strcmp(name, "tcp") == 0) {
    return HY_AT_T_TCP;
  } else if (strcmp(name, "udp") == 0) {
    return HY_AT_T_UDP;
  } else if (strcmp(name, "dns-query") == 0) {
    return HY_AT_T_DNS_QUERY;
  } else if (strcmp(name, "dhcp-discover") == 0) {
    return HY_AT_T_DHCP_DISCOVER;
  } else if (strcmp(name, "dhcp-request") == 0) {
    return HY_AT_T_DHCP_REQUEST;
  } else if (strcmp(name, "dhcp-release") == 0) {
    return HY_AT_T_DHCP_RELEASE;
  } else if (strcmp(name, "hsrp-hello") == 0) {
    return HY_AT_T_HSRP_HELLO;
  } else if (strcmp(name, "hsrp-coup") == 0) {
    return HY_AT_T_HSRP_COUP;
  } else if (strcmp(name, "hsrp-resign") == 0) {
    return HY_AT_T_HSRP_RESIGN;
  }
  return HY_AT_T_UNKNOWN;
} /* hy_get_attack_type_value */

/* -------------------------------------------------------------------------- */

const char*
  hy_get_attack_name
    (
      int type
    ) {

  /*
   * USAGE:
   *   Returns the name of the given attack type.
   */

  switch(type) {
    case HY_AT_T_ARP_REQUEST:
      return "arp-request";
    case HY_AT_T_ARP_REPLY:
      return "arp-reply";
    case HY_AT_T_PPPOE_DISCOVER:
      return "pppoe-discover";
    case HY_AT_T_ICMP_ECHO:
      return "icmp-echo";
    case HY_AT_T_ICMP_UNREACH_TCP:
      return "icmp-unreach-tcp";
    case HY_AT_T_TCP:
      return "tcp";
    case HY_AT_T_UDP:
      return "udp";
    case HY_AT_T_DNS_QUERY:
      return "dns-query";
    case HY_AT_T_DHCP_DISCOVER:
      return "dhcp-discover";
    case HY_AT_T_DHCP_REQUEST:
      return "dhcp-request";
    case HY_AT_T_DHCP_RELEASE:
      return "dhcp-release";
    case HY_AT_T_HSRP_HELLO:
      return "hsrp-hello";
    case HY_AT_T_HSRP_COUP:
      return "hsrp-coup";
    case HY_AT_T_HSRP_RESIGN:
      return "hsrp-resign";
    default:
      return "Unknown";
  }
} /* hy_get_attack_name */

/* -------------------------------------------------------------------------- */

char*
  hy_get_attack_result_string
    (
      hy_attack_result_t* result
    ) {

  /*
   * USAGE:
   *   Returns a string containing a result
   *   comparison based on the given attack
   *   results.
   */

  unsigned long sec = 0;
  unsigned long msec = 0;
  char* ret = NULL;

  ret = malloc(HY_RES_LINE_BUFLEN);
  memset(ret, 0, HY_RES_LINE_BUFLEN);
  if (!(result->tc_flg & HY_TC_PKT_CNT)) {
    sprintf(ret, "%li packets sent ", result->pkt_cnt);
    if (!(result->tc_flg & HY_TC_TOT_BYT)) {
      sprintf(ret, "%s(%li bytes) ", ret, result->tot_byt);
    }
  }
  if (result->dur_msec > 0) {
    sec = result->dur_msec / 1000;
    msec = result->dur_msec - (sec * 1000);
    sprintf(
      ret,
      "%sin %li.%li seconds",
      ret,
      sec,
      msec);
  } else {
    sprintf(
      ret,
      "%sin less than 0.1 seconds",
      ret);
  }
  return ret;
} /* hy_get_attack_result_string */

/* -------------------------------------------------------------------------- */

void
  hy_attack
    (
      hy_attack_t* attack,
      pcap_t* pcap_dsc,
      int is_remote_call,
      hy_attack_result_t* result
    ) {

  /*
   * USAGE:
   *   Executes the given attack.
   */

  hy_attack_loop_t prm;
  #ifdef OS_WINDOWS
    long pid = 0;
    HANDLE thr = NULL;
  #else
    pthread_t thr;
  #endif /* OS_WINDOWS */

  prm.pkt_lmt = 0;
  prm.dsc = pcap_dsc;
  prm.att = attack;
  prm.res = result;
  prm.pkt_buf = NULL;
  prm.run_stat = HY_RUN_STAT_RUNNING;
  result->ret = HY_ER_OK;
  if (is_remote_call == 0) {
    hy_output(
      stdout,
      HY_OUT_T_TASK,
      0,
      "Launching attack");
    if (attack->cld_run == 1) {
      hy_output(
        stdout,
        HY_OUT_T_NOTE,
        0,
        "This is a cold run, no data will be sent");
    }
  }
  memset(result, 0, sizeof(hy_attack_result_t));
  /* Check required patterns */
  if (attack->type == HY_AT_T_UNKNOWN) {
    result->ret = HY_ER_AT_T_UNKNOWN;
    return;
  }
  if (strlen(attack->src_pat.src) == 0) {
    result->ret = HY_ER_NO_SRC_PT_GIVEN;
    return;
  }
  if (strlen(attack->dst_pat.src) == 0) {
    result->ret = HY_ER_NO_DST_PT_GIVEN;
    return;
  }
  if (attack->type == HY_AT_T_ARP_REPLY ||
      attack->type == HY_AT_T_ARP_REQUEST ||
      attack->type == HY_AT_T_ICMP_UNREACH_TCP) {
    if (strlen(attack->sec_src_pat.src) == 0) {
      if (attack->type == HY_AT_T_ARP_REPLY ||
          attack->type == HY_AT_T_ARP_REQUEST) {
        result->ret = HY_ER_NO_SND_PT_GIVEN;
        return;
      } else if (attack->type == HY_AT_T_ICMP_UNREACH_TCP) {
        result->ret = HY_ER_NO_TCP_SRC_PT_GIVEN;
        return;
      } else if (attack->type == HY_AT_T_HSRP_HELLO ||
                 attack->type == HY_AT_T_HSRP_COUP ||
                 attack->type == HY_AT_T_HSRP_RESIGN) {
        result->ret = HY_ER_NO_VIR_PT_GIVEN;
        return;
      } else {
        result->ret = HY_ER_UNKNOWN;
        return;
      }
    }
  }
  if (attack->type == HY_AT_T_ARP_REPLY ||
      attack->type == HY_AT_T_ARP_REQUEST ||
      attack->type == HY_AT_T_ICMP_UNREACH_TCP ||
      attack->type == HY_AT_T_DHCP_REQUEST ||
      attack->type == HY_AT_T_DHCP_RELEASE) {
    if (strlen(attack->sec_dst_pat.src) == 0) {
      if (attack->type == HY_AT_T_ARP_REPLY ||
          attack->type == HY_AT_T_ARP_REQUEST) {
        result->ret = HY_ER_NO_TRG_PT_GIVEN;
        return;
      } else if (attack->type == HY_AT_T_ICMP_UNREACH_TCP) {
        result->ret = HY_ER_NO_TCP_DST_PT_GIVEN;
        return;
      } else if (attack->type == HY_AT_T_DHCP_REQUEST ||
                 attack->type == HY_AT_T_DHCP_RELEASE) {
        result->ret = HY_ER_NO_SRV_IP_GIVEN;
        return;
      } else {
        result->ret = HY_ER_UNKNOWN;
        return;
      }
    }
  }
  /* Set packet count */
  if (attack->min_cnt > 0 ||  attack->max_cnt > 0) {
    prm.pkt_lmt = hy_random(attack->min_cnt, attack->max_cnt);
    if (prm.pkt_lmt < 1) {
      prm.pkt_lmt = 1;
    }
  } else {
    prm.pkt_lmt = 0;
  }
  #ifdef OS_WINDOWS
    if ((thr =
            CreateThread(
              NULL,
              0,
              hy_win32_attack_loop,
              &prm,
              0,
              &pid)) == NULL) {
      result->ret = HY_ER_CREATE_THREAD;
      return;
    }
  #else
    if (pthread_create(
          &thr,
          NULL,
          hy_unix_attack_loop,
          &prm) != 0) {
      result->ret = HY_ER_CREATE_THREAD;
      return;
    }
  #endif /* OS_WINDOWS */
  hy_handle_attack_blocking(&prm);
  if (prm.pkt_buf != NULL) {
    free(prm.pkt_buf);
  }
} /* hy_attack */

/* -------------------------------------------------------------------------- */

/* Win32 and UNIX thread functions for executing the attack
 * loop, these functions only delegate their parameters
 * to hy_attck_loop
 */

#ifdef OS_WINDOWS
  DWORD WINAPI
    hy_win32_attack_loop
    (
      LPVOID params
    ) {

    hy_attack_loop((hy_attack_loop_t*) params);
    return 0;
  } /* hy_win32_attack_loop */
#else
  void*
    hy_unix_attack_loop
      (
        void* params
      ) {

    hy_attack_loop((hy_attack_loop_t*) params);
    return 0;
  } /* hy_unix_attack_loop */
#endif /* OS_WINDOWS */

/* -------------------------------------------------------------------------- */

void
  hy_attack_loop
    (
      hy_attack_loop_t* params
    ) {

  /*
   * USAGE:
   *   Generates packets for the given attack
   *   and writes them to the network.
   */

  int pkt_len = 0;
  unsigned long i = 0;
  unsigned int snd_del = 0;
  unsigned long seq_sid = 0;
  unsigned long dur_start = 0;
  unsigned long dur_stop = 0;
  unsigned int tmp_buf_len = 0;
  unsigned char* tmp_buf = NULL;

  if (params->att->min_dur > 0 ||
      params->att->max_dur > 0) {
    dur_stop =
      hy_random(
        params->att->min_dur,
        params->att->max_dur);
  }
  /* Check payload support */
  if (params->att->pay_len > 0 &&
      (params->att->type == HY_AT_T_ARP_REQUEST ||
       params->att->type == HY_AT_T_ARP_REPLY ||
       params->att->type == HY_AT_T_ICMP_UNREACH_TCP ||
       params->att->type == HY_AT_T_DHCP_REQUEST)) {
    params->res->ret = HY_ER_PKT_PAY_UNSUPPORTED;
    params->run_stat = HY_RUN_STAT_STOPPED;
    return;
  }
  /* Enter attack loop */
  dur_start = hy_get_milliseconds_of_day();
  while (i < params->pkt_lmt || params->pkt_lmt < 1) {
    fflush(stdin);
    if (params->run_stat == HY_RUN_STAT_REQUESTED_STOP) {
      break;
    }
    if (dur_stop > 0 &&
        (hy_get_milliseconds_of_day() - dur_start) >= dur_stop) {
      break;
    }
    /* Calculate send delay */
    if (params->att->min_del > 0 ||
        params->att->max_del > 0) {
      snd_del =
        hy_random(params->att->min_del,
                  params->att->max_del);
    }
    /* Calculate TCP sequence number / PPPoE session id */
    if (params->att->seq_sid == 0) {
      if (params->att->type == HY_AT_T_TCP ||
          params->att->type == HY_AT_T_ICMP_UNREACH_TCP) {
        if (params->att->seq_sid_ins == 0 || seq_sid == 0) {
          seq_sid =
            (hy_random(1, 32000) * 1000000000) +
             hy_random(1, 32000);
        }
      }
    } else if (seq_sid == 0) {
      seq_sid = params->att->seq_sid;
    }
    if (params->att->seq_sid_ins > 0 &&
        params->res->pkt_cnt > 0) {
      seq_sid = seq_sid + params->att->seq_sid_ins;
    }
    /* Build packet buffer */
    if (params->att->type == HY_AT_T_ARP_REQUEST) {
      if ((params->res->ret =
             hy_build_arp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               &params->att->sec_src_pat,
               &params->att->sec_dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               ARP_OP_REQUEST)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_ARP_REPLY) {
      if ((params->res->ret =
             hy_build_arp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               &params->att->sec_src_pat,
               &params->att->sec_dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               ARP_OP_REPLY)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_PPPOE_DISCOVER) {
      if ((params->res->ret =
             hy_build_pppoe_discover_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               seq_sid,
               params->att->pppoe_disc_code)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_ICMP_ECHO) {
      if ((params->res->ret =
             hy_build_icmp_echo_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->pay,
               params->att->pay_len,
               params->att->ip_ttl)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_TCP ||
                params->att->type == HY_AT_T_ICMP_UNREACH_TCP) {
      if (params->att->type == HY_AT_T_ICMP_UNREACH_TCP) {
        if ((params->res->ret =
               hy_build_tcp_packet(
                 &params->att->sec_src_pat,
                 &params->att->sec_dst_pat,
                 params->att->ip_v_asm,
                 &params->pkt_buf,
                 &pkt_len,
                 params->att->pay,
                 params->att->pay_len,
                 params->att->ip_ttl,
                 TH_SYN,
                 seq_sid,
                 params->att->tcp_ack,
                 0)) != HY_ER_OK) {
            if (params->res->ret == HY_ER_WRONG_PT_FMT_SRC) {
              params->res->ret = HY_ER_WRONG_PT_FMT_TCP_SRC;
            } else if (params->res->ret == HY_ER_WRONG_PT_FMT_DST) {
              params->res->ret = HY_ER_WRONG_PT_FMT_TCP_DST;
            }
          break;
        }
        tmp_buf_len = pkt_len;
        tmp_buf = malloc(tmp_buf_len);
        memset(tmp_buf, 0, tmp_buf_len);
        memcpy(tmp_buf, params->pkt_buf, tmp_buf_len);
        if ((params->res->ret =
               hy_build_icmp_unreach_packet(
                 &params->att->src_pat,
                 &params->att->dst_pat,
                 params->att->ip_v_asm,
                 &params->pkt_buf,
                 &pkt_len,
                 tmp_buf + sizeof(eth_h_t),
                 tmp_buf_len - sizeof(eth_h_t),
                 IP_PROTO_TCP,
                 params->att->ip_ttl,
                 params->att->icmp_unr_code)) != HY_ER_OK) {
          free(tmp_buf);
          break;
        }
        free(tmp_buf);
      } else {
        if ((params->res->ret =
               hy_build_tcp_packet(
                 &params->att->src_pat,
                 &params->att->dst_pat,
                 params->att->ip_v_asm,
                 &params->pkt_buf,
                 &pkt_len,
                 params->att->pay,
                 params->att->pay_len,
                 params->att->ip_ttl,
                 params->att->tcp_flgs,
                 seq_sid,
                 params->att->tcp_ack,
                 params->att->tcp_wnd)) != HY_ER_OK) {
          break;
        }
      }
    } else if (params->att->type == HY_AT_T_UDP) {
      if ((params->res->ret =
             hy_build_udp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->pay,
               params->att->pay_len,
               params->att->ip_ttl)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_DNS_QUERY) {
      if ((params->res->ret =
             hy_build_dns_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->ip_ttl,
               params->att->dns_qry)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_DHCP_DISCOVER) {
      if ((params->res->ret =
             hy_build_dhcp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               &params->att->sec_src_pat,
               &params->att->sec_dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->ip_ttl,
               HY_DHCP_MSG_DISCOVER)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_DHCP_REQUEST) {
      if ((params->res->ret =
             hy_build_dhcp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               &params->att->sec_src_pat,
               &params->att->sec_dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->ip_ttl,
               HY_DHCP_MSG_REQUEST)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_DHCP_RELEASE) {
      if ((params->res->ret =
             hy_build_dhcp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               &params->att->sec_src_pat,
               &params->att->sec_dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->ip_ttl,
               HY_DHCP_MSG_RELEASE)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_HSRP_HELLO) {
      if ((params->res->ret =
             hy_build_hsrp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->ip_ttl,
               HY_HSRP_OP_HELLO,
               params->att->hsrp_state_code,
               params->att->hsrp_auth,
               snd_del / 1000,
               params->att->hsrp_prio,
               params->att->hsrp_group)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_HSRP_COUP) {
      if ((params->res->ret =
             hy_build_hsrp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->ip_ttl,
               HY_HSRP_OP_COUP,
               params->att->hsrp_state_code,
               params->att->hsrp_auth,
               snd_del / 1000,
               params->att->hsrp_prio,
               params->att->hsrp_group)) != HY_ER_OK) {
        break;
      }
    } else if (params->att->type == HY_AT_T_HSRP_RESIGN) {
      if ((params->res->ret =
             hy_build_hsrp_packet(
               &params->att->src_pat,
               &params->att->dst_pat,
               params->att->ip_v_asm,
               &params->pkt_buf,
               &pkt_len,
               params->att->ip_ttl,
               HY_HSRP_OP_RESIGN,
               params->att->hsrp_state_code,
               params->att->hsrp_auth,
               snd_del / 1000,
               params->att->hsrp_prio,
               params->att->hsrp_group)) != HY_ER_OK) {
        break;
      }
    } else {
      params->res->ret = HY_ER_AT_T_UNKNOWN;
      break;
    }
    if (pkt_len > HY_MTU_LIMIT &&
        params->att->ign_mtu == 0) {
      params->res->ret = HY_MTU_LIMIT_EXCEED;
      break;
    }
    if (params->att->cld_run != 1) {
      #ifdef OS_WINDOWS
        if (pcap_sendpacket(
              params->dsc,
              params->pkt_buf,
              pkt_len) != 0) {
          params->res->ret = HY_ER_PCAP_WRITE;
          break;
        }
      #else
        if (pcap_inject(
              params->dsc,
              params->pkt_buf,
              pkt_len) != pkt_len) {
          params->res->ret = HY_ER_PCAP_WRITE;
          break;
        }
      #endif /* OS_WINDOWS */
    }
    free(params->pkt_buf);
    params->pkt_buf = NULL;
    if (params->res->tc_flg & HY_TC_PKT_CNT ||
        (params->pkt_lmt != 1 &&
         params->res->pkt_cnt < 1 ||
         (params->res->pkt_cnt + 1) < params->pkt_lmt)) {
      hy_sleep(snd_del);
    }
    if ((params->res->tot_byt + pkt_len) < params->res->tot_byt) {
      params->res->tc_flg =
        params->res->tc_flg + HY_TC_TOT_BYT;
    }
    params->res->tot_byt = params->res->tot_byt + pkt_len;
    if (params->pkt_lmt >= 1) {
      i = i + 1;
    }
    /* Check for turncation */
    if ((params->res->pkt_cnt + 1) < params->res->pkt_cnt) {
      params->res->tc_flg =
        params->res->tc_flg + HY_TC_PKT_CNT;
    }
    params->res->pkt_cnt = params->res->pkt_cnt + 1;
  }
  /* Calculate ellapsed time */
  params->res->dur_msec = hy_get_milliseconds_of_day() - dur_start;
  /* Reset packet stats on cold run */
  if (params->att->cld_run == 1) {
    params->res->pkt_cnt = 0;
    params->res->tot_byt = 0;
    params->res->tc_flg = 0;
  }
  params->run_stat = HY_RUN_STAT_STOPPED;
} /* hy_attack_loop */

/* -------------------------------------------------------------------------- */

void
  hy_local_attack
    (
      const char* if_name,
      hy_attack_t* params,
      hy_attack_result_t* result
    ) {

  /*
   * USAGE:
   *   Executes the given attack. This function should
   *   be called on local attacks.
   */

  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_t* dsc = NULL;

  memset(result, 0, sizeof(hy_attack_result_t));
  result->ret = HY_ER_OK;
  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Opening network interface (%s)",
    if_name);
  if ((dsc =
         pcap_open_live(
           if_name,
           BUFSIZ,
           0,
           0,
           err_buf)) == NULL) {
    result->ret = HY_ER_PCAP_OPEN_LIVE;
    return;
  }
  hy_attack(params, dsc, 0, result);
  pcap_close(dsc);
} /* hy_local_attack */

/* -------------------------------------------------------------------------- */
