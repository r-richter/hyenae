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

#include "hyenae-assistant.h"

/* -------------------------------------------------------------------------- */

int
  hy_assistant_input_yes_no
    (
      const char* text,
      int* input
    ) {

  /*
   * USAGE:
   *   Assistent helper function for
   *   prompting yes or no input.
   */

  int ret = HY_ER_OK;
  int inp_len = 0;
  char inp [HY_INPUT_BUFLEN];

  memset(inp, 0, HY_INPUT_BUFLEN);
  while (1) {
    printf("%s [y or n]: ", text);
    if ((inp_len = scanf("%s", inp)) > 0) {
      if (inp_len > HY_INPUT_BUFLEN) {
        return HY_ER_INP_BUFLEN_EXCEED;
      }
      hy_str_to_lower(inp, inp_len);
      if (strcmp(inp, "y") == 0 ) {
        *input = 1;
        break;
      } else {
        if (strcmp(inp, "n") == 0) {
          *input = 0;
          break;
        } else {
          printf("\n  (!) Invalid input\n");
        }
      }
    }
  }
  return ret;
} /* hy_assistant_input_yes_no */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_input_numeric
    (
      const char* text,
      int* input,
      int min_val,
      int max_val
    ) {

  /*
   * USAGE:
   *   Assistent helper function for
   *   prompting numeric input.
   */

  int ret = HY_ER_OK;
  int inp_len = 0;
  char inp [HY_INPUT_BUFLEN];

  memset(inp, 0, HY_INPUT_BUFLEN);
  while (1) {
    printf("%s [%i-%i]: ", text, min_val, max_val);
    if ((inp_len = scanf("%s", inp)) > 0) {
      if (inp_len > HY_INPUT_BUFLEN) {
        return HY_ER_INP_BUFLEN_EXCEED;
      }
      *input = atoi(inp);
      if (*input >= min_val && *input <= max_val) {
        break;
      } else {
        printf("\n  (!) Invalid input\n");
      }
    }
  }
  return ret;
} /* hy_assistant_input_numeric */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_input_address_pattern
    (
      const char* name,
      const char* format,
      int ip_v_asm,
      char* input,
      int inp_offset
    ) {

  /*
   * USAGE:
   *   Assistent helper function for
   *   prompting address patterns.
   */

  int ret = HY_ER_OK;
  hy_pattern_t ver_pat;

  while (1) {
    printf(
      "\n  Enter %s pattern:"
      "\n"
      "\n    Pattern format:"
      "\n      %s"
      "\n"
      "\n  For additional informations about address patterns "
      "\n  and wilcard based randomization see README or man pages.",
      name,
      format
    );
    ret =
      hy_assistant_input_text(
        "\n",
        input + inp_offset,
        HY_PT_BUFLEN);
    if (ret == HY_ER_INP_BUFLEN_EXCEED) {
      break;
    } else {
      strncpy(ver_pat.src, input, HY_PT_BUFLEN);
      ret = hy_parse_pattern(&ver_pat, ip_v_asm);
      if ((strstr(format, "[HW-Address]") != NULL &&
           strlen(ver_pat.hw_addr) == 0) ||
          (strstr(format, "[IP-Address]") != NULL &&
           strlen(ver_pat.ip_addr) == 0) ||
          (strstr(format, "[Port]") != NULL &&
           ver_pat.port < 1)) {
        ret = HY_ER_WRONG_PT_FMT;
      } else {
        if (ver_pat.ip_v != 0 &&
            ver_pat.ip_v != ip_v_asm) {
          ret = HY_ER_WRONG_IP_V;
        }
      }
      if (ret == HY_ER_OK) {
        break;
      } else {
        printf(
          "\n  (!) %s\n",
          hy_get_error_msg(ret));
      }
    }
  }
  return ret;
} /* hy_assistant_input_address_pattern */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_input_text
    (
      const char* text,
      char* input,
      int len
    ) {

  /*
   * USAGE:
   *   Assistent helper function for
   *   prompting text input.
   */

  int ret = HY_ER_OK;
  int inp_len = 0;
  char inp [HY_INPUT_BUFLEN];

  memset(inp, 0, HY_INPUT_BUFLEN);
  printf("%s\n  > ", text);
  while (1) {
    if ((inp_len = scanf("%s", inp)) > 0) {
      if (inp_len > HY_INPUT_BUFLEN) {
        return HY_ER_INP_BUFLEN_EXCEED;
      }
      strncpy(input, inp, len);
      break;
    }
  }
  return ret;
} /* hy_assistant_input_string */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_arp_request_flood
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   ARP-Request floods.
   */

  int ret = HY_ER_OK;

  attack->type = HY_AT_T_ARP_REQUEST;
  strcpy(
    attack->sec_dst_pat.src,
    "00:00:00:00:00:00-");
  while (1) {
    /*  Enter target pattern */
    ret =
      hy_assistant_input_address_pattern(
        "target",
        "[IP-Address]",
        attack->ip_v_asm,
        attack->sec_dst_pat.src,
        18);
    if (ret != HY_ER_OK) {
      return ret;
    }
    if (strchr(attack->sec_dst_pat.src, HY_PT_WCC) != NULL) {
      printf("\n  (!) Pattern must not contain wildcards\n");
    } else {
      break;
    }
  }
  /* Fill address patterns */
  strncpy(
    attack->src_pat.src,
    "%",
    HY_PT_BUFLEN);
  strncpy(
    attack->dst_pat.src,
    "ff:ff:ff:ff:ff:ff",
    HY_PT_BUFLEN);
  strncpy(
    attack->sec_src_pat.src,
    "%-%",
    HY_PT_BUFLEN);
  return ret;
} /* hy_assistant_handle_arp_request_flood */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_arp_cache_poisoning
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   ARP-Cache poisoning.
   */

  int ret = HY_ER_OK;

  attack->type = HY_AT_T_ARP_REPLY;
  /*  Enter target pattern */

  while (1) {
    ret =
      hy_assistant_input_address_pattern(
        "target",
        "[HW-Address]"
        "\n      (HW-Address to replace)",
        attack->ip_v_asm,
        attack->src_pat.src,
        0);
    if (ret != HY_ER_OK) {
      return ret;
    }
    if (strchr(attack->src_pat.src, HY_PT_WCC) != NULL) {
      printf("\n  (!) Pattern must not contain wildcards\n");
    } else {
      break;
    }
  }
  /* Enter spoofed ARP-Entry pattern */
  ret =
    hy_assistant_input_address_pattern(
      "spoofed ARP-Entry",
      "[HW-Address]-[IP-Address]"
      "\n      (replacement HW-Address and orig. associated IP-Address)",
      attack->ip_v_asm,
      attack->sec_src_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Fill remaining address patterns */
  strncpy(
    attack->dst_pat.src,
    "ff:ff:ff:ff:ff:ff",
    HY_PT_BUFLEN);
  strncpy(
    attack->sec_dst_pat.src,
    "ff:ff:ff:ff:ff:ff-0.0.0.0",
    HY_PT_BUFLEN);
  return ret;
} /* hy_assistant_handle_arp_cache_poisoning */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_icmp_echo_flood
    (
      hy_attack_t* attack,
      int is_route_nat_free,
      const char* hw_addr_gateway,
      int is_smurf_attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   ICMP-Echo floods.
   */

  int ret = HY_ER_OK;
  int hw_stp_len = 0;

  attack->type = HY_AT_T_ICMP_ECHO;
  if (is_smurf_attack == 1) {
    /* Enter target pattern */
    ret =
      hy_assistant_input_address_pattern(
        "target",
        "[HW-Address]-[IP-Address]",
        attack->ip_v_asm,
        attack->src_pat.src,
        0);
    strncpy(
      attack->dst_pat.src,
      "ff:ff:ff:ff:ff:ff-255.255.255.255",
      HY_PT_BUFLEN);
  } else {
    /* Enter source pattern */
    ret =
      hy_assistant_input_address_pattern(
        "source",
        "[HW-Address]-[IP-Address]",
        attack->ip_v_asm,
        attack->src_pat.src,
        0);
    if (ret != HY_ER_OK) {
      return ret;
    }
    /* Enter destination pattern */
    if (is_route_nat_free == 1) {
      ret =
        hy_assistant_input_address_pattern(
          "destination",
          "[HW-Address]-[IP-Address]",
          attack->ip_v_asm,
          attack->dst_pat.src,
          0);
    } else {
      hw_stp_len =
        sprintf(
          attack->dst_pat.src,
          "%s-",
          hw_addr_gateway);
      ret =
        hy_assistant_input_address_pattern(
          "destination",
          "[IP-Address]",
          attack->ip_v_asm,
          attack->dst_pat.src,
          hw_stp_len);
    }
  }
  return ret;
} /* hy_assistant_handle_icmp_echo_flood */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_blind_pppoe_ses_ini_flood
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   Blind PPPoE session
   *   initiation flood.
   */

  int ret = HY_ER_OK;

  attack->type = HY_AT_T_PPPOE_DISCOVER;
  attack->pppoe_disc_code = HY_PPPOE_CODE_PADI;
  strncpy(
    attack->src_pat.src,
    "%",
    HY_PT_BUFLEN);
  strncpy(
    attack->dst_pat.src,
    "ff:ff:ff:ff:ff:ff",
    HY_PT_BUFLEN);
} /* hy_assistant_handle_blind_pppoe_ses_ini_flood */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_blind_pppoe_ses_term
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   Blind PPPoE session
   *   termination attacks.
   */

  int ret = HY_ER_OK;

  attack->type = HY_AT_T_PPPOE_DISCOVER;
  attack->pppoe_disc_code = HY_PPPOE_CODE_PADT;
  attack->seq_sid = 1;
  attack->seq_sid_ins = 1;
  /* Enter PPPoE-Session (A) pattern */
  ret =
    hy_assistant_input_address_pattern(
      "Enter PPPoE-Session (A)",
      "[HW-Address]",
      attack->ip_v_asm,
      attack->src_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Enter PPPoE-Session (B) pattern */
  ret =
    hy_assistant_input_address_pattern(
      "Enter PPPoE-Session (B)",
      "[HW-Address]",
      attack->ip_v_asm,
      attack->dst_pat.src,
      0);
  return ret;
} /* hy_assistant_handle_blind_pppoe_ses_term */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_icmp_tcp_reset
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   ICMP based TCP-Resets.
   */

  int ret = HY_ER_OK;
  int opt = 0;

  attack->type = HY_AT_T_ICMP_UNREACH_TCP;
  attack->seq_sid = 1;
  attack->seq_sid_ins = 1;
  /* Select ICMP "Destination Unreachable" Code */
  if ((ret =
         hy_assistant_input_numeric(
           "\n  Select ICMP \"Destination Unreachable\" Code:"
           "\n  > 1. Network Unreachable"
           "\n  > 2. Host Unreachable"
           "\n  > 3. Protocol Unreachable"
           "\n  > 4. Port Unreachable"
           "\n"
           "\n  Enter option",
           &opt,
           1,
           4)) != HY_ER_OK) {
    printf("\n");
    return ret;
  }
  switch (opt) {
    case 1:
      attack->icmp_unr_code = ICMP_UNREACH_NET;
      break;
    case 2:
      attack->icmp_unr_code = ICMP_UNREACH_HOST;
      break;
    case 3:
      attack->icmp_unr_code = ICMP_UNREACH_PROTO;
      break;
    case 4:
      attack->icmp_unr_code = ICMP_UNREACH_PORT;
      break;
  }
  /* Enter TCP-Connection (A) pattern */
  ret =
    hy_assistant_input_address_pattern(
      "TCP-Connection (A)",
      "[HW-Address]-[IP-Address]@[Port]",
      attack->ip_v_asm,
      attack->src_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Enter TCP-Connection (B) pattern */
  ret =
    hy_assistant_input_address_pattern(
      "TCP-Connection (B)",
      "[HW-Address]-[IP-Address]@[Port]",
      attack->ip_v_asm,
      attack->dst_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Fill secondary patterns */
  strncpy(
    attack->sec_src_pat.src,
    attack->src_pat.src,
    HY_PT_BUFLEN);
  strncpy(
    attack->sec_dst_pat.src,
    attack->dst_pat.src,
    HY_PT_BUFLEN);
  return ret;
} /* hy_assistant_handle_icmp_tcp_reset */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_tcp_syn_flood
    (
      hy_attack_t* attack,
      int is_route_nat_free,
      const char* hw_addr_gateway,
      int is_land_attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   TCP-SYN floods.
   */

  int ret = HY_ER_OK;
  int hw_stp_len = 0;

  attack->type = HY_AT_T_TCP;
  attack->tcp_flgs = TH_SYN;

  if (is_land_attack == 1) {
    if (is_land_attack == 1) {
      /* Enter target pattern */
      while (1) {
        ret =
          hy_assistant_input_address_pattern(
            "target",
            "[HW-Address]-[IP-Address]@[Port]",
            attack->ip_v_asm,
            attack->dst_pat.src,
            0);
        if (ret != HY_ER_OK) {
          return ret;
        }
        if (strchr(attack->dst_pat.src, HY_PT_WCC) != NULL) {
          printf("\n  (!) Pattern must not contain wildcards\n");
        } else {
          break;
        }
      }
      if ((ret =
             hy_parse_pattern(
               &attack->dst_pat, attack->ip_v_asm)) != HY_ER_OK) {
        return ret;
      }
      strcpy(attack->src_pat.src, attack->dst_pat.src);
      attack->max_cnt = 1;
    }
  } else {
    /* Enter source pattern */
    ret =
      hy_assistant_input_address_pattern(
        "source",
        "[HW-Address]-[IP-Address]@[Port]",
        attack->ip_v_asm,
        attack->src_pat.src,
        0);
    if (ret != HY_ER_OK) {
      return ret;
    }
    /* Enter destination pattern */
    if (is_route_nat_free == 1) {
      ret =
        hy_assistant_input_address_pattern(
          "destination",
          "[HW-Address]-[IP-Address]@[Port]",
          attack->ip_v_asm,
          attack->dst_pat.src,
          0);
    } else {
      hw_stp_len =
        sprintf(
          attack->dst_pat.src,
          "%s-",
          hw_addr_gateway);
      ret =
        hy_assistant_input_address_pattern(
          "destination",
          "[IP-Address]@[Port]",
          attack->ip_v_asm,
          attack->dst_pat.src,
          hw_stp_len);
    }
  }
  return ret;
} /* hy_assistant_handle_tcp_syn_flood */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_blind_tcp_reset
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   Blind TCP-Reset.
   */

  int ret = HY_ER_OK;

  attack->type = HY_AT_T_TCP;
  attack->tcp_flgs = TH_RST;
  attack->seq_sid = 1;
  attack->seq_sid_ins = 1;
  /* Enter TCP-Connection (A) pattern */
  ret =
    hy_assistant_input_address_pattern(
      "TCP-Connection (A)",
      "[HW-Address]-[IP-Address]@[Port]",
      attack->ip_v_asm,
      attack->src_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Enter TCP-Connection (B) pattern */
  ret =
    hy_assistant_input_address_pattern(
      "TCP-Connection (B)",
      "[HW-Address]-[IP-Address]@[Port]",
      attack->ip_v_asm,
      attack->dst_pat.src,
      0);
  return ret;
} /* hy_assistant_handle_blind_tcp_reset */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_udp_flood
    (
      hy_attack_t* attack,
      int is_route_nat_free,
      const char* hw_addr_gateway
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   UPD-Floods.
   */

  int ret = HY_ER_OK;
  int hw_stp_len = 0;

  attack->type = HY_AT_T_UDP;
  /* Enter source pattern */
  ret =
    hy_assistant_input_address_pattern(
      "source",
      "[HW-Address]-[IP-Address]@[Port]",
      attack->ip_v_asm,
      attack->src_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Enter destination pattern */
  if (is_route_nat_free == 1) {
    ret =
      hy_assistant_input_address_pattern(
        "destination",
        "[HW-Address]-[IP-Address]@[Port]",
        attack->ip_v_asm,
        attack->dst_pat.src,
        0);
  } else {
    hw_stp_len =
      sprintf(
        attack->dst_pat.src,
        "%s-",
        hw_addr_gateway);
    ret =
      hy_assistant_input_address_pattern(
        "destination",
        "[IP-Address]@[Port]",
        attack->ip_v_asm,
        attack->dst_pat.src,
        hw_stp_len);
  }
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Enter payload length */
  if ((ret =
         hy_assistant_input_numeric(
           "\n  Enter payload length:",
           (int*) &attack->pay_len,
           1,
           1000)) != HY_ER_OK) {
    printf("\n");
    return ret;
  }
  /* Attach payload */
  attack->pay = malloc(attack->pay_len);
  hy_randomize_buffer(attack->pay, attack->pay_len);
  return ret;
} /* hy_assistant_handle_udp_flood */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_dns_query_flood
    (
      hy_attack_t* attack,
      int is_route_nat_free,
      const char* hw_addr_gateway,
      int is_land_attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   DNS-Query floods.
   */

  int ret = HY_ER_OK;
  int hw_stp_len = 0;
  int tmp_len = 0;
  int tmp_qry_cnt = 0;
  unsigned char tmp[HY_DNS_PACKET_BUFLEN];

  attack->type = HY_AT_T_DNS_QUERY;
  /* Enter source pattern */
  ret =
    hy_assistant_input_address_pattern(
      "source",
      "[HW-Address]-[IP-Address]",
      attack->ip_v_asm,
      attack->src_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Enter destination pattern */
  if (is_route_nat_free == 1) {
    ret =
      hy_assistant_input_address_pattern(
        "destination",
        "[HW-Address]-[IP-Address]",
        attack->ip_v_asm,
        attack->dst_pat.src,
        0);
  } else {
    hw_stp_len =
      sprintf(
        attack->dst_pat.src,
        "%s-",
        hw_addr_gateway);
    ret =
      hy_assistant_input_address_pattern(
        "destination",
        "[IP-Address]",
        attack->ip_v_asm,
        attack->dst_pat.src,
        hw_stp_len);
  }
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Enter query pattern */
  while (1) {
    if ((ret =
           hy_assistant_input_text(
             "\n  Enter query pattern"
             "\n"
             "\n    Pattern format:"
             "\n      [www.domain1.com],[www.domain2.com],..."
             "\n"
             "\n  For additional informations about query patterns "
             "\n  and wilcard based randomization see README or man pages.",
             attack->dns_qry,
             HY_INPUT_BUFLEN)) != HY_ER_OK) {
      printf("\n");
      return ret;
    }
    memset(tmp, 0, HY_DNS_PACKET_BUFLEN);
    ret =
      hy_dns_parse_add_queries(
        tmp, &tmp_len, attack->dns_qry, &tmp_qry_cnt, attack->ip_v_asm);
    if (ret == HY_ER_OK) {
      break;
    } else {
      printf(
        "\n  (!) %s\n",
        hy_get_error_msg(ret));
    }
  }
  return ret;
} /* hy_assistant_handle_dns_query_flood */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_dhcp_discover_flood
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   DHCP-Discover floods.
   */

  int ret = HY_ER_OK;

  attack->type = HY_AT_T_DHCP_DISCOVER;
  /* Fill primary address patterns */
  strncpy(
    attack->src_pat.src,
    "%-0.0.0.0",
    HY_PT_BUFLEN);
  strncpy(
    attack->dst_pat.src,
    "ff:ff:ff:ff:ff:ff-255.255.255.255",
    HY_PT_BUFLEN);
  return ret;
} /* hy_assistant_handle_dhcp_discover_flood */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_dhcp_starvation
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   DHCP-Starvation attacks.
   */

  int ret = HY_ER_OK;
  int opt = 0;

  attack->type = HY_AT_T_DHCP_REQUEST;
  /* Fill address patterns */
  strncpy(
    attack->src_pat.src,
    "%-0.0.0.0",
    HY_PT_BUFLEN);
  strncpy(
    attack->dst_pat.src,
    "ff:ff:ff:ff:ff:ff-255.255.255.255",
    HY_PT_BUFLEN);
  /* Enter target pattern */
  ret =
    hy_assistant_input_address_pattern(
      "target",
      "[IP-Address]"
      "\n      (Address of the target DHCP-Server)",
      attack->ip_v_asm,
      attack->sec_dst_pat.src,
      0);
  /* Define a requested IP-Address? */
  if ((ret =
         hy_assistant_input_yes_no(
           "\n  Define a requested IP-Address?"
           "\n"
           "\n  Some DHCP-Servers will drop DHCP-Requests "
           "\n  packets when no particular IP-Address was"
           "\n  requested"
           "\n"
           "\n  Enter choice",
           &opt)) != HY_ER_OK) {
    return ret;
  }
  if (opt == 1) {
    /* Enter requested IP-Address pattern */
    ret =
      hy_assistant_input_address_pattern(
        "request",
        "[IP-Address]"
        "\n      (IP-Address to request from the DHCP-Server)",
        attack->ip_v_asm,
        attack->sec_src_pat.src,
        0);
    if (ret != HY_ER_OK) {
      return ret;
    }
  }
  return ret;
} /* hy_assistant_handle_dhcp_starvation */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_dhcp_release_forcing
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   DHCP-Release forcing.
   */

  int ret = HY_ER_OK;
  int pat_len = 0;
  int eoa_ind = 0;

  attack->type = HY_AT_T_DHCP_RELEASE;
  /* Enter source pattern */
  ret =
    hy_assistant_input_address_pattern(
      "source",
      "[HW-Address]-[IP-Address]"
      "\n      (Address of the DHCP-Client)",
      attack->ip_v_asm,
      attack->src_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Enter destination pattern */
  ret =
    hy_assistant_input_address_pattern(
      "destination",
      "[HW-Address]-[IP-Address]"
      "\n      (Address of the DHCP-Server)",
      attack->ip_v_asm,
      attack->dst_pat.src,
      0);
  if (ret != HY_ER_OK) {
    return ret;
  }
  /* Fill secondary source pattern */
  pat_len = strlen(attack->dst_pat.src);
  while (eoa_ind < pat_len) {
    if (*(attack->dst_pat.src + eoa_ind) == HY_PT_EOA_HW) {
      break;
    }
    eoa_ind = eoa_ind + 1;
  }
  strncpy(
    attack->sec_dst_pat.src,
    (attack->dst_pat.src + (eoa_ind + 1)),
    HY_PT_BUFLEN);
  return ret;
} /* hy_assistant_handle_dhcp_release_forcing */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_handle_hsrp_hello_hijacking
    (
      hy_attack_t* attack
    ) {

  /*
   * USAGE:
   *   Assistent handler for
   *   HSRP active router hijacking.
   */

  int ret = HY_ER_OK;
  int opt = 0;
  char hsrp_auth_inp[HY_INPUT_BUFLEN];

  attack->type = HY_AT_T_HSRP_HELLO;
  attack->hsrp_state_code = HY_HSRP_STATE_ACTIVE;
  attack->hsrp_prio = 1;
  strcpy(
    attack->dst_pat.src,
    "00:00:00:00:00:00-");
  memset(hsrp_auth_inp, 0, HY_INPUT_BUFLEN);
  /* Enter target pattern */
  ret =
    hy_assistant_input_address_pattern(
      "source",
      "[HW-Address]-[IP-Address]",
      attack->ip_v_asm,
      attack->src_pat.src,
      0);
  while (1) {
    /*  Enter virtual IP-Address pattern */
    ret =
      hy_assistant_input_address_pattern(
        "virtual IP-Address",
        "[IP-Address]",
        attack->ip_v_asm,
        attack->dst_pat.src,
        18);
    if (ret != HY_ER_OK) {
      return ret;
    }
    if (strchr(attack->dst_pat.src, HY_PT_WCC) != NULL) {
      printf("\n  (!) Pattern must not contain wildcards\n");
    } else {
      break;
    }
  }
  /* Enter HSRP group */
  if ((ret =
         hy_assistant_input_numeric(
           "\n  Enter HSRP group:",
           (int*) &attack->hsrp_group,
           1,
           255)) != HY_ER_OK) {
  }
  /* Use default authentification? */
  if ((ret =
         hy_assistant_input_yes_no(
           "\n  Use HSRP default authentification?"
           "\n"
           "\n  Say 'n' here if you want to define a custom "
           "\n  authentification instead of using the default. "
           "\n"
           "\n  Enter choice",
           &opt)) != HY_ER_OK) {
    return ret;
  }
  if (opt == 0) {
    /* Enter HSRP authentification */
    while (1) {
      if ((ret =
             hy_assistant_input_text(
               "\n  Enter HSRP authentification:",
               hsrp_auth_inp,
               HY_INPUT_BUFLEN)) != HY_ER_OK) {
        printf("\n");
        return ret;
      }
      if (strlen(hsrp_auth_inp) <= HY_HSRP_AUTH_LEN) {
        break;
      } else {
        printf(
          "\n  (!) %s\n",
          hy_get_error_msg(HY_ER_HSRP_AUTH_LEN_EXCEED));
      }
    }
    strncpy(attack->hsrp_auth, hsrp_auth_inp, HY_HSRP_AUTH_LEN);
  }
  return ret;
} /* hy_assistant_handle_hsrp_hello_hijacking */

/* -------------------------------------------------------------------------- */

int
  hy_assistant_start
    (
      int* if_index,
      hy_server_list_t** srv_list,
      hy_attack_t* attack,
      int* execute
    ) {

  /*
   * USAGE:
   *   Fills the given network interface
   *   index, server list and attack
   *   structure by using an interactive
   *   text based assistant.
   */

  int ret = HY_ER_OK;
  int opt = 0;
  int if_cnt = 0;
  int nat_free = 0;
  int eap_free = 0;
  int max_opt_val = 0;
  char inp [HY_INPUT_BUFLEN];
  char srv_pat_inp [HY_INPUT_BUFLEN];
  char srv_lst_inp [HY_INPUT_BUFLEN];
  char hw_addr_gateway[HY_PT_BUFLEN];

  hy_output(
    stdout,
    HY_OUT_T_TASK,
    0,
    "Starting attack assistant");
  *if_index = -1;
  hy_init_attack_params(attack);
  memset(inp, 0, HY_PT_BUFLEN);
  memset(srv_pat_inp, 0, HY_PT_BUFLEN);
  memset(srv_lst_inp, 0, HY_PT_BUFLEN);
  memset(hw_addr_gateway, 0, HY_PT_BUFLEN);

  /* Select operation mode */
  if ((ret =
         hy_assistant_input_numeric(
           "\n  Select operation mode:"
           "\n  > 1. Local"
           "\n  > 2. Remote (Single Daemon)"
           "\n  > 3. Remote (Multiple Daemons)"
           "\n"
           "\n  Enter option",
           &opt,
           1,
           3)) != HY_ER_OK) {
    printf("\n");
    return ret;
  }
  if (opt == 1) {
    /* Select network interface */
    printf("\n  Select network interface:\n");
    if ((ret =
           hy_print_if_list(
           &if_cnt,
           1)) != HY_ER_OK) {
      printf("\n");
      return ret;
    }
    if ((ret =
           hy_assistant_input_numeric(
             "\n  Enter option",
             if_index,
             1,
             if_cnt)) != HY_ER_OK) {
      printf("\n");
      return ret;
    }
  } else {
    if (opt == 2) {
      while (1) {
        /* Enter connection pattern */
        if ((ret =
               hy_assistant_input_text(
                 "\n  Enter connection pattern:"
                 "\n"
                 "\n    Pattern formats:"
                 "\n      [IP-Address]@[Port]"
                 "\n      [IP-Address]@[Port]+[Password]"
                 "\n",
                 srv_pat_inp,
                 HY_INPUT_BUFLEN)) != HY_ER_OK) {
          printf("\n");
          return ret;
        }
        if (*srv_list != NULL) {
          free(*srv_list);
          *srv_list = NULL;
        }
        *srv_list = malloc(sizeof(hy_server_list_t));
        (*srv_list)->next = NULL;
        ret =
          hy_set_server_list_item(
            srv_pat_inp,
            *srv_list);
        if (ret == HY_ER_OK) {
          break;
        } else {
          printf(
            "\n  (!) %s\n",
            hy_get_error_msg(ret));
        }
      }
    } else {
      /* Enter path of the server list file */
      while (1) {
        if ((ret =
               hy_assistant_input_text(
                 "\n  Enter path of server.lst:",
                 srv_lst_inp,
                 HY_INPUT_BUFLEN)) != HY_ER_OK) {
          printf("\n");
          return ret;
        }
        ret =
          hy_load_server_list(
            srv_lst_inp,
            srv_list);
        if (ret == HY_ER_OK) {
          break;
        } else {
          printf(
            "\n  (!) %s\n",
            hy_get_error_msg(ret));
        }
      }
    }
  }
  /* Select IP version */
  if ((ret =
         hy_assistant_input_numeric(
           "\n  Select IP version:"
           "\n  > 1. IPv4"
           "\n  > 2. IPv6"
           "\n"
           "\n  Enter option",
           &opt,
           1,
           3)) != HY_ER_OK) {
    printf("\n");
    return ret;
  }
  if (opt == 1) {
    attack->ip_v_asm = HY_AD_T_IP_V4;
  } else {
    attack->ip_v_asm = HY_AD_T_IP_V6;
  }
  /* Is packet route NAT-Free? */
  if ((ret =
         hy_assistant_input_yes_no(
           "\n  Is packet route NAT-Free?"
           "\n"
           "\n  Say 'n' here if the target machine is on a"
           "\n  different subnet than you such as hosts on the internet."
           "\n"
           "\n  Enter choice",
           &nat_free)) != HY_ER_OK) {
    printf("\n");
    return ret;
  }
  if (nat_free != 1) {
    /* Enter router / gateway pattern */
    while (1) {
      ret =
        hy_assistant_input_address_pattern(
          "router / gateway",
          "[HW-Address]",
          attack->ip_v_asm,
          hw_addr_gateway,
          0);
      if (ret != HY_ER_OK) {
        return ret;
      }
      if (strchr(hw_addr_gateway, HY_PT_WCC) != NULL) {
        printf("\n  (!) Pattern must not contain wildcards\n");
      } else {
        break;
      }
    }
  } else {
    /* Is network using EAP-Free? */
    if ((ret =
           hy_assistant_input_yes_no(
             "\n  Is network EAP-Free?"
             "\n"
             "\n  Say 'n' here if the network you are on is using the"
             "\n  Extensible Authentication Protocol (EAP). This would be"
             "\n  the case if you are connected with a wireless network card."
             "\n"
             "\n  Enter choice",
             &eap_free)) != HY_ER_OK) {
      printf("\n");
      return ret;
    }
  }
  /* Select attack type */
  printf("\n  Select attack type:");
  if (nat_free == 1) {
    if (attack->ip_v_asm == HY_AD_T_IP_V4) {
      if (eap_free == 1) {
        /* NAT-Free, EAP-Free IPv4 attacks */
        printf("\n  > 1.  ARP-Request flood                   DoS");
        printf("\n  > 2.  ARP-Cache poisoning                 MITM");
        printf("\n  > 3.  PPPoE session initiation flood      DoS");
        printf("\n  > 4.  Blind PPPoE session termination     DoS");
        printf("\n  > 5.  ICMPv4-Echo flood                   DoS");
        printf("\n  > 6.  ICMPv4-Smurf attack                 DDoS");
        printf("\n  > 7.  ICMPv4 based TCP-Connection reset   DoS");
        printf("\n  > 8.  TCP-SYN flood                       DoS");
        printf("\n  > 9.  TCP-Land attack                     DoS");
        printf("\n  > 10. Blind TCP-Connection reset          DoS");
        printf("\n  > 11. UDP flood                           DoS");
        printf("\n  > 12. DNS-Query flood                     DoS");
        printf("\n  > 13. DHCP-Discover flood                 DoS");
        printf("\n  > 14. DHCP starvation                     DoS");
        printf("\n  > 15. DHCP-Release forcing                DoS");
        printf("\n  > 16. Cisco HSRP active router hijacking  DoS");
        max_opt_val = 16;
      } else {
        /* NAT-Free, None EAP-Free IPv4 attacks */
        printf("\n  > 1.  ARP-Cache poisoning                 MITM");
        printf("\n  > 2.  ICMPv4-Echo flood                   DoS");
        printf("\n  > 3.  ICMPv4-Smurf attack                 DDoS");
        printf("\n  > 4.  ICMPv4 based TCP-Connection reset   DoS");
        printf("\n  > 5.  TCP-SYN flood                       DoS");
        printf("\n  > 6.  TCP-Land attack                     DoS");
        printf("\n  > 7.  Blind TCP-Connection reset          DoS");
        printf("\n  > 8.  UDP flood                           DoS");
        printf("\n  > 9.  DNS-Query flood                     DoS");
        printf("\n  > 10. DHCP-Release forcing                DoS");
        max_opt_val = 10;
      }
    } else {
      /* NAT-Free IPv6 attacks */
      printf("\n  > 1. PPPoE session initiation flood         DoS");
      printf("\n  > 2. Blind PPPoE session termination        DoS");
      printf("\n  > 3. ICMPv6-Echo flood                      DoS");
      printf("\n  > 4. TCP-SYN flood                          DoS");
      printf("\n  > 5. Blind TCP-Connection reset             DoS");
      printf("\n  > 6. UDP flood                              DoS");
      printf("\n  > 7. DNS-Query flood                        DoS");
      max_opt_val = 7;
    }
  } else {
    if (attack->ip_v_asm == HY_AD_T_IP_V4) {
      /* None NAT-Free IPv4 attacks */
      printf("\n  > 1. ICMPv4-Echo flood                      DoS");
      printf("\n  > 2. TCP-SYN flood                          DoS");
      printf("\n  > 3. UDP flood                              DoS");
      printf("\n  > 4. DNS-Query flood                        DoS");
      max_opt_val = 4;
    } else {
      /* None NAT-Free IPv6 attacks */
      printf("\n  > 1. ICMPv6-Echo flood                      DoS");
      printf("\n  > 2. TCP-SYN flood                          DoS");
      printf("\n  > 3. UDP flood                              DoS");
      printf("\n  > 4. DNS-Query flood                        DoS");
      max_opt_val = 4;
    }
  }
  if ((ret =
         hy_assistant_input_numeric(
           "\n"
           "\n  Enter option",
           &opt,
           1,
           max_opt_val)) != HY_ER_OK) {
    printf("\n");
    return ret;
  }
  if (nat_free == 1) {
    if (attack->ip_v_asm == HY_AD_T_IP_V4) {
      if (eap_free == 1) {
        /* Handle NAT-Free, EAP-Free IPv4 attacks */
        switch (opt) {
          case 1:
            ret =
              hy_assistant_handle_arp_request_flood(attack);
            break;
          case 2:
            ret =
              hy_assistant_handle_arp_cache_poisoning(attack);
            break;
          case 3:
            ret =
              hy_assistant_handle_blind_pppoe_ses_ini_flood(attack);
            break;
          case 4:
            ret =
              hy_assistant_handle_blind_pppoe_ses_term(attack);
            break;
          case 5:
            ret =
              hy_assistant_handle_icmp_echo_flood(
                attack, nat_free, hw_addr_gateway, 0);
            break;
          case 6:
            ret =
              hy_assistant_handle_icmp_echo_flood(
                attack, nat_free, hw_addr_gateway, 1);
            break;
          case 7:
            ret =
              hy_assistant_handle_icmp_tcp_reset(attack);
            break;
          case 8:
            ret =
              hy_assistant_handle_tcp_syn_flood(
                attack, nat_free, hw_addr_gateway, 0);
            break;
          case 9:
            ret =
              hy_assistant_handle_tcp_syn_flood(
                attack, nat_free, hw_addr_gateway, 1);
            break;
          case 10:
            ret =
              hy_assistant_handle_blind_tcp_reset(attack);
            break;
          case 11:
            ret =
              hy_assistant_handle_udp_flood(
                attack, nat_free, hw_addr_gateway);
            break;
          case 12:
            ret =
              hy_assistant_handle_dns_query_flood(
                attack, nat_free, hw_addr_gateway, 1);
            break;
          case 13:
            ret =
              hy_assistant_handle_dhcp_discover_flood(attack);
            break;
          case 14:
            ret =
              hy_assistant_handle_dhcp_starvation(attack);
            break;
          case 15:
            ret =
              hy_assistant_handle_dhcp_release_forcing(attack);
            break;
          case 16:
            ret =
              hy_assistant_handle_hsrp_hello_hijacking(attack);
            break;
        }
      } else {
        /* Handle NAT-Free, None EAP-Free IPv4 attacks */
        switch (opt) {
          case 1:
            ret =
              hy_assistant_handle_arp_cache_poisoning(attack);
            break;
          case 2:
            ret =
              hy_assistant_handle_icmp_echo_flood(
                attack, nat_free, hw_addr_gateway, 0);
            break;
          case 3:
            ret =
              hy_assistant_handle_icmp_echo_flood(
                attack, nat_free, hw_addr_gateway, 1);
            break;
          case 4:
            ret =
              hy_assistant_handle_icmp_tcp_reset(attack);
            break;
          case 5:
            ret =
              hy_assistant_handle_tcp_syn_flood(
                attack, nat_free, hw_addr_gateway, 0);
            break;
          case 6:
            ret =
              hy_assistant_handle_tcp_syn_flood(
                attack, nat_free, hw_addr_gateway, 1);
            break;
          case 7:
            ret =
              hy_assistant_handle_blind_tcp_reset(attack);
            break;
          case 8:
            ret =
              hy_assistant_handle_udp_flood(
                attack, nat_free, hw_addr_gateway);
            break;
          case 9:
            ret =
              hy_assistant_handle_dns_query_flood(
                attack, nat_free, hw_addr_gateway, 1);
            break;
          case 10:
            ret =
              hy_assistant_handle_dhcp_release_forcing(attack);
            break;
        }
      }
    } else {
      /* Handle NAT-Free IPv6 attacks */
      switch (opt) {
        case 1:
          ret =
            hy_assistant_handle_blind_pppoe_ses_ini_flood(attack);
          break;
        case 2:
          ret =
            hy_assistant_handle_blind_pppoe_ses_term(attack);
          break;
        case 3:
          ret =
            hy_assistant_handle_icmp_echo_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
        case 4:
          ret =
            hy_assistant_handle_tcp_syn_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
        case 5:
          ret =
            hy_assistant_handle_blind_tcp_reset(attack);
          break;
        case 6:
          ret =
            hy_assistant_handle_udp_flood(
              attack, nat_free, hw_addr_gateway);
          break;
        case 7:
          ret =
            hy_assistant_handle_dns_query_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
      }
    }
  } else {
    if (attack->ip_v_asm == HY_AD_T_IP_V4) {
      /* Handle non NAT-Free IPv4 attacks */
      switch (opt) {
        case 1:
          ret =
            hy_assistant_handle_icmp_echo_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
        case 2:
          ret =
            hy_assistant_handle_tcp_syn_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
        case 3:
          ret =
            hy_assistant_handle_udp_flood(
              attack, nat_free, hw_addr_gateway);
          break;
        case 4:
          ret =
            hy_assistant_handle_dns_query_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
      }
    } else {
      /* Handle non NAT-Free IPv6 attacks */
      switch (opt) {
        case 1:
          ret =
            hy_assistant_handle_icmp_echo_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
        case 2:
          ret =
            hy_assistant_handle_tcp_syn_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
        case 3:
          ret =
            hy_assistant_handle_udp_flood(
              attack, nat_free, hw_addr_gateway);
          break;
        case 4:
          ret =
            hy_assistant_handle_dns_query_flood(
              attack, nat_free, hw_addr_gateway, 0);
          break;
      }
    }
  }
  if (attack->min_cnt < 1 &&
      attack->max_cnt < 1) {
    /* Activate random send delay? */
    if (attack->type == HY_AT_T_HSRP_HELLO) {
      if ((ret =
             hy_assistant_input_numeric(
               "\n  Enter HSRP hello interval (Seconds):",
               (int*) &attack->min_del,
               1,
               255)) != HY_ER_OK) {
        return ret;
      }
      attack->min_del = attack->min_del * 1000;
      attack->max_del = 0;
    } else {
      if ((ret =
             hy_assistant_input_yes_no(
               "\n  Activate random send delay?"
               "\n"
               "\n  A random send delay can be usefull to break"
               "\n  flood detection mechanisms but will slow down "
               "\n  the packet rate of the attack."
               "\n"
               "\n  Enter choice",
               &opt)) != HY_ER_OK) {
        return ret;
      }
      if (opt == 1) {
        attack->min_del = 0;
        attack->max_del = 1000;
      }
    }
  }
  /* Print attack usage */
  printf("\n  Attack usage:");
  printf("\n");
  printf("\n    hyenae");
  if (*if_index > -1) {
    printf(" -I %i", *if_index);
  } else {
    if (strlen(srv_pat_inp) > 0) {
      printf(" -r %s", srv_pat_inp);
    }
    if (strlen(srv_lst_inp) > 0) {
      printf(" -R %s", srv_lst_inp);
    }
  }
  printf(
    " -a %s",
    hy_get_attack_name(attack->type));
  if (attack->type == HY_AT_T_PPPOE_DISCOVER ||
      attack->type == HY_AT_T_ICMP_UNREACH_TCP ||
      attack->type == HY_AT_T_HSRP_HELLO ||
      attack->type == HY_AT_T_HSRP_COUP ||
      attack->type == HY_AT_T_HSRP_RESIGN) {
    printf(" -o ");
    if (attack->type == HY_AT_T_PPPOE_DISCOVER) {
      switch (attack->pppoe_disc_code) {
        case HY_PPPOE_CODE_PADI:
          printf("padi");
          break;
        case HY_PPPOE_CODE_PADT:
          printf("padt");
          break;
      }
    } else if (attack->type == HY_AT_T_ICMP_UNREACH_TCP) {
      switch (attack->icmp_unr_code) {
        case ICMP_UNREACH_NET:
          printf("network");
          break;
        case ICMP_UNREACH_HOST:
          printf("host");
          break;
        case ICMP_UNREACH_PROTO:
          printf("protocol");
          break;
        case ICMP_UNREACH_PORT:
          printf("port");
          break;
      }
    } else if (attack->type == HY_AT_T_HSRP_HELLO ||
               attack->type == HY_AT_T_HSRP_COUP ||
               attack->type == HY_AT_T_HSRP_RESIGN) {
      switch (attack->hsrp_state_code) {
        case HY_HSRP_STATE_INIT:
          printf("init");
          break;
        case HY_HSRP_STATE_LEARN:
          printf("learn");
          break;
        case HY_HSRP_STATE_LISTEN:
          printf("listen");
          break;
        case HY_HSRP_STATE_SPEAK:
          printf("speak");
          break;
        case HY_HSRP_STATE_STANDBY:
          printf("standby");
          break;
        case HY_HSRP_STATE_ACTIVE:
          printf("active");
          break;
      }
      if (strlen(attack->hsrp_auth) > 0) {
        printf(" -h %s", attack->hsrp_auth);
      }
      printf(" -z %i", attack->hsrp_prio);
      printf(" -g %i", attack->hsrp_group);
    } else {
      return HY_ER_UNKNOWN;
    }
  }
  if (attack->type == HY_AT_T_TCP) {
    printf(" -f ");
    if (attack->tcp_flgs & TH_FIN) {
       printf("f");
    }
    if (attack->tcp_flgs & TH_SYN) {
      printf("s");
    }
    if (attack->tcp_flgs & TH_RST) {
      printf("r");
    }
    if (attack->tcp_flgs & TH_PUSH) {
      printf("p");
    }
    if (attack->tcp_flgs & TH_ACK) {
      printf("a");
    }
  }
  if (attack->seq_sid > 0) {
    printf(" -q %li", attack->seq_sid);
  }
  if (attack->seq_sid_ins > 0) {
    printf(" -Q %li", attack->seq_sid_ins);
  }
  if (attack->type == HY_AT_T_UDP) {
    printf(" -p %i",attack->pay_len);
  }
  printf(" -A %i", attack->ip_v_asm);
  printf(
    "\n           -s %s -d %s",
    attack->src_pat.src,
    attack->dst_pat.src);
  if (strlen(attack->sec_src_pat.src) > 0) {
    printf(
      "\n           -S %s",
      attack->sec_src_pat.src);
  }
  if (strlen(attack->sec_dst_pat.src) > 0) {
    if (strlen(attack->sec_src_pat.src) == 0) {
      printf("\n           ");
    } else {
      printf(" ");
    }
    printf("-D %s", attack->dst_pat.src);
  }
  if (strlen(attack->dns_qry) > 0) {
    printf("\n           -y %s", attack->dns_qry);
  }
  if (attack->min_del > 0) {
    printf("\n           -e %i", attack->min_del);
  }
  if (attack->max_del > 0) {
    printf("\n           -E %i", attack->max_del);
  }
  printf("\n");
  if ((ret =
           hy_assistant_input_yes_no(
             "\n  Would you like to execute the attack now?"
             "\n"
             "\n  Enter choice",
             execute)) != HY_ER_OK) {
    return ret;
  }
  printf("\n");
  return ret;
} /* hy_assistant_start */

/* -------------------------------------------------------------------------- */
