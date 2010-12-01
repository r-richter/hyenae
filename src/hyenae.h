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

#ifndef HYENAE_H
  #define HYENAE_H

#include "hyenae-common.h"
#include "hyenae-remote.h"
#include "hyenae-assistant.h"

#include <getopt.h>

/* Path separation character */
 #ifdef OS_WINDOWS
    #define HY_PATH_SEP_CHR '\\'
#else
  #define HY_PATH_SEP_CHR   '/'
#endif

/* Frontend stop condition file name */
#define HY_FE_STOP_FILENAME ".hyenae_fe_stop"

/* Frontend stop condition file path buffer length */
#define HY_FE_STOP_PATH_BUFLEN 1024

/* Frontend stop condition file path */
const char HY_FE_STOP_PATH[HY_FE_STOP_PATH_BUFLEN];

/* -------------------------------------------------------------------------- */

void
  hy_handle_output
    (
      FILE*,
      int,
      const char*,
      const char*
    );

/* -------------------------------------------------------------------------- */

void
  hy_handle_attack_blocking
    (
      hy_attack_loop_t*
    );

/* -------------------------------------------------------------------------- */

int
  hy_parse_ppoe_discover_code
    (
      unsigned int*,
      char*
    );

/* -------------------------------------------------------------------------- */

int
  hy_parse_icmp_unreach_code
    (
      unsigned int*,
      char*
    );

/* -------------------------------------------------------------------------- */

int
  hy_parse_hsrp_state_code
    (
      unsigned int*,
      char*
    );

/* -------------------------------------------------------------------------- */

int
  hy_parse_tcp_flags
    (
      unsigned int*,
      const char*
    );

/* -------------------------------------------------------------------------- */

int
  hy_init_fe_stop_path
    (
      char**
    );

/* -------------------------------------------------------------------------- */

int
  main
    (
      int argc,
      char** argv
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_H */
