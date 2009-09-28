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

#ifndef HYENAE_COMMON_H
  #define HYENAE_COMMON_H

#include "hyenae-base.h"
#include "hyenae-config.h"
#include "hyenae-patterns.h"
#include "hyenae-attack.h"
#include "hyenae-arp.h"
#include "hyenae-icmp.h"
#include "hyenae-tcp.h"
#include "hyenae-udp.h"
#include "hyenae-protocol.h"

/* General informations */
#define HY_COPYRIGHT "2009 Robin Richter"
#define HY_CONTACT   "richterr@users.sourceforge.net"
#define HY_HOMEPAGE  "http://sourceforge.net/projects/hyenae/"

/* -------------------------------------------------------------------------- */

int
  hy_print_if_list
    (
      int*,
      int
    );

/* -------------------------------------------------------------------------- */

void
  hy_print_attack_list();

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_COMMON_H */
