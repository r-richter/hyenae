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

#ifndef HYENAE_CONFIG_H
  #define HYENAE_CONFIG_H

#include "hyenae-base.h"

/* Comment indication character */
#define HY_CF_CMC '#'

/* Key/Value separation character */
#define HY_CF_KVC '='

/* Buffer lengths */
#define HY_CF_KEY_BUFLEN 255
#define HY_CF_VAL_BUFLEN 2048

/* -------------------------------------------------------------------------- */

typedef
  struct hy_key_list {

  /*
   * USAGE:
   *   Represents a list of configurations keys
   *   and their values.
   */

  char key[HY_CF_KEY_BUFLEN];
  char value[HY_CF_VAL_BUFLEN];
  struct hy_key_list* prev;
  struct hy_key_list* next;

} hy_key_list_t;

/* -------------------------------------------------------------------------- */

int
  hy_load_config_keys
    (
      const char*,
      hy_key_list_t**
    );

/* -------------------------------------------------------------------------- */

void
  hy_free_key_list
    (
      hy_key_list_t*
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_CONFIG_H */
