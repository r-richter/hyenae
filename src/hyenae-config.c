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

#include "hyenae-config.h"

/* -------------------------------------------------------------------------- */

int
  hy_load_config_keys
    (
      const char* filename,
      hy_key_list_t** key_list
    ) {

  /*
   * USAGE:
   *   Loads all configuration keys and their
   *   values from the given file.
   */

  int c = 0;
  int buf_i = 0;
  int key_i = 0;
  int val_i = -1;
  int ret = HY_ER_OK;
  int len = 0;
  unsigned char* buf = NULL;
  hy_key_list_t* cur_key = NULL;

  if ((ret =
         hy_load_file_to_buffer(
           filename,
           &buf,
           &len)) != HY_ER_OK) {
    return ret;
  }
  *key_list = malloc(sizeof(hy_key_list_t));
  memset(*key_list, 0, sizeof(hy_key_list_t));
  ((hy_key_list_t*) *key_list)->next = NULL;
  cur_key = *key_list;
  while (buf_i < len) {
    c = *(buf + buf_i);
    if (c == HY_CF_CMC) {
      key_i = -1;
      val_i = -1;
    } else if (c == HY_CF_KVC && key_i > -1) {
      key_i = -1;
      val_i = 0;
    } else if (c == '\n' || (buf_i + 1) == len) {
      key_i = 0;
      val_i = -1;
      if (strlen(cur_key->key) > 0 &&
          strlen(cur_key->value) > 0) {
        if ((buf_i + 1) < len && *(buf + buf_i + 1) != '\n') {
          cur_key->next = malloc(sizeof(hy_key_list_t));
          memset(cur_key->next, 0, sizeof(hy_key_list_t));
          cur_key->next->prev = cur_key;
          cur_key->next->next = NULL;
          cur_key = cur_key->next;
        }
      } else if (strlen(cur_key->key) != 0 &&
                  strlen(cur_key->value) == 0) {
        return HY_ER_CF_EMPTY_KEY;
      }
    } else {
      if (c != ' ' && c != '\t' && c != '\n') {
        if (key_i > -1) {
          if (key_i >= HY_CF_KEY_BUFLEN) {
            return HY_ER_CF_KEY_BUFLEN_EXCEED;
          }
          *(cur_key->key + key_i) = c;
          key_i = key_i + 1;
        } else if (val_i > -1) {
          if (val_i >= HY_CF_VAL_BUFLEN) {
            return HY_ER_CF_VAL_BUFLEN_EXCEED;
          }
          *(cur_key->value + val_i) = c;
          val_i = val_i + 1;
        }
      }
    }
    buf_i = buf_i + 1;
  }
  if (strlen(cur_key->key) == 0 &&
      strlen(cur_key->value) == 0) {
    if (cur_key->prev == NULL) {
      return HY_ER_CF_NO_KEYS;
    }
    cur_key = cur_key->prev;
    free(cur_key->next);
    cur_key->next = NULL;
  }
  if (strlen(cur_key->value) == 0) {
    return HY_ER_CF_EMPTY_KEY;
  }
  return ret;
} /* hy_load_config_keys */

/* -------------------------------------------------------------------------- */

void
  hy_free_key_list
    (
      hy_key_list_t* key_list
    ) {

  /*
   * USAGE:
   *   Frees a key list.
   */

  if (key_list->next != NULL) {
    hy_free_key_list(key_list->next);
    key_list->next = NULL;
  }
  free(key_list);
} /* hy_free_key_list */

/* -------------------------------------------------------------------------- */
