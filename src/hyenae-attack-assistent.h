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

#ifndef HYENAE_ATTACK_ASSISTENT_H
  #define HYENAE_ATTACK_ASSISTENT_H

#include "hyenae.h"

/* -------------------------------------------------------------------------- */

int
  hy_enter_numeric_option
    (
      int,
      int
    );

/* -------------------------------------------------------------------------- */

int
  hy_start_attack_assistent
    (
      int*,
      hy_attack_t*
    );

/* -------------------------------------------------------------------------- */

#endif /* HYENAE_ATTACK_ASSISTENT_H */
