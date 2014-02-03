/* privkey.h - Internal definitions for the Private Keys Parser
 * Copyright (C) 2014 Dmitry Eremin-Solenikov
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * KSBA is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PRIVKEY_H
#define PRIVKEY_H 1

#include "ksba.h"

struct ksba_priv_key_s {
  gpg_error_t last_error;

  int initialized;
  ksba_asn_tree_t asn_tree;
  AsnNode root;  /* root of the tree with the values */
  unsigned char *image;
  size_t imagelen;
};

/*-- privkey.c --*/

#endif /*PRIVKEY_H*/
