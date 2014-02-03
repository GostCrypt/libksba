/* privkey.c - Private Keys parser
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "util.h"

#include "convert.h"
#include "keyinfo.h"
#include "der-encoder.h"
#include "ber-help.h"
#include "ber-decoder.h"
#include "privkey.h"


/**
 * ksba_priv_key_new:
 *
 * Create a new and empty Private Key object
 *
 * Return value: A Private Key object or an error code.
 **/
gpg_error_t ksba_priv_key_new (ksba_priv_key_t *r_priv_key)
{
  *r_priv_key = xtrycalloc (1, sizeof **r_priv_key);
  if (!*r_priv_key)
    return gpg_error_from_errno (errno);
  return 0;
}

/**
 * ksba_priv_key_release:
 * @priv_key: A Private Key object
 *
 * Release a Private Key object.
 **/
void ksba_priv_key_release (ksba_priv_key_t priv_key)
{
  xfree(priv_key);
}

gpg_error_t ksba_priv_key_parse_der (ksba_priv_key_t priv_key, ksba_reader_t reader)
{
  gpg_error_t err = 0;
  BerDecoder decoder = NULL;

  if (!priv_key || !reader)
    return gpg_error (GPG_ERR_INV_VALUE);

  _ksba_asn_release_nodes (priv_key->root);
  ksba_asn_tree_release (priv_key->asn_tree);
  priv_key->root = NULL;
  priv_key->asn_tree = NULL;

  err = ksba_asn_create_tree ("tmttv2", &priv_key->asn_tree);
  if (err)
    goto leave;

  decoder = _ksba_ber_decoder_new ();
  if (!decoder)
    {
      err = gpg_error (GPG_ERR_ENOMEM);
      goto leave;
    }

  err = _ksba_ber_decoder_set_reader (decoder, reader);
  if (err)
    goto leave;

  err = _ksba_ber_decoder_set_module (decoder, priv_key->asn_tree);
  if (err)
     goto leave;

  err = _ksba_ber_decoder_decode (decoder, "TMTTv2.PrivateKeyInfo", 0,
                                  &priv_key->root, &priv_key->image,
                                  &priv_key->imagelen);
  if (!err)
      priv_key->initialized = 1;

 leave:
  _ksba_ber_decoder_release (decoder);

  return err;
}

ksba_sexp_t ksba_priv_key_get_private_key (ksba_priv_key_t priv_key)
{
  AsnNode n;
  gpg_error_t err;
  ksba_sexp_t string;

  if (!priv_key)
    return NULL;
  if (!priv_key->initialized)
    return NULL;

  n = _ksba_asn_find_node (priv_key->root,
                           "PrivateKeyInfo");
  if (!n)
    {
      priv_key->last_error = gpg_error (GPG_ERR_NO_VALUE);
      return NULL;
    }

  err = _ksba_privkey_to_sexp (priv_key->image + n->off, n->nhdr + n->len,
                               &string);
  if (err)
    {
      priv_key->last_error = err;
      return NULL;
    }

  return string;
}
