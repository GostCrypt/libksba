/* t-privkey.c - basic test for the Private Keys parser.
 *      Copyright (C) 2014 Dmitry Eremin-Solenikov
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * KSBA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#include "../src/ksba.h"

#include "t-common.h"
#include "oidtranstbl.h"

/* Return the description for OID; if no description is available
   NULL is returned. */
static const char *
get_oid_desc (const char *oid)
{
  int i;

  if (oid)
    for (i=0; oidtranstbl[i].oid; i++)
      if (!strcmp (oidtranstbl[i].oid, oid))
        return oidtranstbl[i].desc;
  return NULL;
}



static void
one_file (const char *fname)
{
  gpg_error_t err;
  FILE *fp;
  ksba_reader_t r;
  ksba_priv_key_t priv_key;
  ksba_sexp_t key;


  printf ("*** checking `%s' ***\n", fname);
  fp = fopen (fname, "r");
  if (!fp)
    {
      fprintf (stderr, "%s:%d: can't open `%s': %s\n",
               __FILE__, __LINE__, fname, strerror (errno));
      exit (1);
    }

  err = ksba_reader_new (&r);
  if (err)
    fail_if_err (err);
  err = ksba_reader_set_file (r, fp);
  fail_if_err (err);

  err = ksba_priv_key_new (&priv_key);
  if (err)
    fail_if_err (err);

  err = ksba_priv_key_parse_der (priv_key, r);
  fail_if_err2 (fname, err);

  key = ksba_priv_key_get_private_key (priv_key);
  if (!key)
    fail ("no private key");

  fputs ("private key: ", stdout);
  print_sexp (key);
  putchar ('\n');


  ksba_priv_key_release (priv_key);
  ksba_reader_release (r);
  fclose (fp);
}




int
main (int argc, char **argv)
{
  const char *srcdir = getenv ("srcdir");

  if (!srcdir)
    srcdir = ".";

  if (argc > 1)
    {
      for (argc--, argv++; argc; argc--, argv++)
        one_file (*argv);
    }
  else
    {
      const char *files[] = {
        "privkey.der",
        NULL
      };
      int idx;

      for (idx=0; files[idx]; idx++)
        {
          char *fname;

          fname = xmalloc (strlen (srcdir) + 1 + strlen (files[idx]) + 1);
          strcpy (fname, srcdir);
          strcat (fname, "/");
          strcat (fname, files[idx]);
          one_file (fname);
          xfree (fname);
        }
    }

  return 0;
}
