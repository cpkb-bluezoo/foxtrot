/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of foxtrot.

   foxtrot is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   foxtrot is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */
/* Ask a key revocation list about keys.

     krl-check KRLFILE KEYFILE...

   KRLFILE is the file ssh-keygen -k writes; each KEYFILE is a public key or
   an OpenSSH certificate (a .pub file, or an -cert.pub file).  Prints
   "REVOKED" or "ok" and the file name.  The answers are those of
   ssh-keygen -Q.

   Exit status: 0 if none is revoked, 1 if one is, 2 for a file that could
   not be read.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <foxtrot/krl.h>

#include "example.h"

int
main (int argc, char **argv)
{
  gf_krl *krl = NULL;
  size_t n;
  char *list;
  int i, status = 0, rc;

  if (argc < 3)
    {
      fprintf (stderr, "usage: krl-check KRLFILE KEYFILE...\n");
      return 2;
    }
  list = read_file (argv[1], &n);
  if (list == NULL || gf_krl_new (&krl) != GF_OK)
    {
      fprintf (stderr, "krl-check: cannot read %s\n", argv[1]);
      return 2;
    }
  /* A list is refused whole if the library does not understand all of it:
     a revocation that is not understood is never ignored.  */
  rc = gf_krl_load (krl, (const uint8_t *) list, n);
  free (list);
  if (rc != GF_OK)
    {
      fprintf (stderr, "krl-check: %s was refused (status %d)\n", argv[1], rc);
      return 2;
    }
  for (i = 2; i < argc; i++)
    {
      gf_key *key = NULL;

      if (load_key (&key, argv[i], NULL) != GF_OK)
        {
          fprintf (stderr, "krl-check: cannot read %s\n", argv[i]);
          status = 2;
          continue;
        }
      /* Anything but 0 is to be treated as revoked.  */
      rc = gf_krl_check (krl, key);
      printf ("%s %s\n", rc == 0 ? "ok" : "REVOKED", argv[i]);
      if (rc != 0 && status == 0)
        status = 1;
      gf_key_free (key);
    }
  gf_krl_free (krl);
  return status;
}
