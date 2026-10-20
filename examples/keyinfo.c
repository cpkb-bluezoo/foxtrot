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
/* Show what is in key files, whatever format they are in.

     keyinfo [-v] [-a] [-r] [-s] FILE...

   For each file: the type and size, the SHA-256 fingerprint (as ssh-keygen
   -l shows it), whether there is a private part, and the public key as an
   authorized_keys line.  -v adds the randomart picture, -r the key as an
   RFC 4716 public key file, -s as a PEM SPKI.  The formats are the ones the
   library reads: OpenSSH public and private keys (without a passphrase),
   RFC 4716, PEM and DER keys of OpenSSL's, and PuTTY files.  The passphrase
   of an encrypted PEM or PuTTY file is taken from KEYINFO_PASSPHRASE.

   Exit status: 0, or 1 if any file could not be read.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "example.h"

static void
show (const char *file, const gf_key *key, int art, int rfc, int spki)
{
  char fp[64], text[4096];
  size_t n;

  gf_key_fingerprint (key, fp, sizeof fp);
  printf ("%s: %s %u bits %s%s\n", file, gf_key_type_name (key),
          gf_key_bits (key), fp,
          gf_key_has_private (key) ? " (private key)" : "");
  /* The authorized_keys line (the text has no line end of its own).  */
  if (gf_key_to_text (key, text, sizeof text, &n) == GF_OK)
    printf ("%s\n", text);
  if (art && gf_key_randomart (key, text, sizeof text, &n) == GF_OK)
    printf ("%s", text);
  if (rfc && gf_key_to_rfc4716 (key, NULL, text, sizeof text, &n) == GF_OK)
    printf ("%s", text);
  if (spki && gf_key_to_pem_public (key, text, sizeof text, &n) == GF_OK)
    printf ("%s", text);
}

int
main (int argc, char **argv)
{
  int i, art = 0, rfc = 0, spki = 0, bad = 0;
  const char *pass = getenv ("KEYINFO_PASSPHRASE");

  for (i = 1; i < argc && argv[i][0] == '-' && argv[i][1] != '\0'; i++)
    {
      if (strcmp (argv[i], "-v") == 0)
        art = 1;
      else if (strcmp (argv[i], "-r") == 0)
        rfc = 1;
      else if (strcmp (argv[i], "-s") == 0)
        spki = 1;
      else
        {
          fprintf (stderr, "usage: keyinfo [-v] [-r] [-s] FILE...\n");
          return 2;
        }
    }
  if (i == argc)
    {
      fprintf (stderr, "usage: keyinfo [-v] [-r] [-s] FILE...\n");
      return 2;
    }
  for (; i < argc; i++)
    {
      gf_key *key = NULL;
      int rc = load_key (&key, argv[i], pass);

      if (rc != GF_OK)
        {
          fprintf (stderr, "%s: not read (status %d)\n", argv[i], rc);
          bad = 1;
          continue;
        }
      show (argv[i], key, art, rfc, spki);
      gf_key_free (key);
    }
  return bad;
}
