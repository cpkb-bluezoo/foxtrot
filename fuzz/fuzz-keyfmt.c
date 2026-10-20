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

/* A key file in one of the other formats: the first byte says which (0: PEM,
   1: PEM with a passphrase, 2: RFC 4716, 3: PuTTY, 4: PuTTY with a
   passphrase) and the rest is the file.  A key that is read can be written
   in the formats that take a public key and read back as itself.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>
#include <foxtrot/keyfmt.h>

#include "fuzz-common.h"

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  return 0;
}

static void
die (const char *what)
{
  fprintf (stderr, "keyfmt: %s\n", what);
  abort ();
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  static char text[70000];
  char out[8192], comment[64];
  gf_key *k = NULL, *back = NULL;
  size_t n;
  int rc;

  if (size < 1 || size > sizeof text)
    return 0;
  memcpy (text, data + 1, size - 1);
  switch (data[0] % 5)
    {
    case 0:
      rc = gf_key_from_pem (&k, text, size - 1, NULL);
      break;
    case 1:
      rc = gf_key_from_pem (&k, text, size - 1, "correct horse");
      break;
    case 2:
      rc = gf_key_from_rfc4716 (&k, text, size - 1, comment, sizeof comment);
      break;
    case 3:
      rc = gf_key_from_ppk (&k, text, size - 1, NULL, comment, sizeof comment);
      break;
    default:
      rc = gf_key_from_ppk (&k, text, size - 1, "correct horse", comment,
                            sizeof comment);
      break;
    }
  if ((rc == GF_OK) != (k != NULL))
    die ("status and key disagree");
  if (k == NULL)
    return 0;
  if (gf_key_is_certificate (k))
    die ("a certificate was read as a key");
  if (data[0] % 5 == 2 && gf_key_has_private (k))
    die ("a public key file gave a private key");
  /* The public forms: out and back in.  */
  if (gf_key_to_pem_public (k, out, sizeof out, &n) != GF_OK)
    die ("cannot write the SPKI");
  if (gf_key_from_pem (&back, out, n, NULL) != GF_OK || !gf_key_equal (back, k)
      || gf_key_has_private (back))
    die ("the SPKI does not read back");
  gf_key_free (back);
  back = NULL;
  if (gf_key_to_rfc4716 (k, "c", out, sizeof out, &n) != GF_OK
      || gf_key_from_rfc4716 (&back, out, n, NULL, 0) != GF_OK
      || !gf_key_equal (back, k))
    die ("RFC 4716 does not read back");
  gf_key_free (back);
  if (gf_key_randomart (k, out, sizeof out, &n) != GF_OK || n == 0)
    die ("no randomart");
  gf_key_free (k);
  return 0;
}
