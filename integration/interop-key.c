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

/* Passphrase-protected private key files, against ssh-keygen.

     interop-key decrypt FILE PASSPHRASE          prints the public key
     interop-key encrypt FILE PASSPHRASE OUT      writes FILE encrypted to OUT
     interop-key roundtrip FILE PASSPHRASE        encrypts, decrypts, prints

   FILE is an OpenSSH private key file, protected or not.  The library has no
   bcrypt-pbkdf, so this program, like an application, supplies one: it asks
   python3's bcrypt module for it.  That is for testing; the passphrase is on
   the command line of the helper for a moment.  Exit 0 for success, 3 for a
   wrong passphrase, 1 for anything else.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>

static int
bcrypt_via_python (void *user, const uint8_t *pass, size_t passlen,
                   const uint8_t *salt, size_t saltlen, uint32_t rounds,
                   uint8_t *out, size_t outlen)
{
  char cmd[1024], hex[256];
  size_t i, o = 0;
  FILE *p;

  (void) user;
  if (passlen * 2 + saltlen * 2 + 200 > sizeof cmd)
    return 1;
  o = (size_t) snprintf (cmd, sizeof cmd,
    "python3 -c 'import sys,bcrypt; a=sys.argv; "
    "sys.stdout.write(bcrypt.kdf(bytes.fromhex(a[1]), bytes.fromhex(a[2]), "
    "int(a[3]), int(a[4]), ignore_few_rounds=True).hex())' ");
  for (i = 0; i < passlen; i++)
    {
      if (i == 0)
        cmd[o++] = '\'';
      o += (size_t) snprintf (cmd + o, sizeof cmd - o, "%02x", pass[i]);
    }
  if (passlen == 0)
    cmd[o++] = '\'';
  o += (size_t) snprintf (cmd + o, sizeof cmd - o, "' ");
  cmd[o++] = '\'';
  for (i = 0; i < saltlen; i++)
    o += (size_t) snprintf (cmd + o, sizeof cmd - o, "%02x", salt[i]);
  o += (size_t) snprintf (cmd + o, sizeof cmd - o, "' %zu %u", outlen,
                          (unsigned) rounds);
  p = popen (cmd, "r");
  if (p == NULL)
    return 1;
  if (fread (hex, 1, outlen * 2, p) != outlen * 2)
    {
      pclose (p);
      return 1;
    }
  if (pclose (p) != 0)
    return 1;
  for (i = 0; i < outlen; i++)
    {
      unsigned v;

      if (sscanf (hex + 2 * i, "%2x", &v) != 1)
        return 1;
      out[i] = (uint8_t) v;
    }
  return 0;
}

static char *
slurp (const char *file, size_t *n)
{
  FILE *f = fopen (file, "r");
  char *buf = malloc (65536);

  if (f == NULL || buf == NULL)
    return NULL;
  *n = fread (buf, 1, 65535, f);
  fclose (f);
  buf[*n] = 0;
  return buf;
}

static int
show (const gf_key *k)
{
  char line[4096], fp[64];

  if (gf_key_to_text (k, line, sizeof line, NULL) != GF_OK
      || gf_key_fingerprint (k, fp, sizeof fp) != GF_OK)
    return 1;
  printf ("PUB %s\nFP %s\n", line, fp);
  return 0;
}

int
main (int argc, char **argv)
{
  size_t n;
  char *text;
  gf_key *k = NULL;
  int rc;

  if (argc < 4)
    {
      fprintf (stderr, "usage: interop-key decrypt|encrypt|roundtrip FILE PASSPHRASE [OUT]\n");
      return 2;
    }
  gf_crypto_init ();
  text = slurp (argv[2], &n);
  if (text == NULL)
    return 1;
  rc = gf_key_from_openssh_private_encrypted (&k, text, n, argv[3],
                                              bcrypt_via_python, NULL);
  if (rc != GF_OK)
    {
      fprintf (stderr, "cannot read %s: %s\n", argv[2], gf_strerror (rc));
      return rc == GF_ERR_PASSPHRASE ? 3 : 1;
    }
  if (strcmp (argv[1], "decrypt") == 0)
    return show (k);
  if (strcmp (argv[1], "encrypt") == 0 || strcmp (argv[1], "roundtrip") == 0)
    {
      char out[16384];
      size_t on;
      gf_key *back = NULL;

      rc = gf_key_to_openssh_private_encrypted (k, out, sizeof out, &on, argv[3],
                                                4, bcrypt_via_python, NULL);
      if (rc != GF_OK)
        return 1;
      if (strcmp (argv[1], "encrypt") == 0 && argc >= 5)
        {
          FILE *f = fopen (argv[4], "w");

          if (f == NULL || fwrite (out, 1, on, f) != on || fclose (f) != 0)
            return 1;
          return 0;
        }
      rc = gf_key_from_openssh_private_encrypted (&back, out, on, argv[3],
                                                  bcrypt_via_python, NULL);
      if (rc != GF_OK || !gf_key_equal (k, back))
        return 1;
      gf_key_free (back);
      return show (k);
    }
  return 2;
}
