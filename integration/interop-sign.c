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

/* Makes OpenSSH certificates with gf_cert_sign, as ssh-keygen -s does, to be
   checked by OpenSSH.

     interop-sign --ca FILE --key FILE.pub --out FILE-cert.pub --id ID
                  --principals A,B [--host] [--serial N] [--from SECONDS]
                  [--to SECONDS] [--allow pty,port-forwarding,agent-forwarding,
                  x11-forwarding,user-rc|all] [--force-command CMD]
                  [--source-address LIST] [--verify-required] [--alg NAME]

   FILE is the CA's OpenSSH private key (unprotected) and FILE.pub the public
   key to certify, as ssh-keygen writes it.  Exit 0 and the certificate line
   in OUT, or 1 and a message.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>

static char *
slurp (const char *path, size_t *len)
{
  FILE *f = fopen (path, "rb");
  char *b;
  long n;

  if (f == NULL)
    return NULL;
  fseek (f, 0, SEEK_END);
  n = ftell (f);
  fseek (f, 0, SEEK_SET);
  b = malloc ((size_t) n + 1);
  if (b != NULL && fread (b, 1, (size_t) n, f) != (size_t) n)
    {
      free (b);
      b = NULL;
    }
  fclose (f);
  if (b != NULL)
    {
      b[n] = '\0';
      *len = (size_t) n;
    }
  return b;
}

static unsigned
allow_bits (char *list)
{
  static const struct
  {
    const char *name;
    unsigned bit;
  } t[] = {
    { "pty", GF_CERT_ALLOW_PTY },
    { "port-forwarding", GF_CERT_ALLOW_PORT_FORWARDING },
    { "agent-forwarding", GF_CERT_ALLOW_AGENT_FORWARDING },
    { "x11-forwarding", GF_CERT_ALLOW_X11_FORWARDING },
    { "user-rc", GF_CERT_ALLOW_USER_RC },
    { "all", GF_CERT_ALLOW_ALL }
  };
  unsigned bits = 0;
  char *tok;

  for (tok = strtok (list, ","); tok != NULL; tok = strtok (NULL, ","))
    {
      size_t i;

      for (i = 0; i < sizeof t / sizeof t[0]; i++)
        if (strcmp (tok, t[i].name) == 0)
          bits |= t[i].bit;
    }
  return bits;
}

int
main (int argc, char **argv)
{
  const char *ca_path = NULL, *key_path = NULL, *out_path = NULL;
  const char *principals = NULL, *alg_name = NULL;
  gf_cert_spec sp;
  gf_key *ca = NULL, *subject = NULL, *cert = NULL;
  char *text, *pl, *tok, *allow = NULL;
  const char *plist[64];
  size_t n, tl;
  char out[8192];
  int i, rc;
  enum gf_sigalg alg = 0;
  FILE *f;

  memset (&sp, 0, sizeof sp);
  sp.type = GF_CERT_USER;
  sp.serial = 1;
  sp.valid_after = 0;
  sp.valid_before = UINT64_MAX - 1;
  for (i = 1; i < argc; i++)
    {
      const char *a = argv[i];
      const char *v = i + 1 < argc ? argv[i + 1] : NULL;

      if (strcmp (a, "--host") == 0)
        sp.type = GF_CERT_HOST;
      else if (strcmp (a, "--verify-required") == 0)
        sp.verify_required = 1;
      else if (v == NULL)
        {
          fprintf (stderr, "%s needs a value\n", a);
          return 1;
        }
      else if (strcmp (a, "--ca") == 0)
        ca_path = argv[++i];
      else if (strcmp (a, "--key") == 0)
        key_path = argv[++i];
      else if (strcmp (a, "--out") == 0)
        out_path = argv[++i];
      else if (strcmp (a, "--id") == 0)
        sp.key_id = argv[++i];
      else if (strcmp (a, "--principals") == 0)
        principals = argv[++i];
      else if (strcmp (a, "--serial") == 0)
        sp.serial = strtoull (argv[++i], NULL, 10);
      else if (strcmp (a, "--from") == 0)
        sp.valid_after = strtoull (argv[++i], NULL, 10);
      else if (strcmp (a, "--to") == 0)
        sp.valid_before = strtoull (argv[++i], NULL, 10);
      else if (strcmp (a, "--allow") == 0)
        allow = argv[++i];
      else if (strcmp (a, "--force-command") == 0)
        sp.force_command = argv[++i];
      else if (strcmp (a, "--source-address") == 0)
        sp.source_address = argv[++i];
      else if (strcmp (a, "--alg") == 0)
        alg_name = argv[++i];
      else
        {
          fprintf (stderr, "unknown option %s\n", a);
          return 1;
        }
    }
  if (ca_path == NULL || key_path == NULL || out_path == NULL
      || principals == NULL || sp.key_id == NULL)
    {
      fprintf (stderr, "usage: interop-sign --ca FILE --key FILE.pub --out FILE "
               "--id ID --principals A,B [options]\n");
      return 1;
    }
  if (gf_crypto_init () != GF_OK)
    return 1;
  if (alg_name != NULL)
    {
      alg = gf_sigalg_from_name (alg_name, strlen (alg_name));
      if (alg == 0)
        {
          fprintf (stderr, "unknown algorithm %s\n", alg_name);
          return 1;
        }
    }
  if (allow != NULL)
    {
      char *c = strdup (allow);

      sp.allow = allow_bits (c);
      free (c);
    }
  pl = strdup (principals);
  for (tok = strtok (pl, ","); tok != NULL && sp.nprincipals < 64;
       tok = strtok (NULL, ","))
    plist[sp.nprincipals++] = tok;
  sp.principals = plist;

  text = slurp (ca_path, &tl);
  if (text == NULL || gf_key_from_openssh_private (&ca, text, tl) != GF_OK)
    {
      fprintf (stderr, "cannot read the CA key %s\n", ca_path);
      return 1;
    }
  free (text);
  text = slurp (key_path, &tl);
  if (text == NULL || gf_key_from_text (&subject, text, tl, NULL) != GF_OK)
    {
      fprintf (stderr, "cannot read the public key %s\n", key_path);
      return 1;
    }
  free (text);
  rc = gf_cert_sign (&cert, ca, subject, &sp, alg);
  if (rc != GF_OK)
    {
      fprintf (stderr, "gf_cert_sign: %d\n", rc);
      return 1;
    }
  if (gf_key_to_text (cert, out, sizeof out, &n) != GF_OK)
    return 1;
  f = fopen (out_path, "wb");
  if (f == NULL || fwrite (out, 1, n, f) != n || fclose (f) != 0)
    return 1;
  gf_key_free (cert);
  gf_key_free (subject);
  gf_key_free (ca);
  free (pl);
  return 0;
}
