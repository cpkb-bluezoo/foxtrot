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
/* Sign an OpenSSH certificate for a public key.

     cert-sign -s CAKEY -I KEYID -n PRINCIPALS [-z SERIAL] [-h]
               [-V SECONDS] [-O OPTION]... PUBKEY

   The ssh-keygen -s of this library, for the few things most certificates
   need.  CAKEY is the CA's private key (any format keyinfo(1) reads);
   PUBKEY is the public key to certify; PRINCIPALS is a comma separated list
   of user names (or host names with -h).  The certificate is written to
   PUBKEY with "-cert" before the ".pub".  It is good for SECONDS from now
   (default one day): every certificate must end.  Options (-O, user
   certificates): permit-pty, permit-port-forwarding, permit-agent-forwarding,
   permit-X11-forwarding, permit-user-rc, force-command=COMMAND,
   source-address=LIST, verify-required.  With none, the certificate permits
   nothing, which is not what ssh-keygen does by default.  A serial
   defaults to the time, and is not 0.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "example.h"

int
main (int argc, char **argv)
{
  gf_cert_spec sp;
  const char *ca_path = NULL, *key_path = NULL, *principals = NULL;
  const char *plist[64];
  char *pl, *tok, *pubfile, *cert;
  gf_key *ca = NULL, *subject = NULL, *c = NULL;
  uint64_t now = (uint64_t) time (NULL), valid = 86400;
  char out[8192];
  size_t n, i;
  int rc;
  FILE *f;

  memset (&sp, 0, sizeof sp);
  sp.type = GF_CERT_USER;
  sp.serial = now;
  for (i = 1; i < (size_t) argc; i++)
    {
      const char *a = argv[i], *v = i + 1 < (size_t) argc ? argv[i + 1] : NULL;

      if (strcmp (a, "-h") == 0)
        sp.type = GF_CERT_HOST;
      else if (strcmp (a, "-s") == 0 && v)
        ca_path = argv[++i];
      else if (strcmp (a, "-I") == 0 && v)
        sp.key_id = argv[++i];
      else if (strcmp (a, "-n") == 0 && v)
        principals = argv[++i];
      else if (strcmp (a, "-z") == 0 && v)
        sp.serial = strtoull (argv[++i], NULL, 10);
      else if (strcmp (a, "-V") == 0 && v)
        valid = strtoull (argv[++i], NULL, 10);
      else if (strcmp (a, "-O") == 0 && v)
        {
          const char *o = argv[++i];

          if (strcmp (o, "permit-pty") == 0)
            sp.allow |= GF_CERT_ALLOW_PTY;
          else if (strcmp (o, "permit-port-forwarding") == 0)
            sp.allow |= GF_CERT_ALLOW_PORT_FORWARDING;
          else if (strcmp (o, "permit-agent-forwarding") == 0)
            sp.allow |= GF_CERT_ALLOW_AGENT_FORWARDING;
          else if (strcmp (o, "permit-X11-forwarding") == 0)
            sp.allow |= GF_CERT_ALLOW_X11_FORWARDING;
          else if (strcmp (o, "permit-user-rc") == 0)
            sp.allow |= GF_CERT_ALLOW_USER_RC;
          else if (strncmp (o, "force-command=", 14) == 0)
            sp.force_command = o + 14;
          else if (strncmp (o, "source-address=", 15) == 0)
            sp.source_address = o + 15;
          else if (strcmp (o, "verify-required") == 0)
            sp.verify_required = 1;
          else
            {
              fprintf (stderr, "cert-sign: unknown option %s\n", o);
              return 2;
            }
        }
      else if (a[0] != '-' && key_path == NULL)
        key_path = a;
      else
        {
          fprintf (stderr, "cert-sign: unexpected %s\n", a);
          return 2;
        }
    }
  if (ca_path == NULL || key_path == NULL || principals == NULL
      || sp.key_id == NULL)
    {
      fprintf (stderr, "usage: cert-sign -s CAKEY -I KEYID -n PRINCIPALS "
               "[-z SERIAL] [-h] [-V SECONDS] [-O OPTION]... PUBKEY\n");
      return 2;
    }
  sp.valid_after = now - 60;			/* A little for clocks.  */
  sp.valid_before = now + valid;
  pl = strdup (principals);
  for (tok = strtok (pl, ","); tok != NULL && sp.nprincipals < 64;
       tok = strtok (NULL, ","))
    plist[sp.nprincipals++] = tok;
  sp.principals = plist;
  rc = load_key (&ca, ca_path, getenv ("CERT_SIGN_PASSPHRASE"));
  if (rc != GF_OK || !gf_key_has_private (ca))
    {
      fprintf (stderr, "cert-sign: cannot use %s as a CA key (%d)\n", ca_path, rc);
      return 1;
    }
  rc = load_key (&subject, key_path, NULL);
  if (rc != GF_OK)
    {
      fprintf (stderr, "cert-sign: cannot read %s (%d)\n", key_path, rc);
      return 1;
    }
  rc = gf_cert_sign (&c, ca, subject, &sp, 0);
  if (rc != GF_OK)
    {
      /* The library refuses what would be a mistake to sign.  */
      fprintf (stderr, "cert-sign: refused (status %d): check the key ID, "
               "principals, serial and options\n", rc);
      return 1;
    }
  gf_key_to_text (c, out, sizeof out, &n);
  /* PUBKEY.pub becomes PUBKEY-cert.pub.  */
  pubfile = strdup (key_path);
  cert = malloc (strlen (key_path) + 16);
  {
    size_t kl = strlen (pubfile);

    if (kl > 4 && strcmp (pubfile + kl - 4, ".pub") == 0)
      pubfile[kl - 4] = '\0';
    sprintf (cert, "%s-cert.pub", pubfile);
  }
  f = fopen (cert, "w");
  if (f == NULL || fwrite (out, 1, n, f) != n || fclose (f) != 0)
    {
      fprintf (stderr, "cert-sign: cannot write %s\n", cert);
      return 1;
    }
  printf ("wrote %s\n", cert);
  gf_key_free (c);
  gf_key_free (subject);
  gf_key_free (ca);
  free (pl);
  free (pubfile);
  free (cert);
  return 0;
}
