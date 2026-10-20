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

/* authorized_keys text: [address length][address][name length][name]
   [user length][user][text].  */

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
#include <foxtrot/auth.h>
#include <foxtrot/authkeys.h>

#include "fuzz-common.h"
#include "vectors-cert.h"

#define NKEYS 5

static gf_key *keys[NKEYS];
static char edline[1024];

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  static uint8_t b[4096];
  size_t n, len;

  (void) argc;
  (void) argv;
  gf_crypto_init ();
  if (gf_key_generate (&keys[0], GF_KEY_ED25519, 0) != GF_OK
      || gf_key_generate (&keys[1], GF_KEY_ECDSA_P256, 0) != GF_OK
      || gf_key_generate (&keys[2], GF_KEY_RSA, 2048) != GF_OK)
    abort ();
  n = fuzz_unhex (vec_ed_user_cert, b, sizeof b);
  if (gf_key_from_blob (&keys[3], b, n) != GF_OK)
    abort ();
  n = fuzz_unhex (vec_forever_cert, b, sizeof b);
  if (gf_key_from_blob (&keys[4], b, n) != GF_OK)
    abort ();
  if (gf_key_to_text (keys[0], edline, sizeof edline - 2, &len) != GF_OK)
    abort ();
  return 0;
}

/* A length-prefixed string from the input, as a NUL-terminated copy.  */
static int
take (const uint8_t **p, size_t *n, char *out, size_t cap)
{
  size_t l;

  if (*n < 1)
    return 0;
  l = **p;
  (*p)++;
  (*n)--;
  if (l > *n)
    l = *n;
  if (l >= cap)
    l = cap - 1;
  memcpy (out, *p, l);
  out[l] = '\0';
  *p += l;
  *n -= l;
  return 1;
}

static void
touch (const gf_authkey_match *m, const char *host)
{
  static const char *const names[] = {
    GF_CERT_PERMIT_PTY, GF_CERT_PERMIT_PORT_FORWARDING,
    GF_CERT_PERMIT_AGENT_FORWARDING, GF_CERT_PERMIT_X11_FORWARDING,
    GF_CERT_PERMIT_USER_RC, "other"
  };
  gf_slice it;
  size_t pos, i;
  int w;

  if (m->line == 0)
    {
      fprintf (stderr, "a match with no line\n");
      abort ();
    }
  for (i = 0; i < sizeof names / sizeof names[0]; i++)
    (void) gf_authkey_permits (m, names[i]);
  (void) gf_authkey_permits_open (m, host, 22);
  (void) gf_authkey_permits_open (m, host, 0);
  (void) gf_authkey_permits_listen (m, host, 8080);
  (void) gf_authkey_permits_listen (m, NULL, 65535);
  for (w = GF_AUTHKEY_PERMITOPEN; w <= GF_AUTHKEY_ENVIRONMENT; w++)
    {
      pos = 0;
      while (gf_authkey_next (m, (enum gf_authkey_list) w, &pos, &it))
        if (it.len == 0 || it.data[it.len] != '\0')
          {
            fprintf (stderr, "an item that is empty or not terminated\n");
            abort ();
          }
    }
  if (m->command != NULL && m->command[0] == '\0')
    {
      fprintf (stderr, "an empty command\n");
      abort ();
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  static char addr[64], host[300], user[64];
  static char text[70000];
  gf_authkeys *t = NULL, *two = NULL;
  gf_authkey_match m;
  static const uint64_t times[] = { 1700000000u, 0, 4102444800u, UINT64_MAX };
  size_t bad, i, u, k, nt;
  const gf_key *cas[8];

  if (!take (&data, &size, addr, sizeof addr)
      || !take (&data, &size, host, sizeof host)
      || !take (&data, &size, user, sizeof user))
    return 0;
  if (size > 65536)
    size = 65536;
  memcpy (text, data, size);
  if (gf_authkeys_new (&t) != GF_OK)
    return 0;
  if (gf_authkeys_load (t, text, size, &bad) == GF_OK)
    {
      (void) gf_authkeys_cas (t, cas, 8);
      for (k = 0; k < NKEYS; k++)
        for (u = 0; u < 2; u++)
          for (i = 0; i < sizeof times / sizeof times[0]; i++)
            {
              gf_auth_request r;

              memset (&r, 0, sizeof r);
              r.method = GF_AUTH_PUBLICKEY;
              r.user.data = (const uint8_t *) (u ? "alice" : user);
              r.user.len = strlen (u ? "alice" : user);
              r.key = keys[k];
              r.has_signature = (int) (i & 1);
              r.sk_flags = (uint8_t) i;
              if (gf_authkeys_check (t, &r, addr[0] ? addr : NULL,
                                     host[0] ? host : NULL, times[i], &m) == 1)
                touch (&m, host);
            }
      /* Lines after it do not take back that a plain key line authorizes
         its key, whatever came before.  */
      nt = size;
      if (nt + strlen (edline) + 2 < sizeof text)
        {
          gf_auth_request r;

          text[nt++] = '\n';
          memcpy (text + nt, edline, strlen (edline));
          nt += strlen (edline);
          if (gf_authkeys_new (&two) == GF_OK
              && gf_authkeys_load (two, text, nt, &bad) == GF_OK)
            {
              memset (&r, 0, sizeof r);
              r.method = GF_AUTH_PUBLICKEY;
              r.user.data = (const uint8_t *) "alice";
              r.user.len = 5;
              r.key = keys[0];
              r.has_signature = 1;
              if (gf_authkeys_check (two, &r, "192.0.2.1", NULL, 1700000000u, NULL) != 1)
                {
                  fprintf (stderr, "a line that authorizes a key does not: %s\n",
                           edline);
                  abort ();
                }
            }
        }
    }
  gf_authkeys_free (t);
  gf_authkeys_free (two);
  return 0;
}
