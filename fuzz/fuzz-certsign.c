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

/* gf_cert_sign with whatever fields.  [type][allow][flags][serial 8]
   [valid after 8][valid before 8] then length-prefixed strings: key ID,
   command, source address, and as many principals as are left.  What it
   signs must read back as exactly what was asked, and what it refuses must
   not leave a certificate.  */

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

#include "fuzz-common.h"

static gf_key *ca, *subject, *rsa;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  if (gf_key_generate (&ca, GF_KEY_ED25519, 0) != GF_OK
      || gf_key_generate (&subject, GF_KEY_ECDSA_P256, 0) != GF_OK
      || gf_key_generate (&rsa, GF_KEY_RSA, 2048) != GF_OK)
    abort ();
  return 0;
}

static uint64_t
u64 (const uint8_t *p)
{
  uint64_t v = 0;
  int i;

  for (i = 0; i < 8; i++)
    v = v << 8 | p[i];
  return v;
}

static void
die (const char *what)
{
  fprintf (stderr, "gf_cert_sign: %s\n", what);
  abort ();
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  static char strs[4][600];
  char *princ[16];
  static char pbuf[16][300];
  gf_cert_spec sp;
  gf_key *c = NULL;
  size_t i, np = 0;
  int rc, ok;

  if (size < 27)
    return 0;
  memset (&sp, 0, sizeof sp);
  sp.type = data[0] % 4;	/* 0 and 3 are no type.  */
  sp.allow = data[1];
  sp.verify_required = data[2] & 1;
  sp.serial = u64 (data + 3);
  sp.valid_after = u64 (data + 11);
  sp.valid_before = u64 (data + 19);
  data += 27;
  size -= 27;
  for (i = 0; i < 3; i++)
    {
      size_t l;

      if (!fuzz_take (&data, &size, strs[i], sizeof strs[i], &l))
        strs[i][0] = '\0';
    }
  while (np < 16)
    {
      size_t l;

      if (!fuzz_take (&data, &size, pbuf[np], sizeof pbuf[np], &l))
        break;
      princ[np] = pbuf[np];
      np++;
    }
  sp.key_id = strs[0];
  sp.force_command = strs[1][0] ? strs[1] : NULL;
  sp.source_address = strs[2][0] ? strs[2] : NULL;
  sp.principals = (const char *const *) princ;
  sp.nprincipals = np;

  rc = gf_cert_sign (&c, ca, (sp.serial & 1) ? rsa : subject, &sp, 0);
  if (rc != GF_OK)
    {
      if (c != NULL)
        die ("refused, but returned a certificate");
      return 0;
    }
  if (c == NULL || !gf_key_is_certificate (c))
    die ("signed, but no certificate");
  {
    gf_cert_info ci;
    gf_slice n, d;
    size_t pos = 0;

    if (gf_key_certificate_info (c, &ci) != GF_OK || ci.serial != sp.serial
        || ci.type != sp.type || ci.valid_after != sp.valid_after
        || ci.valid_before != sp.valid_before
        || !gf_slice_equals (ci.key_id, sp.key_id) || !gf_key_equal (ci.ca, ca))
      die ("fields not as asked");
    ok = 0;
    for (i = 0; i < np; i++)
      {
        if (!gf_cert_principal_next (c, &pos, &n) || !gf_slice_equals (n, princ[i]))
          die ("principals not as asked");
        ok++;
      }
    if (gf_cert_principal_next (c, &pos, &n))
      die ("more principals than asked");
    if (sp.type == GF_CERT_USER)
      {
        gf_slice v;
        int fc = gf_cert_critical_option (c, "force-command", &v);

        if (fc != (sp.force_command != NULL)
            || (fc == 1 && !gf_slice_equals (v, sp.force_command)))
          die ("force-command not as asked");
        pos = 0;
        i = 0;
        while (gf_cert_extension_next (c, &pos, &n, &d))
          i++;
        if (i != (size_t) __builtin_popcount (sp.allow & GF_CERT_ALLOW_ALL))
          die ("extensions not as asked");
      }
    if (gf_cert_check (c, sp.type, sp.valid_after, NULL) != GF_OK)
      die ("not valid at the start");
    if (gf_cert_check (c, sp.type, sp.valid_before, NULL) == GF_OK)
      die ("valid at the end");
  }
  gf_key_free (c);
  return 0;
}
