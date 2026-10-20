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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <foxtrot/status.h>
#include <foxtrot/policy.h>

#include "tst-util.h"

static void
test_defaults (void)
{
  size_t n, i;
  const enum gf_kex *kex = gf_policy_default_kex (&n);

  CHECK (n > 0);
  CHECK_EQ (kex[0], GF_KEX_MLKEM768X25519_SHA256);
  for (i = 0; i < n; i++)
    {
      const char *name = gf_kex_name (kex[i]);

      CHECK (name != NULL);
      CHECK_EQ (gf_kex_from_name (name, strlen (name)), kex[i]);
      CHECK (gf_kex_names (kex[i]) != NULL);
    }
  {
    const enum gf_sigalg *s = gf_policy_default_sigalgs (&n);

    CHECK_EQ (n, 5);
    for (i = 0; i < n; i++)
      {
        const char *name = gf_sigalg_name (s[i]);

        CHECK (name != NULL);
        CHECK_EQ (gf_sigalg_from_name (name, strlen (name)), s[i]);
        CHECK (gf_sigalg_matches_key_type (s[i], gf_sigalg_key_type (s[i]),
                                           strlen (gf_sigalg_key_type (s[i]))));
      }
  }
  {
    const enum gf_cipher *c = gf_policy_default_ciphers (&n);

    CHECK_EQ (n, 3);
    CHECK_EQ (c[0], GF_CIPHER_CHACHA20_POLY1305);
    for (i = 0; i < n; i++)
      {
        const char *name = gf_cipher_name (c[i]);

        CHECK (name != NULL);
        CHECK_EQ (gf_cipher_from_name (name, strlen (name)), c[i]);
      }
  }
}

#define REFUSED(from, name) CHECK_EQ (from (name, sizeof name - 1), 0)

/* Everything the manual says is absent is refused by name.  */
static void
test_absent (void)
{
  /* Key exchange: finite-field Diffie-Hellman in all its forms, SHA-1
     anything, legacy aliases, the P-521 curve.  */
  REFUSED (gf_kex_from_name, "diffie-hellman-group1-sha1");
  REFUSED (gf_kex_from_name, "diffie-hellman-group14-sha1");
  REFUSED (gf_kex_from_name, "diffie-hellman-group14-sha256");
  REFUSED (gf_kex_from_name, "diffie-hellman-group16-sha512");
  REFUSED (gf_kex_from_name, "diffie-hellman-group18-sha512");
  REFUSED (gf_kex_from_name, "diffie-hellman-group-exchange-sha1");
  REFUSED (gf_kex_from_name, "diffie-hellman-group-exchange-sha256");
  REFUSED (gf_kex_from_name, "ecdh-sha2-nistp521");
  REFUSED (gf_kex_from_name, "curve25519-sha256@libssh.org");
  REFUSED (gf_kex_from_name, "rsa1024-sha1");
  REFUSED (gf_kex_from_name, "gss-group14-sha256-");
  REFUSED (gf_kex_from_name, "ext-info-c");
  REFUSED (gf_kex_from_name, "kex-strict-c-v00@openssh.com");
  REFUSED (gf_kex_from_name, "");
  REFUSED (gf_kex_from_name, "curve25519-sha25");
  REFUSED (gf_kex_from_name, "curve25519-sha2566");
  /* Host keys and signatures: SHA-1 RSA, DSA, P-521, certificates.  */
  REFUSED (gf_sigalg_from_name, "ssh-rsa");
  REFUSED (gf_sigalg_from_name, "ssh-dss");
  REFUSED (gf_sigalg_from_name, "ecdsa-sha2-nistp521");
  REFUSED (gf_sigalg_from_name, "ssh-ed448");
  REFUSED (gf_sigalg_from_name, "ssh-rsa-cert-v01@openssh.com");
  REFUSED (gf_sigalg_from_name, "ssh-ed25519-cert-v01@openssh.com");
  REFUSED (gf_sigalg_from_name, "sk-ssh-ed25519@openssh.com");
  REFUSED (gf_sigalg_from_name, "x509v3-ssh-rsa");
  REFUSED (gf_sigalg_from_name, "rsa-sha2-384");
  /* Ciphers: CBC, CTR, stream ciphers, 3DES, none.  */
  REFUSED (gf_cipher_from_name, "none");
  REFUSED (gf_cipher_from_name, "3des-cbc");
  REFUSED (gf_cipher_from_name, "aes128-cbc");
  REFUSED (gf_cipher_from_name, "aes256-cbc");
  REFUSED (gf_cipher_from_name, "aes128-ctr");
  REFUSED (gf_cipher_from_name, "aes192-ctr");
  REFUSED (gf_cipher_from_name, "aes256-ctr");
  REFUSED (gf_cipher_from_name, "arcfour");
  REFUSED (gf_cipher_from_name, "arcfour128");
  REFUSED (gf_cipher_from_name, "blowfish-cbc");
  REFUSED (gf_cipher_from_name, "cast128-cbc");
  REFUSED (gf_cipher_from_name, "chacha20-poly1305");
  REFUSED (gf_cipher_from_name, "aes128-gcm");
  REFUSED (gf_cipher_from_name, "AES128-GCM@OPENSSH.COM");
  REFUSED (gf_cipher_from_name, "");
  CHECK_EQ (gf_cipher_name (GF_CIPHER_NONE), 0);
}

static void
test_names_are_exact (void)
{
  /* A name followed by garbage, or with an embedded NUL, is not the name.  */
  CHECK_EQ (gf_cipher_from_name ("chacha20-poly1305@openssh.com\0x", 31), 0);
  CHECK_EQ (gf_sigalg_from_name ("ssh-ed25519\0", 12), 0);
  CHECK_EQ (gf_kex_from_name ("curve25519-sha256\0", 18), 0);
  /* The OpenSSH name of the sntrup hybrid is the same method.  */
  CHECK_EQ (gf_kex_from_name ("sntrup761x25519-sha512", 22),
            GF_KEX_SNTRUP761X25519_SHA512);
  CHECK_EQ (gf_kex_from_name ("sntrup761x25519-sha512@openssh.com", 34),
            GF_KEX_SNTRUP761X25519_SHA512);
  CHECK (!gf_sigalg_matches_key_type (GF_SIG_RSA_SHA2_256, "rsa-sha2-256", 12));
  CHECK (gf_sigalg_matches_key_type (GF_SIG_RSA_SHA2_256, "ssh-rsa", 7));
  CHECK (gf_sigalg_matches_key_type (GF_SIG_RSA_SHA2_512, "ssh-rsa", 7));
  CHECK (!gf_sigalg_matches_key_type (GF_SIG_ED25519, "ssh-rsa", 7));
}

int
main (void)
{
  test_defaults ();
  test_absent ();
  test_names_are_exact ();
  TST_DONE ();
}
