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

    /* Five plain algorithms, the same five as OpenSSH certificates, then
       the three X.509 ones.  */
    CHECK_EQ (n, 13);
    for (i = 0; i < n; i++)
      {
        const char *name = gf_sigalg_name (s[i]);

        CHECK_EQ (gf_sigalg_is_cert (s[i]), i >= 5 && i < 10);
        CHECK_EQ (gf_sigalg_is_x509 (s[i]), i >= 10);

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
  /* Host keys and signatures: SHA-1 RSA, DSA, P-521, and certificates
     whose key or signature would be refused as a plain key.  */
  REFUSED (gf_sigalg_from_name, "ssh-rsa");
  REFUSED (gf_sigalg_from_name, "ssh-dss");
  REFUSED (gf_sigalg_from_name, "ecdsa-sha2-nistp521");
  REFUSED (gf_sigalg_from_name, "ssh-ed448");
  REFUSED (gf_sigalg_from_name, "ssh-rsa-cert-v01@openssh.com");
  REFUSED (gf_sigalg_from_name, "ssh-dss-cert-v01@openssh.com");
  REFUSED (gf_sigalg_from_name, "ecdsa-sha2-nistp521-cert-v01@openssh.com");
  REFUSED (gf_sigalg_from_name, "rsa-sha2-384-cert-v01@openssh.com");
  REFUSED (gf_sigalg_from_name, "sk-ecdsa-sha2-nistp384@openssh.com");
  REFUSED (gf_sigalg_from_name, "sk-ssh-ed25519@openssh");
  REFUSED (gf_sigalg_from_name, "ecdsa-sha2-nistp256@openssh.com");
  REFUSED (gf_sigalg_from_name, "x509v3-ssh-rsa");
  REFUSED (gf_sigalg_from_name, "x509v3-ssh-dss");
  REFUSED (gf_sigalg_from_name, "x509v3-ecdsa-sha2-nistp521");
  REFUSED (gf_sigalg_from_name, "x509v3-rsa2048-sha1");
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
  /* X.509 (RFC 6187): the three that are not SHA-1 and not P-521.  */
  CHECK_EQ (gf_sigalg_from_name ("x509v3-ecdsa-sha2-nistp256", 26), GF_SIG_X509_ECDSA_NISTP256);
  CHECK_EQ (gf_sigalg_from_name ("x509v3-ecdsa-sha2-nistp384", 26), GF_SIG_X509_ECDSA_NISTP384);
  CHECK_EQ (gf_sigalg_from_name ("x509v3-rsa2048-sha256", 21), GF_SIG_X509_RSA2048_SHA256);
  CHECK (gf_sigalg_is_x509 (GF_SIG_X509_RSA2048_SHA256));
  CHECK (!gf_sigalg_is_x509 (GF_SIG_RSA_SHA2_256));
  CHECK (!gf_sigalg_is_cert (GF_SIG_X509_ECDSA_NISTP256));
  CHECK (!gf_sigalg_is_user_only (GF_SIG_X509_ECDSA_NISTP256));
  CHECK_EQ (gf_sigalg_base (GF_SIG_X509_RSA2048_SHA256), GF_SIG_X509_RSA2048_SHA256);
  CHECK (strcmp (gf_sigalg_key_type (GF_SIG_X509_ECDSA_NISTP384),
                 "x509v3-ecdsa-sha2-nistp384") == 0);
  /* Security keys: for users, never for a host.  */
  CHECK_EQ (gf_sigalg_from_name ("sk-ssh-ed25519@openssh.com", 26), GF_SIG_SK_ED25519);
  CHECK_EQ (gf_sigalg_from_name ("sk-ecdsa-sha2-nistp256@openssh.com", 34),
            GF_SIG_SK_ECDSA_NISTP256);
  CHECK (gf_sigalg_is_user_only (GF_SIG_SK_ED25519));
  CHECK (gf_sigalg_is_user_only (GF_SIG_SK_ECDSA_NISTP256_CERT));
  CHECK (!gf_sigalg_is_user_only (GF_SIG_ED25519));
  CHECK (!gf_sigalg_is_user_only (GF_SIG_RSA_SHA2_256_CERT));
  CHECK_EQ (gf_sigalg_base (GF_SIG_SK_ED25519_CERT), GF_SIG_SK_ED25519);
  CHECK (gf_sigalg_is_cert (GF_SIG_SK_ECDSA_NISTP256_CERT));
  CHECK (strcmp (gf_sigalg_signature_name (GF_SIG_SK_ECDSA_NISTP256_CERT),
                 "sk-ecdsa-sha2-nistp256@openssh.com") == 0);
  {
    size_t n, i;
    const enum gf_sigalg *d = gf_policy_default_sigalgs (&n);
    const enum gf_sigalg *u = gf_policy_user_sigalgs (&n);

    /* No host key list has one; the user list has the plain ones and the
       two security keys, and nothing that is a certificate.  */
    for (i = 0; i < 13; i++)
      CHECK (!gf_sigalg_is_user_only (d[i]));
    CHECK_EQ (n, 7);
    for (i = 0; i < n; i++)
      CHECK (!gf_sigalg_is_cert (u[i]));
    CHECK_EQ (u[5], GF_SIG_SK_ED25519);
    CHECK_EQ (u[6], GF_SIG_SK_ECDSA_NISTP256);
  }
  /* Certificate algorithms.  */
  CHECK_EQ (gf_sigalg_from_name ("ssh-ed25519-cert-v01@openssh.com", 32),
            GF_SIG_ED25519_CERT);
  CHECK_EQ (gf_sigalg_from_name ("rsa-sha2-512-cert-v01@openssh.com", 33),
            GF_SIG_RSA_SHA2_512_CERT);
  CHECK (gf_sigalg_is_cert (GF_SIG_RSA_SHA2_256_CERT));
  CHECK (!gf_sigalg_is_cert (GF_SIG_RSA_SHA2_256));
  CHECK_EQ (gf_sigalg_base (GF_SIG_RSA_SHA2_256_CERT), GF_SIG_RSA_SHA2_256);
  CHECK_EQ (gf_sigalg_base (GF_SIG_ECDSA_NISTP384_CERT), GF_SIG_ECDSA_NISTP384);
  CHECK_EQ (gf_sigalg_base (GF_SIG_ED25519), GF_SIG_ED25519);
  CHECK (strcmp (gf_sigalg_signature_name (GF_SIG_RSA_SHA2_512_CERT),
                 "rsa-sha2-512") == 0);
  CHECK (strcmp (gf_sigalg_signature_name (GF_SIG_ED25519),
                 "ssh-ed25519") == 0);
  CHECK (strcmp (gf_sigalg_key_type (GF_SIG_RSA_SHA2_256_CERT),
                 "ssh-rsa-cert-v01@openssh.com") == 0);
  CHECK (gf_sigalg_matches_key_type (GF_SIG_RSA_SHA2_512_CERT,
                                     "ssh-rsa-cert-v01@openssh.com", 28));
  CHECK (!gf_sigalg_matches_key_type (GF_SIG_RSA_SHA2_512_CERT, "ssh-rsa", 7));
}

int
main (void)
{
  test_defaults ();
  test_absent ();
  test_names_are_exact ();
  TST_DONE ();
}
