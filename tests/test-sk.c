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

#include <stdio.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>

#include "tst-util.h"
#include "vectors-sk.h"

#define BLOBMAX 2048

static uint8_t msg[64];
static size_t msglen;

static gf_key *
blob_key (const char *hex)
{
  static uint8_t b[BLOBMAX];
  gf_key *k = NULL;
  size_t n = tst_unhex (hex, b, sizeof b);

  CHECK_EQ (gf_key_from_blob (&k, b, n), GF_OK);
  return k;
}

static int
verify (const gf_key *k, enum gf_sigalg alg, const char *sighex, const uint8_t *m,
        size_t ml, uint8_t *flags, uint32_t *counter)
{
  static uint8_t sig[BLOBMAX];
  size_t n = tst_unhex (sighex, sig, sizeof sig);

  return gf_key_verify_sk (k, alg, m, ml, sig, n, flags, counter);
}

static void
test_keys (void)
{
  static const struct
  {
    const char *blob, *pub;
    enum gf_keytype type;
    enum gf_sigalg alg;
    const char *name;
    const char *app;
  } v[] = {
    { vec_sk_ed_blob, vec_sk_ed_pub, GF_KEY_ED25519, GF_SIG_SK_ED25519,
      "sk-ssh-ed25519@openssh.com", "ssh:" },
    { vec_sk_p256_blob, vec_sk_p256_pub, GF_KEY_ECDSA_P256, GF_SIG_SK_ECDSA_NISTP256,
      "sk-ecdsa-sha2-nistp256@openssh.com", "ssh:" },
    { vec_sk_ed_app_blob, vec_sk_ed_app_pub, GF_KEY_ED25519, GF_SIG_SK_ED25519,
      "sk-ssh-ed25519@openssh.com", "ssh:foxtrot" }
  };
  size_t i;

  for (i = 0; i < 3; i++)
    {
      gf_key *k = blob_key (v[i].blob), *t = NULL;
      const uint8_t *app;
      size_t al, na;
      const enum gf_sigalg *a;
      char fp[64];

      if (k == NULL)
        continue;
      CHECK (gf_key_is_security_key (k));
      CHECK (!gf_key_is_certificate (k));
      CHECK (!gf_key_has_private (k));
      CHECK_EQ (gf_key_type (k), v[i].type);
      CHECK (strcmp (gf_key_type_name (k), v[i].name) == 0);
      app = gf_key_application (k, &al);
      CHECK (app != NULL && al == strlen (v[i].app) && memcmp (app, v[i].app, al) == 0);
      a = gf_key_sigalgs (k, &na);
      CHECK (na == 1 && a[0] == v[i].alg);
      CHECK_EQ (gf_key_fingerprint (k, fp, sizeof fp), GF_OK);
      CHECK (strncmp (fp, "SHA256:", 7) == 0);
      /* The text form, as ssh-keygen wrote it.  */
      CHECK_EQ (gf_key_from_text (&t, v[i].pub, strlen (v[i].pub), NULL), GF_OK);
      CHECK (t != NULL && gf_key_equal (k, t));
      gf_key_free (t);
      gf_key_free (k);
    }
  {
    gf_key *ed = blob_key (vec_sk_ed_blob), *app = blob_key (vec_sk_ed_app_blob);

    CHECK (!gf_key_equal (ed, app));	/* The application is part of the key. */
    gf_key_free (ed);
    gf_key_free (app);
  }
}

static void
test_verify (void)
{
  static const struct
  {
    const char *blob, *up, *upuv, *nouv, *noup, *other;
    enum gf_sigalg alg;
  } v[] = {
    { vec_sk_ed_blob, vec_sk_ed_sig_up, vec_sk_ed_sig_upuv, vec_sk_ed_sig_nouv,
      vec_sk_ed_sig_noup, vec_sk_ed_sig_other, GF_SIG_SK_ED25519 },
    { vec_sk_p256_blob, vec_sk_p256_sig_up, vec_sk_p256_sig_upuv, vec_sk_p256_sig_nouv,
      vec_sk_p256_sig_noup, vec_sk_p256_sig_other, GF_SIG_SK_ECDSA_NISTP256 },
    { vec_sk_ed_app_blob, vec_sk_ed_app_sig_up, vec_sk_ed_app_sig_upuv,
      vec_sk_ed_app_sig_nouv, vec_sk_ed_app_sig_noup, vec_sk_ed_app_sig_other,
      GF_SIG_SK_ED25519 }
  };
  size_t i, j;

  msglen = tst_unhex (vec_msg, msg, sizeof msg);
  for (i = 0; i < 3; i++)
    {
      gf_key *k = blob_key (v[i].blob);
      static uint8_t sig[BLOBMAX], bad[BLOBMAX];
      size_t n;
      uint8_t flags = 0xff;
      uint32_t counter = 0;

      if (k == NULL)
        continue;
      /* Signed by the token: its flags and counter come out.  */
      CHECK_EQ (verify (k, v[i].alg, v[i].up, msg, msglen, &flags, &counter), GF_OK);
      CHECK_EQ (flags, GF_SK_USER_PRESENT);
      CHECK_EQ (counter, 0x12345678);
      CHECK_EQ (verify (k, v[i].alg, v[i].upuv, msg, msglen, &flags, &counter), GF_OK);
      CHECK_EQ (flags, GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED);
      CHECK_EQ (counter, 7);
      CHECK_EQ (verify (k, v[i].alg, v[i].nouv, msg, msglen, &flags, &counter), GF_OK);
      CHECK_EQ (counter, 0);
      CHECK_EQ (verify (k, v[i].alg, v[i].up, msg, msglen, NULL, NULL), GF_OK);
      /* gf_key_verify takes it as well.  */
      n = tst_unhex (v[i].up, sig, sizeof sig);
      CHECK_EQ (gf_key_verify (k, v[i].alg, msg, msglen, sig, n), GF_OK);
      /* A signature without the user presence flag is genuine and refused. */
      CHECK_EQ (verify (k, v[i].alg, v[i].noup, msg, msglen, &flags, NULL), GF_ERR_HOSTKEY);
      n = tst_unhex (v[i].noup, sig, sizeof sig);
      CHECK_EQ (gf_key_verify (k, v[i].alg, msg, msglen, sig, n), GF_ERR_HOSTKEY);
      /* Another message; the message changed; truncated; extended.  */
      CHECK_EQ (verify (k, v[i].alg, v[i].other, msg, msglen, NULL, NULL), GF_ERR_HOSTKEY);
      CHECK_EQ (verify (k, v[i].alg, v[i].up, msg, msglen - 1, NULL, NULL), GF_ERR_HOSTKEY);
      n = tst_unhex (v[i].up, sig, sizeof sig);
      CHECK_EQ (gf_key_verify_sk (k, v[i].alg, msg, msglen, sig, n - 1, NULL, NULL),
                GF_ERR_HOSTKEY);
      memcpy (bad, sig, n);
      bad[n] = 0;
      CHECK_EQ (gf_key_verify_sk (k, v[i].alg, msg, msglen, bad, n + 1, NULL, NULL),
                GF_ERR_HOSTKEY);
      /* Every byte of the signature blob counts, the flags and the counter
         among them: changing any one is refused.  */
      for (j = 0; j < n; j++)
        {
          memcpy (bad, sig, n);
          bad[j] ^= 0x01;
          if (gf_key_verify_sk (k, v[i].alg, msg, msglen, bad, n, NULL, NULL) == GF_OK)
            {
              fprintf (stderr, "key %zu: byte %zu changed, still verifies\n", i, j);
              CHECK (0);
            }
        }
      /* Setting the user verified flag after the fact does not help.  */
      memcpy (bad, sig, n);
      bad[n - 5] |= GF_SK_USER_VERIFIED;
      CHECK_EQ (gf_key_verify_sk (k, v[i].alg, msg, msglen, bad, n, NULL, NULL),
                GF_ERR_HOSTKEY);
      /* A token's signature is not a plain signature of the key, and the
         key does not make the plain algorithm.  */
      CHECK_EQ (gf_key_verify (k, i == 1 ? GF_SIG_ECDSA_NISTP256 : GF_SIG_ED25519,
                               msg, msglen, sig, n), GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_verify (k, i == 1 ? GF_SIG_SK_ED25519 : GF_SIG_SK_ECDSA_NISTP256,
                               msg, msglen, sig, n), GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_verify_sk (k, GF_SIG_ED25519, msg, msglen, sig, n, NULL, NULL),
                GF_ERR_UNSUPPORTED);
      /* No signing here: there is no private key, and the token is not us. */
      CHECK (gf_key_sign (k, v[i].alg, msg, msglen, bad, sizeof bad, &n) != GF_OK);
      gf_key_free (k);
    }
  /* The other application: the same key bytes, a different application, and
     the signature (made for the first) is not valid for it.  */
  {
    gf_key *ed = blob_key (vec_sk_ed_blob), *app = blob_key (vec_sk_ed_app_blob);

    /* They are different keys, so build the second key's blob around the
       first one's public key.  */
    static uint8_t b[BLOBMAX];
    size_t n = tst_unhex (vec_sk_ed_blob, b, sizeof b), bl;
    const uint8_t *pb = gf_key_blob (ed, &bl);
    gf_writer w;
    gf_key *swapped = NULL;

    (void) n;
    gf_writer_init (&w, b, sizeof b);
    gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
    gf_wr_string (&w, pb + 4 + 26 + 4, 32);
    gf_wr_string (&w, "ssh:foxtrot", 11);
    CHECK_EQ (gf_key_from_blob (&swapped, b, w.len), GF_OK);
    if (swapped != NULL)
      {
        CHECK_EQ (verify (swapped, GF_SIG_SK_ED25519, vec_sk_ed_sig_up, msg, msglen,
                          NULL, NULL), GF_ERR_HOSTKEY);
        CHECK (!gf_key_equal (swapped, ed));
      }
    gf_key_free (swapped);
    gf_key_free (ed);
    gf_key_free (app);
  }
  /* A plain key has no security key algorithm.  */
  {
    gf_key *plain = NULL;
    static uint8_t sig[BLOBMAX];
    size_t n = tst_unhex (vec_sk_ed_sig_up, sig, sizeof sig);

    CHECK_EQ (gf_key_generate (&plain, GF_KEY_ED25519, 0), GF_OK);
    CHECK_EQ (gf_key_verify (plain, GF_SIG_SK_ED25519, msg, msglen, sig, n),
              GF_ERR_UNSUPPORTED);
    CHECK_EQ (gf_key_verify_sk (plain, GF_SIG_SK_ED25519, msg, msglen, sig, n,
                                NULL, NULL), GF_ERR_UNSUPPORTED);
    CHECK_EQ (gf_key_sign (plain, GF_SIG_SK_ED25519, msg, msglen, sig, sizeof sig, &n),
              GF_ERR_UNSUPPORTED);
    CHECK (!gf_key_is_security_key (plain));
    CHECK (gf_key_application (plain, &n) == NULL);
    gf_key_free (plain);
  }
}

/* Blobs that are not security keys. */
static void
test_refusals (void)
{
  static uint8_t pk[65], b[BLOBMAX];
  static const struct
  {
    const char *app;
    size_t len;
    int ok;
  } apps[] = {
    { "ssh:", 4, 1 }, { "ssh:foxtrot", 11, 1 }, { "ssh:\xc3\xa9", 6, 1 },
    { "", 0, 0 }, { "ssh", 3, 0 }, { "xssh:", 5, 0 }, { "SSH:", 4, 0 },
    { "https://example.org", 19, 0 }, { "ssh:a\0b", 7, 0 },
    { " ssh:", 5, 0 }
  };
  size_t i;
  gf_writer w;
  gf_key *k = NULL;
  static char big[300];

  memset (pk, 7, sizeof pk);
  for (i = 0; i < sizeof apps / sizeof apps[0]; i++)
    {
      gf_writer_init (&w, b, sizeof b);
      gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
      gf_wr_string (&w, pk, 32);
      gf_wr_string (&w, apps[i].app, apps[i].len);
      k = NULL;
      if (apps[i].ok)
        {
          /* Any 32 bytes are an Ed25519 key's public part to libgcrypt. */
          int rc = gf_key_from_blob (&k, b, w.len);

          if (rc != GF_OK)
            fprintf (stderr, "application %zu: %d\n", i, rc);
          CHECK_EQ (rc, GF_OK);
        }
      else
        CHECK (gf_key_from_blob (&k, b, w.len) != GF_OK);
      gf_key_free (k);
    }
  memset (big, 'a', sizeof big);
  memcpy (big, "ssh:", 4);
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
  gf_wr_string (&w, pk, 32);
  gf_wr_string (&w, big, 255);
  k = NULL;
  CHECK_EQ (gf_key_from_blob (&k, b, w.len), GF_OK);
  gf_key_free (k);
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
  gf_wr_string (&w, pk, 32);
  gf_wr_string (&w, big, 256);
  k = NULL;
  CHECK (gf_key_from_blob (&k, b, w.len) != GF_OK);
  /* Without an application, with a second one, with a short key. */
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
  gf_wr_string (&w, pk, 32);
  CHECK (gf_key_from_blob (&k, b, w.len) != GF_OK);
  gf_wr_string (&w, "ssh:", 4);
  gf_wr_string (&w, "ssh:", 4);
  CHECK (gf_key_from_blob (&k, b, w.len) != GF_OK);
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
  gf_wr_string (&w, pk, 31);
  gf_wr_string (&w, "ssh:", 4);
  CHECK (gf_key_from_blob (&k, b, w.len) != GF_OK);
  /* The plain name with an application, the security key's name without. */
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "ssh-ed25519");
  gf_wr_string (&w, pk, 32);
  gf_wr_string (&w, "ssh:", 4);
  CHECK (gf_key_from_blob (&k, b, w.len) != GF_OK);
  /* An ECDSA security key: the curve, the point (on it), then the application. */
  {
    gf_key *p = blob_key (vec_sk_p256_blob);
    size_t bl;
    const uint8_t *pb = gf_key_blob (p, &bl);

    CHECK_EQ (gf_key_from_blob (&k, pb, bl), GF_OK);
    gf_key_free (k);
    k = NULL;
    CHECK (gf_key_from_blob (&k, pb, bl - 1) != GF_OK);
    gf_writer_init (&w, b, sizeof b);
    gf_wr_cstring (&w, "sk-ecdsa-sha2-nistp256@openssh.com");
    gf_wr_cstring (&w, "nistp256");
    gf_wr_string (&w, pb + 4 + 34 + 4 + 8 + 4, 65);
    gf_wr_string (&w, "ssh:", 4);
    CHECK_EQ (gf_key_from_blob (&k, b, w.len), GF_OK);
    gf_key_free (k);
    k = NULL;
    /* The wrong curve name, a point that is not on the curve. */
    gf_writer_init (&w, b, sizeof b);
    gf_wr_cstring (&w, "sk-ecdsa-sha2-nistp256@openssh.com");
    gf_wr_cstring (&w, "nistp384");
    gf_wr_string (&w, pb + 4 + 34 + 4 + 8 + 4, 65);
    gf_wr_string (&w, "ssh:", 4);
    CHECK (gf_key_from_blob (&k, b, w.len) != GF_OK);
    gf_writer_init (&w, b, sizeof b);
    gf_wr_cstring (&w, "sk-ecdsa-sha2-nistp256@openssh.com");
    gf_wr_cstring (&w, "nistp256");
    memset (pk, 1, sizeof pk);
    pk[0] = 4;
    gf_wr_string (&w, pk, 65);
    gf_wr_string (&w, "ssh:", 4);
    CHECK (gf_key_from_blob (&k, b, w.len) != GF_OK);
    gf_key_free (p);
  }
  /* Types there are none of: P-384 and RSA security keys. */
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ecdsa-sha2-nistp384@openssh.com");
  gf_wr_cstring (&w, "nistp384");
  gf_wr_string (&w, pk, 97);
  gf_wr_string (&w, "ssh:", 4);
  CHECK_EQ (gf_key_from_blob (&k, b, w.len), GF_ERR_UNSUPPORTED);
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ssh-rsa@openssh.com");
  gf_wr_string (&w, pk, 32);
  CHECK_EQ (gf_key_from_blob (&k, b, w.len), GF_ERR_UNSUPPORTED);
}

/* An OpenSSH private key file whose key is a security key: its private part
   is a key handle for a token, which is not ours to use.  */
static void
test_private_file (void)
{
  static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static uint8_t raw[BLOBMAX], pub[BLOBMAX], priv[16];
  static char pem[4 * BLOBMAX];
  gf_writer w;
  size_t n, i, o = 0, pubn = tst_unhex (vec_sk_ed_blob, pub, sizeof pub);
  gf_key *k = NULL;

  gf_writer_init (&w, raw, sizeof raw);
  gf_wr_bytes (&w, "openssh-key-v1", 15);		/* With its NUL.  */
  gf_wr_cstring (&w, "none");
  gf_wr_cstring (&w, "none");
  gf_wr_string (&w, "", 0);
  gf_wr_u32 (&w, 1);
  gf_wr_string (&w, pub, pubn);
  memset (priv, 0, sizeof priv);
  gf_wr_string (&w, priv, sizeof priv);
  n = w.len;
  o += (size_t) snprintf (pem, sizeof pem, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
  for (i = 0; i < n; i += 3)
    {
      uint32_t v = (uint32_t) raw[i] << 16 | (i + 1 < n ? raw[i + 1] << 8 : 0)
        | (i + 2 < n ? raw[i + 2] : 0);

      pem[o++] = b64[v >> 18];
      pem[o++] = b64[(v >> 12) & 63];
      pem[o++] = i + 1 < n ? b64[(v >> 6) & 63] : '=';
      pem[o++] = i + 2 < n ? b64[v & 63] : '=';
      if ((i / 3 + 1) % 17 == 0)
        pem[o++] = '\n';
    }
  o += (size_t) snprintf (pem + o, sizeof pem - o,
                          "\n-----END OPENSSH PRIVATE KEY-----\n");
  CHECK_EQ (gf_key_from_openssh_private (&k, pem, o), GF_ERR_UNSUPPORTED);
  CHECK (k == NULL);
}

/* Certificates for security keys, from ssh-keygen. */
static void
test_certificates (void)
{
  gf_key *ed = blob_key (vec_sk_ed_cert), *p = blob_key (vec_sk_p256_cert);
  gf_key *uv = blob_key (vec_sk_ed_cert_uv), *ca = blob_key (vec_sk_ca_blob);
  gf_key *plain = blob_key (vec_sk_ed_blob);
  gf_cert_info ci;
  gf_slice v;
  const enum gf_sigalg *a;
  size_t na, pl;
  const uint8_t *pb;

  if (ed == NULL || p == NULL || uv == NULL)
    return;
  CHECK (gf_key_is_certificate (ed) && gf_key_is_security_key (ed));
  CHECK (strcmp (gf_key_type_name (ed), "sk-ssh-ed25519-cert-v01@openssh.com") == 0);
  CHECK (strcmp (gf_key_type_name (p), "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com") == 0);
  a = gf_key_sigalgs (ed, &na);
  CHECK (na == 1 && a[0] == GF_SIG_SK_ED25519_CERT);
  a = gf_key_sigalgs (p, &na);
  CHECK (na == 1 && a[0] == GF_SIG_SK_ECDSA_NISTP256_CERT);
  CHECK_EQ (gf_key_certificate_info (ed, &ci), GF_OK);
  CHECK (gf_key_equal (ci.ca, ca));
  CHECK (gf_cert_has_principal (ed, "alice", 5, 0));
  CHECK_EQ (gf_cert_check (ed, GF_CERT_USER, 1700000000, NULL), GF_OK);
  CHECK_EQ (gf_cert_critical_option (ed, "verify-required", &v), 0);
  CHECK_EQ (gf_cert_critical_option (uv, "verify-required", &v), 1);
  /* The key inside is the security key, application and all.  */
  pb = gf_key_plain_blob (ed, &pl);
  {
    size_t bl;
    const uint8_t *b = gf_key_blob (plain, &bl);

    CHECK (pl == bl && memcmp (pb, b, bl) == 0);
  }
  /* The token's signature verifies under the certificate algorithm, and not
     under the plain one.  */
  CHECK_EQ (verify (ed, GF_SIG_SK_ED25519_CERT, vec_sk_ed_sig_up, msg, msglen, NULL, NULL),
            GF_OK);
  CHECK_EQ (verify (ed, GF_SIG_SK_ED25519, vec_sk_ed_sig_up, msg, msglen, NULL, NULL),
            GF_ERR_UNSUPPORTED);
  CHECK_EQ (verify (plain, GF_SIG_SK_ED25519_CERT, vec_sk_ed_sig_up, msg, msglen, NULL, NULL),
            GF_ERR_UNSUPPORTED);
  CHECK_EQ (verify (ed, GF_SIG_SK_ED25519_CERT, vec_sk_ed_sig_noup, msg, msglen, NULL, NULL),
            GF_ERR_HOSTKEY);
  CHECK_EQ (verify (p, GF_SIG_SK_ECDSA_NISTP256_CERT, vec_sk_p256_sig_up, msg, msglen,
                    NULL, NULL), GF_OK);
  /* Every byte of a certificate counts here too.  */
  {
    static uint8_t blob[BLOBMAX], copy[BLOBMAX];
    size_t n = tst_unhex (vec_sk_ed_cert, blob, sizeof blob), i;
    int bad = 0;

    for (i = 0; i < n; i++)
      {
        gf_key *k = NULL;

        memcpy (copy, blob, n);
        copy[i] ^= 1;
        if (gf_key_from_blob (&k, copy, n) == GF_OK)
          bad++;
        gf_key_free (k);
      }
    CHECK_EQ (bad, 0);
  }
  gf_key_free (ed);
  gf_key_free (p);
  gf_key_free (uv);
  gf_key_free (ca);
  gf_key_free (plain);
}

int
main (void)
{
  gf_crypto_init ();
  test_keys ();
  test_verify ();
  test_refusals ();
  test_private_file ();
  test_certificates ();
  TST_DONE ();
}
