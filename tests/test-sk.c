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
#include "vectors-skfile.h"

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
  static uint8_t pk[97], b[BLOBMAX];
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

/* ---- Private key files of security keys (PROTOCOL.u2f) ---- */

#define PASS "correct horse"
#define WRONG "wrong horse"

/* The key derivation of the encrypted vectors, computed by another
   implementation: asking for anything else is a failure.  */
static int
skf_kdf (void *user, const uint8_t *pass, size_t passlen, const uint8_t *salt,
         size_t saltlen, uint32_t rounds, uint8_t *out, size_t outlen)
{
  size_t i, j;

  (void) user;
  for (i = 0; i < sizeof vec_skf_kdfs / sizeof vec_skf_kdfs[0]; i++)
    {
      const struct vec_skf_kdf *v = &vec_skf_kdfs[i];
      static uint8_t s[64];

      if (strlen (v->pass) != passlen || memcmp (v->pass, pass, passlen) != 0
          || v->rounds != rounds || tst_unhex (v->salt, s, sizeof s) != saltlen
          || memcmp (s, salt, saltlen) != 0 || v->outlen != outlen)
        continue;
      for (j = 0; j < outlen; j++)
        {
          unsigned b;

          sscanf (v->out + 2 * j, "%2x", &b);
          out[j] = (uint8_t) b;
        }
      return 0;
    }
  return 1;
}

static size_t
armor (const uint8_t *raw, size_t n, char *pem, size_t cap)
{
  static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i, o = 0;

  o += (size_t) snprintf (pem, cap, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
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
  o += (size_t) snprintf (pem + o, cap - o,
                          "\n-----END OPENSSH PRIVATE KEY-----\n");
  return o;
}

/* An unprotected file for a security key, built from the description, so
   that each field can be wrong.  */
struct skfile
{
  int p256;
  const char *blob_app;		/* In the public key; NULL: "ssh:".  */
  const char *priv_app;		/* In the private part; NULL: the same.  */
  const char *type;		/* The type name there; NULL: the right one. */
  int omit;			/* A field left out of the private part.  */
  uint8_t flags;
  size_t handlelen;
  int other_pub;		/* A different public key in the private part. */
  int bad_pad;			/* The padding is not 1, 2, 3...  */
  int trailing;			/* A byte after the private part.  */
};

enum { OMIT_NONE, OMIT_APP, OMIT_FLAGS, OMIT_HANDLE, OMIT_RESERVED, OMIT_PUB };

static int
skfile_read (const struct skfile *f, gf_key **out)
{
  static uint8_t raw[BLOBMAX], blob[BLOBMAX], priv[BLOBMAX], pk[2][97];
  static char pem[4 * BLOBMAX];
  gf_writer w, pw;
  gf_key *src[2] = { NULL, NULL };
  size_t pkl[2], bl, i, pos;
  const char *app = f->blob_app ? f->blob_app : "ssh:";
  const char *papp = f->priv_app ? f->priv_app : app;
  const char *name = f->p256 ? "sk-ecdsa-sha2-nistp256@openssh.com"
    : "sk-ssh-ed25519@openssh.com";
  int rc;

  /* Two keys' public parts: the one in the file and one to put in its way. */
  for (i = 0; i < 2; i++)
    {
      gf_reader r;
      gf_slice a, b;
      const uint8_t *kb;

      CHECK_EQ (gf_key_generate (&src[i], f->p256 ? GF_KEY_ECDSA_P256
                                 : GF_KEY_ED25519, 0), GF_OK);
      kb = gf_key_blob (src[i], &bl);
      gf_reader_init (&r, kb, bl);
      CHECK_EQ (gf_rd_string (&r, &a), GF_OK);
      CHECK_EQ (gf_rd_string (&r, &a), GF_OK);
      if (f->p256)
        CHECK_EQ (gf_rd_string (&r, &b), GF_OK);
      else
        b = a;
      memcpy (pk[i], f->p256 ? b.data : a.data, f->p256 ? b.len : a.len);
      pkl[i] = f->p256 ? b.len : a.len;
    }
  gf_writer_init (&w, blob, sizeof blob);
  gf_wr_cstring (&w, name);
  if (f->p256)
    gf_wr_cstring (&w, "nistp256");
  gf_wr_string (&w, pk[0], pkl[0]);
  gf_wr_string (&w, app, strlen (app));
  bl = w.len;

  gf_writer_init (&pw, priv, sizeof priv);
  gf_wr_u32 (&pw, 0x01020304);
  gf_wr_u32 (&pw, 0x01020304);
  gf_wr_cstring (&pw, f->type ? f->type : name);
  if (f->omit != OMIT_PUB)
    {
      if (f->p256)
        gf_wr_cstring (&pw, "nistp256");
      gf_wr_string (&pw, pk[f->other_pub ? 1 : 0], pkl[f->other_pub ? 1 : 0]);
    }
  if (f->omit != OMIT_APP)
    gf_wr_string (&pw, papp, strlen (papp));
  if (f->omit != OMIT_FLAGS)
    gf_wr_u8 (&pw, f->flags);
  if (f->omit != OMIT_HANDLE)
    {
      static uint8_t h[512];

      memset (h, 0x5a, sizeof h);
      gf_wr_string (&pw, h, f->handlelen);
    }
  if (f->omit != OMIT_RESERVED)
    gf_wr_string (&pw, "", 0);
  gf_wr_string (&pw, "", 0);			/* The comment.  */
  for (pos = 1; pw.len % 8; pos++)
    gf_wr_u8 (&pw, f->bad_pad && pos == 2 ? 0x7f : (uint8_t) pos);
  if (f->trailing)
    gf_wr_u8 (&pw, 0);
  CHECK_EQ (gf_wr_status (&pw), GF_OK);

  gf_writer_init (&w, raw, sizeof raw);
  gf_wr_bytes (&w, "openssh-key-v1", 15);
  gf_wr_cstring (&w, "none");
  gf_wr_cstring (&w, "none");
  gf_wr_string (&w, "", 0);
  gf_wr_u32 (&w, 1);
  gf_wr_string (&w, blob, bl);
  gf_wr_string (&w, priv, pw.len);
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  rc = gf_key_from_openssh_private (out, pem, armor (raw, w.len, pem, sizeof pem));
  gf_key_free (src[0]);
  gf_key_free (src[1]);
  return rc;
}

static void
check_sk_file (gf_key *k, const char *blobhex, const char *app, uint8_t flags,
               const char *handlehex)
{
  static uint8_t blob[BLOBMAX], handle[BLOBMAX], out[GF_SIG_MAX];
  size_t bl, bn = tst_unhex (blobhex, blob, sizeof blob), hl, hn, al, n;
  const uint8_t *b, *h, *a;

  CHECK (k != NULL);
  if (k == NULL)
    return;
  hn = tst_unhex (handlehex, handle, sizeof handle);
  b = gf_key_blob (k, &bl);
  CHECK (bl == bn && memcmp (b, blob, bn) == 0);
  CHECK (gf_key_is_security_key (k));
  CHECK (!gf_key_has_private (k));
  a = gf_key_application (k, &al);
  CHECK (a != NULL && al == strlen (app) && memcmp (a, app, al) == 0);
  h = gf_key_sk_handle (k, &hl);
  CHECK (h != NULL && hl == hn && memcmp (h, handle, hn) == 0);
  CHECK_EQ (gf_key_sk_flags (k), flags);
  /* The token signs, not us.  */
  {
    size_t na;
    const enum gf_sigalg *algs = gf_key_sigalgs (k, &na);

    CHECK (gf_key_sign (k, algs[0], (const uint8_t *) "x", 1, out, sizeof out, &n)
           != GF_OK);
  }
}

static void
test_private_file (void)
{
  static const struct
  {
    const char *plain, *enc, *blob, *app, *handle;
    uint8_t flags;
  } v[] = {
    { vec_skf_ed_plain, vec_skf_ed_enc, vec_skf_ed_blob, vec_skf_ed_app,
      vec_skf_ed_handle, VEC_SKF_ED_FLAGS },
    { vec_skf_p256_plain, vec_skf_p256_enc, vec_skf_p256_blob, vec_skf_p256_app,
      vec_skf_p256_handle, VEC_SKF_P256_FLAGS },
    /* Resident, user verification required, the longest handle.  */
    { vec_skf_ed_res_plain, NULL, vec_skf_ed_res_blob, vec_skf_ed_res_app,
      vec_skf_ed_res_handle, VEC_SKF_ED_RES_FLAGS },
    { vec_skf_p256_notouch_plain, NULL, vec_skf_p256_notouch_blob,
      vec_skf_p256_notouch_app, vec_skf_p256_notouch_handle,
      VEC_SKF_P256_NOTOUCH_FLAGS }
  };
  size_t i, j;

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      gf_key *k = NULL, *again = NULL;
      int rc = gf_key_from_openssh_private (&k, v[i].plain, strlen (v[i].plain));

      if (rc != GF_OK)
        fprintf (stderr, "file %zu: %d\n", i, rc);
      CHECK_EQ (rc, GF_OK);
      check_sk_file (k, v[i].blob, v[i].app, v[i].flags, v[i].handle);
      /* The same as the public key from its blob, which has no handle.  */
      again = blob_key (v[i].blob);
      CHECK (k != NULL && gf_key_equal (k, again));
      CHECK (gf_key_sk_handle (again, &j) == NULL);
      CHECK_EQ (gf_key_sk_flags (again), 0);
      gf_key_free (again);
      /* The entry point with a passphrase takes an unprotected file too.  */
      gf_key_free (k);
      k = NULL;
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, v[i].plain,
                                                       strlen (v[i].plain), NULL,
                                                       NULL, NULL), GF_OK);
      check_sk_file (k, v[i].blob, v[i].app, v[i].flags, v[i].handle);
      gf_key_free (k);

      if (v[i].enc == NULL)
        continue;
      /* Under a passphrase: the same key, the same handle.  */
      k = NULL;
      rc = gf_key_from_openssh_private_encrypted (&k, v[i].enc, strlen (v[i].enc),
                                                  PASS, skf_kdf, NULL);
      CHECK_EQ (rc, GF_OK);
      check_sk_file (k, v[i].blob, v[i].app, v[i].flags, v[i].handle);
      gf_key_free (k);
      k = NULL;
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, v[i].enc,
                                                       strlen (v[i].enc), WRONG,
                                                       skf_kdf, NULL),
                GF_ERR_PASSPHRASE);
      CHECK (k == NULL);
      CHECK_EQ (gf_key_from_openssh_private (&k, v[i].enc, strlen (v[i].enc)),
                GF_ERR_UNSUPPORTED);
      CHECK (k == NULL);
    }
}

static void
test_private_file_refused (void)
{
  const struct skfile ok = { 0, NULL, NULL, NULL, OMIT_NONE, 0x01, 64, 0, 0, 0 };
  struct skfile f;
  gf_key *k = NULL;
  size_t i, n;

  /* The builder's own file is read, for both types, so that what follows
     is refused for what it changes and not for the builder.  */
  CHECK_EQ (skfile_read (&ok, &k), GF_OK);
  CHECK (k != NULL && gf_key_is_security_key (k));
  gf_key_free (k);
  f = ok;
  f.p256 = 1;
  k = NULL;
  CHECK_EQ (skfile_read (&f, &k), GF_OK);
  gf_key_free (k);
  /* The handle: 1 to 255 bytes.  */
  for (i = 0; i < 2; i++)
    {
      f = ok;
      f.p256 = (int) i;
      f.handlelen = 255;
      k = NULL;
      CHECK_EQ (skfile_read (&f, &k), GF_OK);
      gf_key_free (k);
      f.handlelen = 1;
      k = NULL;
      CHECK_EQ (skfile_read (&f, &k), GF_OK);
      gf_key_free (k);
      f.handlelen = 256;
      k = NULL;
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      f.handlelen = 0;
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      f.handlelen = 512;
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      /* A field missing from the private part.  */
      for (n = OMIT_APP; n <= OMIT_PUB; n++)
        {
          f = ok;
          f.p256 = (int) i;
          f.omit = (int) n;
          CHECK (skfile_read (&f, &k) != GF_OK);
          CHECK (k == NULL);
        }
      /* An application that is not OpenSSH's, in the public key (so that the
         key itself is refused) and only in the private part.  */
      f = ok;
      f.p256 = (int) i;
      f.blob_app = "webauthn.io";
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      f.blob_app = NULL;
      f.priv_app = "webauthn.io";
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      f.priv_app = "ssh:other";			/* Ours begins ssh:, but differs. */
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      /* The wrong type name, the plain key's and the other's.  */
      f = ok;
      f.p256 = (int) i;
      f.type = i ? "ecdsa-sha2-nistp256" : "ssh-ed25519";
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      f.type = i ? "sk-ssh-ed25519@openssh.com" : "sk-ecdsa-sha2-nistp256@openssh.com";
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      /* Another public key in the private part than the file's.  */
      f = ok;
      f.p256 = (int) i;
      f.other_pub = 1;
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      /* Damaged padding, and a byte after the whole.  */
      f = ok;
      f.p256 = (int) i;
      f.bad_pad = 1;
      f.handlelen = 61;				/* So that there is padding.  */
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
      f = ok;
      f.p256 = (int) i;
      f.trailing = 1;
      CHECK (skfile_read (&f, &k) != GF_OK);
      CHECK (k == NULL);
    }
  /* Truncated: no prefix of a good file (short of its last newline) is a key. */
  {
    size_t len = strlen (vec_skf_ed_plain);

    for (i = 0; i + 1 < len; i++)
      {
        k = NULL;
        CHECK (gf_key_from_openssh_private (&k, vec_skf_ed_plain, i) != GF_OK);
        CHECK (k == NULL);
      }
    len = strlen (vec_skf_p256_plain);
    for (i = 0; i + 1 < len; i++)
      {
        k = NULL;
        CHECK (gf_key_from_openssh_private (&k, vec_skf_p256_plain, i) != GF_OK);
        CHECK (k == NULL);
      }
  }
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

/* A security key's handle and flags can be given to a public key, as an
   application that finds its keys on a token does.  */
static void
test_handle (void)
{
  static uint8_t h[300];
  gf_key *k = blob_key (vec_sk_ed_blob), *plain = NULL, *p = blob_key (vec_sk_p256_blob);
  const uint8_t *g;
  size_t n;

  memset (h, 0x33, sizeof h);
  CHECK (gf_key_sk_handle (k, &n) == NULL);
  CHECK_EQ (gf_key_sk_flags (k), 0);
  CHECK_EQ (gf_key_sk_attach_handle (k, GF_SK_USER_PRESENT | GF_SK_RESIDENT_KEY, h, 40),
            GF_OK);
  g = gf_key_sk_handle (k, &n);
  CHECK (g != NULL && n == 40 && memcmp (g, h, 40) == 0);
  CHECK (g != h);				/* It is a copy.  */
  CHECK_EQ (gf_key_sk_flags (k), GF_SK_USER_PRESENT | GF_SK_RESIDENT_KEY);
  CHECK_EQ (GF_SK_RESIDENT_KEY, 0x20);
  /* Replaced, not added to; the key itself is not changed by it.  */
  memset (h, 0x44, sizeof h);
  CHECK_EQ (gf_key_sk_attach_handle (k, 0, h, 255), GF_OK);
  g = gf_key_sk_handle (k, &n);
  CHECK (g != NULL && n == 255 && memcmp (g, h, 255) == 0);
  CHECK_EQ (gf_key_sk_flags (k), 0);
  {
    gf_key *same = blob_key (vec_sk_ed_blob);

    CHECK (gf_key_equal (k, same));
    gf_key_free (same);
  }
  /* A bad handle leaves the old one.  */
  CHECK_EQ (gf_key_sk_attach_handle (k, 1, h, 256), GF_ERR_RANGE);
  CHECK_EQ (gf_key_sk_attach_handle (k, 1, h, 0), GF_ERR_RANGE);
  CHECK_EQ (gf_key_sk_attach_handle (k, 1, NULL, 4), GF_ERR_INVAL);
  CHECK_EQ (gf_key_sk_attach_handle (NULL, 1, h, 4), GF_ERR_INVAL);
  g = gf_key_sk_handle (k, &n);
  CHECK (g != NULL && n == 255 && gf_key_sk_flags (k) == 0);
  CHECK_EQ (gf_key_sk_attach_handle (p, 1, h, 16), GF_OK);
  /* Only a security key has one.  */
  CHECK_EQ (gf_key_generate (&plain, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_sk_attach_handle (plain, 1, h, 16), GF_ERR_UNSUPPORTED);
  CHECK (gf_key_sk_handle (plain, &n) == NULL);
  CHECK_EQ (gf_key_sk_flags (plain), 0);
  gf_key_free (plain);
  gf_key_free (k);
  gf_key_free (p);
}

/* ---- A token's answer as a signature blob ---- */

static uint8_t pk_out[GF_SIG_MAX];

static int
pack (const gf_key *k, enum gf_sigalg alg, const uint8_t *raw, size_t rl, size_t *n)
{
  return gf_sk_signature_pack (k, alg, raw, rl, VEC_SKF_FLAGS, VEC_SKF_COUNTER,
                               pk_out, sizeof pk_out, n);
}

/* DER of an ECDSA signature from two bare integers' contents.  */
static size_t
der_sig (uint8_t *out, const uint8_t *r, size_t rl, const uint8_t *s, size_t sl)
{
  size_t n = 0;

  out[n++] = 0x30;
  out[n++] = (uint8_t) (2 + rl + 2 + sl);
  out[n++] = 0x02;
  out[n++] = (uint8_t) rl;
  memcpy (out + n, r, rl);
  n += rl;
  out[n++] = 0x02;
  out[n++] = (uint8_t) sl;
  memcpy (out + n, s, sl);
  return n + sl;
}

static void
test_pack (void)
{
  static uint8_t raw[GF_SIG_MAX], want[GF_SIG_MAX], bad[GF_SIG_MAX], m[64];
  static const struct
  {
    const char *der, *packed;
  } p256[] = {
    { vec_skf_p256_der_both_high, vec_skf_p256_packed_both_high },
    { vec_skf_p256_der_short_r, vec_skf_p256_packed_short_r },
    { vec_skf_p256_der_short_s, vec_skf_p256_packed_short_s }
  };
  gf_key *ed = blob_key (vec_skf_ed_blob), *p = blob_key (vec_skf_p256_blob);
  gf_key *plain = NULL;
  size_t rl, wl, n, i, ml = tst_unhex (vec_skf_msg, m, sizeof m);
  uint8_t flags = 0;
  uint32_t counter = 0;

  /* Ed25519: the 64 bytes as the token gave them.  */
  rl = tst_unhex (vec_skf_ed_raw, raw, sizeof raw);
  wl = tst_unhex (vec_skf_ed_packed, want, sizeof want);
  CHECK_EQ (rl, 64);
  CHECK_EQ (pack (ed, GF_SIG_SK_ED25519, raw, rl, &n), GF_OK);
  CHECK (n == wl && memcmp (pk_out, want, wl) == 0);
  CHECK_EQ (gf_key_verify_sk (ed, GF_SIG_SK_ED25519, m, ml, pk_out, n, &flags, &counter),
            GF_OK);
  CHECK_EQ (flags, VEC_SKF_FLAGS);
  CHECK_EQ (counter, VEC_SKF_COUNTER);
  /* Not 64 bytes; or a DER signature.  */
  CHECK_EQ (pack (ed, GF_SIG_SK_ED25519, raw, 63, &n), GF_ERR_ENCODING);
  CHECK_EQ (pack (ed, GF_SIG_SK_ED25519, raw, 0, &n), GF_ERR_ENCODING);
  memcpy (bad, raw, rl);
  bad[rl] = 0;
  CHECK_EQ (pack (ed, GF_SIG_SK_ED25519, bad, rl + 1, &n), GF_ERR_ENCODING);
  /* A bad answer is packed all the same: the check is the key's.  */
  memcpy (bad, raw, rl);
  bad[10] ^= 1;
  CHECK_EQ (pack (ed, GF_SIG_SK_ED25519, bad, rl, &n), GF_OK);
  CHECK_EQ (gf_key_verify_sk (ed, GF_SIG_SK_ED25519, m, ml, pk_out, n, NULL, NULL),
            GF_ERR_HOSTKEY);

  /* ECDSA: DER, whatever the sizes of r and s.  */
  for (i = 0; i < 3; i++)
    {
      static uint8_t der[128];

      rl = tst_unhex (p256[i].der, der, sizeof der);
      wl = tst_unhex (p256[i].packed, want, sizeof want);
      CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, der, rl, &n), GF_OK);
      CHECK (n == wl && memcmp (pk_out, want, wl) == 0);
      CHECK_EQ (gf_key_verify_sk (p, GF_SIG_SK_ECDSA_NISTP256, m, ml, pk_out, n,
                                  &flags, &counter), GF_OK);
      CHECK_EQ (flags, VEC_SKF_FLAGS);
      CHECK_EQ (counter, VEC_SKF_COUNTER);
      /* Strictly: nothing after, nothing missing.  */
      memcpy (bad, der, rl);
      bad[rl] = 0;
      CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, bad, rl + 1, &n), GF_ERR_ENCODING);
      CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, der, rl - 1, &n), GF_ERR_ENCODING);
      CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, der, 0, &n), GF_ERR_ENCODING);
      /* Every prefix is refused.  */
      for (wl = 0; wl < rl; wl++)
        CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, der, wl, &n), GF_ERR_ENCODING);
    }

  /* The shapes of DER that are not canonical, or not a signature.  */
  {
    static const uint8_t one[] = { 1 }, hi[] = { 0x80 }, zhi[] = { 0, 0x80 },
      zlo[] = { 0, 0x7f }, zero[] = { 0 };
    uint8_t big[34], ok33[33];
    uint8_t d[128];

    memset (big, 1, sizeof big);
    memset (ok33, 1, sizeof ok33);
    big[0] = ok33[0] = 0;
    big[1] = ok33[1] = 0x80;
    /* The smallest signature is valid DER; the blob has mpints 1 and 1.  */
    rl = der_sig (d, one, 1, one, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_OK);
    /* A negative integer, an unneeded leading zero, zero, nothing at all.  */
    rl = der_sig (d, hi, 1, one, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_ERR_ENCODING);
    rl = der_sig (d, one, 1, hi, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_ERR_ENCODING);
    rl = der_sig (d, zlo, 2, one, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_ERR_ENCODING);
    rl = der_sig (d, zhi, 2, one, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_OK);
    rl = der_sig (d, zero, 1, one, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_ERR_ENCODING);
    rl = der_sig (d, one, 1, zero, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_ERR_ENCODING);
    rl = der_sig (d, one, 0, one, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_ERR_ENCODING);
    /* Too long for P-256: 33 bytes is the most (a zero and 32).  */
    rl = der_sig (d, ok33, 33, one, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_OK);
    rl = der_sig (d, big, 34, one, 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, d, rl, &n), GF_ERR_ENCODING);
    /* The wrong tags, a long length form for a short length, indefinite
       length, a third integer.  */
    rl = der_sig (d, one, 1, one, 1);
    memcpy (bad, d, rl);
    bad[0] = 0x31;
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, bad, rl, &n), GF_ERR_ENCODING);
    memcpy (bad, d, rl);
    bad[2] = 0x04;
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, bad, rl, &n), GF_ERR_ENCODING);
    memcpy (bad, d, rl);
    bad[4 + 1] = 0x04;
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, bad, rl, &n), GF_ERR_ENCODING);
    bad[0] = 0x30;
    bad[1] = 0x81;
    memcpy (bad + 2, d + 1, rl - 1);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, bad, rl + 1, &n), GF_ERR_ENCODING);
    bad[1] = 0x80;
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, bad, rl + 1, &n), GF_ERR_ENCODING);
    memcpy (bad, d, rl);
    bad[1] += 3;
    memcpy (bad + rl, "\x02\x01\x01", 3);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, bad, rl + 3, &n), GF_ERR_ENCODING);
    /* Ed25519's 64 bytes are not an ECDSA signature.  */
    memset (bad, 0x30, 64);
    CHECK_EQ (pack (p, GF_SIG_SK_ECDSA_NISTP256, bad, 64, &n), GF_ERR_ENCODING);
  }

  /* The key and the algorithm must go together, and be a token's.  */
  rl = tst_unhex (vec_skf_ed_raw, raw, sizeof raw);
  CHECK_EQ (pack (ed, GF_SIG_SK_ECDSA_NISTP256, raw, rl, &n), GF_ERR_UNSUPPORTED);
  CHECK_EQ (pack (ed, GF_SIG_ED25519, raw, rl, &n), GF_ERR_UNSUPPORTED);
  CHECK_EQ (pack (p, GF_SIG_SK_ED25519, raw, rl, &n), GF_ERR_UNSUPPORTED);
  CHECK_EQ (pack (ed, GF_SIG_SK_ED25519_CERT, raw, rl, &n), GF_ERR_UNSUPPORTED);
  CHECK_EQ (gf_key_generate (&plain, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (pack (plain, GF_SIG_SK_ED25519, raw, rl, &n), GF_ERR_UNSUPPORTED);
  CHECK_EQ (pack (plain, GF_SIG_ED25519, raw, rl, &n), GF_ERR_UNSUPPORTED);
  /* Room for it, to the byte.  */
  CHECK_EQ (pack (ed, GF_SIG_SK_ED25519, raw, rl, &n), GF_OK);
  CHECK_EQ (gf_sk_signature_pack (ed, GF_SIG_SK_ED25519, raw, rl, 1, 1, pk_out,
                                  n - 1, &wl), GF_ERR_BUFSIZE);
  CHECK_EQ (gf_sk_signature_pack (ed, GF_SIG_SK_ED25519, raw, rl, 1, 1, pk_out, n,
                                  &wl), GF_OK);
  CHECK (wl == n);
  CHECK_EQ (gf_sk_signature_pack (NULL, GF_SIG_SK_ED25519, raw, rl, 1, 1, pk_out, n,
                                  &wl), GF_ERR_INVAL);
  CHECK_EQ (gf_sk_signature_pack (ed, GF_SIG_SK_ED25519, NULL, rl, 1, 1, pk_out, n,
                                  &wl), GF_ERR_INVAL);
  CHECK_EQ (gf_sk_signature_pack (ed, GF_SIG_SK_ED25519, raw, rl, 1, 1, pk_out, n,
                                  NULL), GF_ERR_INVAL);
  gf_key_free (plain);
  gf_key_free (ed);
  gf_key_free (p);
}

int
main (void)
{
  gf_crypto_init ();
  test_keys ();
  test_verify ();
  test_refusals ();
  test_private_file ();
  test_private_file_refused ();
  test_handle ();
  test_pack ();
  test_certificates ();
  TST_DONE ();
}
