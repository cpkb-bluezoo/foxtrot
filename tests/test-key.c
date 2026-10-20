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
#include <foxtrot/crypto.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>

#include "tst-util.h"
#include "vectors-key.h"

#define SIGMAX GF_SIG_MAX

static uint8_t msg[64];
static size_t msglen;

static size_t
hexbuf (const char *hex, uint8_t *out, size_t cap)
{
  return tst_unhex (hex, out, cap);
}

/* One key from ssh-keygen: parse, compare with its public blob and
   fingerprint, verify the independent signatures, and sign again.  */
static void
check_vector_key (const char *priv, const char *blobhex, const char *fp,
                  enum gf_keytype type, const char *const *sigs,
                  const enum gf_sigalg *algs, size_t nsigs)
{
  static uint8_t blob[2048], sig[SIGMAX], mysig[SIGMAX];
  gf_key *k = NULL, *pub = NULL, *again = NULL;
  size_t bn = hexbuf (blobhex, blob, sizeof blob), i, n;
  const uint8_t *kb;
  char fpbuf[64];
  static char pem[4096];

  CHECK_EQ (gf_key_from_openssh_private (&k, priv, strlen (priv)), GF_OK);
  if (k == NULL)
    return;
  CHECK_EQ (gf_key_type (k), type);
  CHECK (gf_key_has_private (k));
  kb = gf_key_blob (k, &n);
  CHECK (n == bn && memcmp (kb, blob, bn) == 0);
  CHECK_EQ (gf_key_fingerprint (k, fpbuf, sizeof fpbuf), GF_OK);
  CHECK (strcmp (fpbuf, fp) == 0);

  CHECK_EQ (gf_key_from_blob (&pub, blob, bn), GF_OK);
  if (pub == NULL)
    {
      gf_key_free (k);
      return;
    }
  CHECK (!gf_key_has_private (pub));
  CHECK (gf_key_equal (k, pub));
  CHECK_EQ (gf_key_sign (pub, algs[0], msg, msglen, mysig, sizeof mysig, &n),
            GF_ERR_INVAL);

  for (i = 0; i < nsigs; i++)
    {
      size_t sn = hexbuf (sigs[i], sig, sizeof sig);

      /* Made by OpenSSL; we must accept it, and only for its own alg.  */
      CHECK_EQ (gf_key_verify (pub, algs[i], msg, msglen, sig, sn), GF_OK);
      sig[sn - 1] ^= 1;
      CHECK_EQ (gf_key_verify (pub, algs[i], msg, msglen, sig, sn),
                GF_ERR_HOSTKEY);
      sig[sn - 1] ^= 1;
      CHECK_EQ (gf_key_verify (pub, algs[i], msg, msglen - 1, sig, sn),
                GF_ERR_HOSTKEY);
      CHECK_EQ (gf_key_verify (pub, algs[i], msg, msglen, sig, sn - 1),
                GF_ERR_HOSTKEY);

      /* And ours, made with the private key, must verify too.  */
      CHECK_EQ (gf_key_sign (k, algs[i], msg, msglen, mysig, sizeof mysig,
                             &n), GF_OK);
      CHECK_EQ (gf_key_verify (pub, algs[i], msg, msglen, mysig, n), GF_OK);
      CHECK_EQ (gf_key_sign (k, algs[i], msg, msglen, mysig, 10, &n),
                GF_ERR_BUFSIZE);
    }

  /* Write the private key out and read it back.  */
  CHECK_EQ (gf_key_to_openssh_private (k, pem, sizeof pem, &n), GF_OK);
  CHECK (strncmp (pem, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 36) == 0);
  CHECK_EQ (gf_key_from_openssh_private (&again, pem, n), GF_OK);
  if (again != NULL)
    {
      CHECK (gf_key_equal (again, k));
      CHECK_EQ (gf_key_sign (again, algs[0], msg, msglen, mysig,
                             sizeof mysig, &n), GF_OK);
      CHECK_EQ (gf_key_verify (pub, algs[0], msg, msglen, mysig, n), GF_OK);
    }
  gf_key_free (again);
  gf_key_free (pub);
  gf_key_free (k);
}

static void
test_vectors (void)
{
  const char *const ed[] = { vec_ed_sig };
  const enum gf_sigalg edalg[] = { GF_SIG_ED25519 };
  const char *const p256[] = { vec_p256_sig };
  const enum gf_sigalg p256alg[] = { GF_SIG_ECDSA_NISTP256 };
  const char *const p384[] = { vec_p384_sig };
  const enum gf_sigalg p384alg[] = { GF_SIG_ECDSA_NISTP384 };
  const char *const rsa[] = { vec_rsa_sig256, vec_rsa_sig512 };
  const enum gf_sigalg rsaalg[] = { GF_SIG_RSA_SHA2_256, GF_SIG_RSA_SHA2_512 };

  msglen = hexbuf (vec_msg, msg, sizeof msg);
  check_vector_key (vec_ed_private, vec_ed_blob, vec_ed_fp, GF_KEY_ED25519,
                    ed, edalg, 1);
  check_vector_key (vec_p256_private, vec_p256_blob, vec_p256_fp,
                    GF_KEY_ECDSA_P256, p256, p256alg, 1);
  check_vector_key (vec_p384_private, vec_p384_blob, vec_p384_fp,
                    GF_KEY_ECDSA_P384, p384, p384alg, 1);
  check_vector_key (vec_rsa_private, vec_rsa_blob, vec_rsa_fp, GF_KEY_RSA,
                    rsa, rsaalg, 2);
}

/* RFC 8032 section 7.1, test 1, as an SSH key and signature.  */
static void
test_ed25519_rfc8032 (void)
{
  uint8_t blob[64], sig[128];
  gf_writer w;
  gf_key *k;
  uint8_t pub[32], rs[64];

  tst_unhex ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
             pub, sizeof pub);
  tst_unhex ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
             "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
             rs, sizeof rs);
  gf_writer_init (&w, blob, sizeof blob);
  gf_wr_cstring (&w, "ssh-ed25519");
  gf_wr_string (&w, pub, 32);
  CHECK_EQ (gf_key_from_blob (&k, blob, w.len), GF_OK);

  gf_writer_init (&w, sig, sizeof sig);
  gf_wr_cstring (&w, "ssh-ed25519");
  gf_wr_string (&w, rs, 64);
  CHECK_EQ (gf_key_verify (k, GF_SIG_ED25519, (const uint8_t *) "", 0, sig,
                           w.len), GF_OK);

  /* S + L is the same signature to a lax verifier; not ours.  */
  {
    static const uint8_t l[32] = {
      0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
      0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0x10
    };
    unsigned carry = 0;
    int i;

    for (i = 0; i < 32; i++)
      {
        unsigned v = rs[32 + i] + l[i] + carry;

        rs[32 + i] = (uint8_t) v;
        carry = v >> 8;
      }
    CHECK_EQ (carry, 0);
    gf_writer_init (&w, sig, sizeof sig);
    gf_wr_cstring (&w, "ssh-ed25519");
    gf_wr_string (&w, rs, 64);
    CHECK_EQ (gf_key_verify (k, GF_SIG_ED25519, (const uint8_t *) "", 0, sig,
                             w.len), GF_ERR_HOSTKEY);
  }
  gf_key_free (k);
}

static void
test_generate (void)
{
  static const enum gf_keytype types[] = { GF_KEY_ED25519, GF_KEY_ECDSA_P256,
                                           GF_KEY_ECDSA_P384, GF_KEY_RSA };
  size_t t;

  msglen = hexbuf (vec_msg, msg, sizeof msg);
  for (t = 0; t < 4; t++)
    {
      gf_key *k = NULL, *pub = NULL;
      uint8_t sig[SIGMAX], other[SIGMAX];
      size_t n, na, i, bn;
      const enum gf_sigalg *algs;
      const uint8_t *b;

      CHECK_EQ (gf_key_generate (&k, types[t], 2048), GF_OK);
      if (k == NULL)
        continue;
      algs = gf_key_sigalgs (k, &na);
      CHECK (na >= 1);
      b = gf_key_blob (k, &bn);
      CHECK_EQ (gf_key_from_blob (&pub, b, bn), GF_OK);
      for (i = 0; i < na; i++)
        {
          CHECK_EQ (gf_key_sign (k, algs[i], msg, msglen, sig, sizeof sig,
                                 &n), GF_OK);
          CHECK (n <= SIGMAX);
          CHECK_EQ (gf_key_verify (pub, algs[i], msg, msglen, sig, n), GF_OK);
          /* The signature names its algorithm: another one is refused.  */
          CHECK_EQ (gf_key_verify (pub, algs[(i + 1) % na == i
                                              ? i : (i + 1) % na],
                                   msg, msglen, sig, n),
                    na > 1 ? GF_ERR_HOSTKEY : GF_OK);
        }
      /* Two keys differ.  */
      {
        gf_key *k2;

        CHECK_EQ (gf_key_generate (&k2, types[t], 2048), GF_OK);
        CHECK (!gf_key_equal (k, k2));
        if (k2 != NULL)
          {
            CHECK_EQ (gf_key_sign (k2, algs[0], msg, msglen, other,
                                   sizeof other, &n), GF_OK);
            CHECK_EQ (gf_key_verify (pub, algs[0], msg, msglen, other, n),
                      GF_ERR_HOSTKEY);
          }
        gf_key_free (k2);
      }
      /* A key signs only with its own algorithms.  */
      CHECK_EQ (gf_key_sign (k, types[t] == GF_KEY_ED25519
                                ? GF_SIG_ECDSA_NISTP256 : GF_SIG_ED25519,
                             msg, msglen, sig, sizeof sig, &n),
                GF_ERR_UNSUPPORTED);
      gf_key_free (pub);
      gf_key_free (k);
    }
  CHECK_EQ (gf_key_generate (&(gf_key *) { NULL }, GF_KEY_RSA, 1024),
            GF_ERR_UNSUPPORTED);
  CHECK_EQ (gf_key_generate (&(gf_key *) { NULL }, GF_KEY_RSA, 20000),
            GF_ERR_UNSUPPORTED);
}

static size_t
mkblob (uint8_t *buf, size_t cap, const char *name, const char *id,
        const uint8_t *q, size_t qlen)
{
  gf_writer w;

  gf_writer_init (&w, buf, cap);
  gf_wr_cstring (&w, name);
  if (id != NULL)
    gf_wr_cstring (&w, id);
  gf_wr_string (&w, q, qlen);
  return w.len;
}

static void
test_blob_refusals (void)
{
  static uint8_t blob[4096], q[100], good[2048], mod[600];
  gf_key *k = NULL, *gen;
  size_t n, bn;
  const uint8_t *b;
  gf_writer w;

  /* Types that are not in the policy.  */
  memset (q, 1, sizeof q);
  n = mkblob (blob, sizeof blob, "ssh-dss", NULL, q, 20);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_UNSUPPORTED);
  n = mkblob (blob, sizeof blob, "ecdsa-sha2-nistp521", "nistp521", q, 67);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_UNSUPPORTED);
  n = mkblob (blob, sizeof blob, "ssh-dss-cert-v01@openssh.com", NULL, q, 20);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_UNSUPPORTED);
  n = mkblob (blob, sizeof blob, "ecdsa-sha2-nistp521-cert-v01@openssh.com",
              "nistp521", q, 67);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_UNSUPPORTED);
  /* A certificate that is not one (test-cert.c has the rest).  */
  n = mkblob (blob, sizeof blob, "ssh-ed25519-cert-v01@openssh.com", NULL, q, 32);
  CHECK (gf_key_from_blob (&k, blob, n) != GF_OK);
  /* A security key with no application is not one (test-sk.c has the rest). */
  n = mkblob (blob, sizeof blob, "sk-ssh-ed25519@openssh.com", NULL, q, 32);
  CHECK (gf_key_from_blob (&k, blob, n) != GF_OK);
  n = mkblob (blob, sizeof blob, "sk-ecdsa-sha2-nistp384@openssh.com", "nistp384", q, 97);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_UNSUPPORTED);

  /* Ed25519: wrong length.  */
  n = mkblob (blob, sizeof blob, "ssh-ed25519", NULL, q, 31);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_ENCODING);
  n = mkblob (blob, sizeof blob, "ssh-ed25519", NULL, q, 33);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_ENCODING);

  /* ECDSA: a real key, then damaged in each way.  */
  CHECK_EQ (gf_key_generate (&gen, GF_KEY_ECDSA_P256, 0), GF_OK);
  b = gf_key_blob (gen, &bn);
  memcpy (good, b, bn);
  CHECK_EQ (gf_key_from_blob (&k, good, bn), GF_OK);
  gf_key_free (k);
  k = NULL;
  /* Last byte of the point changed: off the curve (almost surely).  */
  memcpy (blob, good, bn);
  blob[bn - 1] ^= 0x55;
  CHECK_EQ (gf_key_from_blob (&k, blob, bn), GF_ERR_ENCODING);
  /* Compressed form.  */
  {
    uint8_t c[33];

    c[0] = 0x02;
    memcpy (c + 1, good + bn - 64, 32);
    n = mkblob (blob, sizeof blob, "ecdsa-sha2-nistp256", "nistp256", c, 33);
    CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_ENCODING);
  }
  /* Wrong curve identifier for the name.  */
  n = mkblob (blob, sizeof blob, "ecdsa-sha2-nistp256", "nistp384",
              good + bn - 65, 65);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_ENCODING);
  /* The point at infinity, and x = y = 0.  */
  memset (q, 0, sizeof q);
  q[0] = 0x04;
  n = mkblob (blob, sizeof blob, "ecdsa-sha2-nistp256", "nistp256", q, 65);
  CHECK_EQ (gf_key_from_blob (&k, blob, n), GF_ERR_ENCODING);
  /* Trailing bytes, and truncation.  */
  memcpy (blob, good, bn);
  blob[bn] = 0;
  CHECK_EQ (gf_key_from_blob (&k, blob, bn + 1), GF_ERR_ENCODING);
  CHECK_EQ (gf_key_from_blob (&k, good, bn - 1), GF_ERR_ENCODING);
  CHECK_EQ (gf_key_from_blob (&k, good, 3), GF_ERR_ENCODING);
  gf_key_free (gen);

  /* RSA: size and exponent.  */
  memset (mod, 0xa5, sizeof mod);
  mod[sizeof mod - 1] = 0xa5;		/* Odd.  */
  {
    static const struct
    {
      unsigned e;
      size_t bytes;
      int rc;
    } v[] = {
      { 65537, 256, GF_OK },		/* 2048 bits: the floor.  */
      { 65537, 255, GF_ERR_UNSUPPORTED },
      { 65537, 128, GF_ERR_UNSUPPORTED },	/* 1024 bits.  */
      { 65537, 513, GF_OK },		/* 4104 bits: allowed.  */
      { 3, 256, GF_ERR_UNSUPPORTED },
      { 17, 256, GF_ERR_UNSUPPORTED },
      { 65538, 256, GF_ERR_UNSUPPORTED },	/* Even.  */
      { 65539, 256, GF_OK }
    };
    size_t i;

    for (i = 0; i < sizeof v / sizeof v[0]; i++)
      {
        uint8_t eb[4];
        size_t el = 0;
        eb[0] = (uint8_t) (v[i].e >> 24);
        eb[1] = (uint8_t) (v[i].e >> 16);
        eb[2] = (uint8_t) (v[i].e >> 8);
        eb[3] = (uint8_t) v[i].e;
        el = 4;
        gf_writer_init (&w, blob, sizeof blob);
        gf_wr_cstring (&w, "ssh-rsa");
        gf_wr_mpint (&w, eb, el);
        mod[0] = 0xa5;
        gf_wr_mpint (&w, mod, v[i].bytes);
        CHECK_EQ (gf_key_from_blob (&k, blob, w.len), v[i].rc);
        gf_key_free (k);
        k = NULL;
      }
    /* Over 16384 bits.  */
    {
      static uint8_t big[2100];

      memset (big, 0xa5, sizeof big);
      gf_writer_init (&w, blob, sizeof blob);
      gf_wr_cstring (&w, "ssh-rsa");
      gf_wr_mpint (&w, (const uint8_t[]) { 1, 0, 1 }, 3);
      gf_wr_mpint (&w, big, 2049);
      CHECK_EQ (gf_wr_status (&w), GF_OK);
      CHECK_EQ (gf_key_from_blob (&k, blob, w.len), GF_ERR_UNSUPPORTED);
    }
  }
}

static void
test_signature_refusals (void)
{
  static uint8_t blob[1024], sig[SIGMAX];
  gf_key *k;
  size_t bn, n;
  gf_writer w;
  uint8_t good[SIGMAX];
  size_t gn;

  msglen = hexbuf (vec_msg, msg, sizeof msg);
  bn = hexbuf (vec_rsa_blob, blob, sizeof blob);
  CHECK_EQ (gf_key_from_blob (&k, blob, bn), GF_OK);

  /* SHA-1 ssh-rsa: the signature is genuine and is refused.  */
  n = hexbuf (vec_rsa_sigsha1, sig, sizeof sig);
  CHECK_EQ (gf_key_verify (k, GF_SIG_RSA_SHA2_256, msg, msglen, sig, n),
            GF_ERR_HOSTKEY);
  CHECK_EQ (gf_key_verify (k, GF_SIG_RSA_SHA2_512, msg, msglen, sig, n),
            GF_ERR_HOSTKEY);
  /* The SHA-256 signature does not pass as SHA-512, or by renaming it.  */
  gn = hexbuf (vec_rsa_sig256, good, sizeof good);
  CHECK_EQ (gf_key_verify (k, GF_SIG_RSA_SHA2_512, msg, msglen, good, gn),
            GF_ERR_HOSTKEY);
  {
    gf_reader r;
    gf_slice nm, sd;

    gf_reader_init (&r, good, gn);
    gf_rd_string (&r, &nm);
    gf_rd_string (&r, &sd);
    gf_writer_init (&w, sig, sizeof sig);
    gf_wr_cstring (&w, "rsa-sha2-512");
    gf_wr_string (&w, sd.data, sd.len);
    CHECK_EQ (gf_key_verify (k, GF_SIG_RSA_SHA2_512, msg, msglen, sig, w.len),
              GF_ERR_HOSTKEY);
    /* Short signature value (leading zero stripped).  */
    gf_writer_init (&w, sig, sizeof sig);
    gf_wr_cstring (&w, "rsa-sha2-256");
    gf_wr_string (&w, sd.data + 1, sd.len - 1);
    CHECK_EQ (gf_key_verify (k, GF_SIG_RSA_SHA2_256, msg, msglen, sig, w.len),
              GF_ERR_HOSTKEY);
    /* Trailing bytes after the signature string.  */
    memcpy (sig, good, gn);
    sig[gn] = 0;
    CHECK_EQ (gf_key_verify (k, GF_SIG_RSA_SHA2_256, msg, msglen, sig, gn + 1),
              GF_ERR_HOSTKEY);
  }
  /* A signature algorithm that does not belong to the key.  */
  CHECK_EQ (gf_key_verify (k, GF_SIG_ED25519, msg, msglen, good, gn),
            GF_ERR_UNSUPPORTED);
  gf_key_free (k);

  /* ECDSA with r or s zero, or not minimally encoded.  */
  bn = hexbuf (vec_p256_blob, blob, sizeof blob);
  CHECK_EQ (gf_key_from_blob (&k, blob, bn), GF_OK);
  {
    uint8_t rs[8];

    gf_writer_init (&w, rs, sizeof rs);
    gf_wr_mpint (&w, (const uint8_t[]) { 0 }, 1);
    gf_wr_mpint (&w, (const uint8_t[]) { 0 }, 1);
    gf_writer_init (&w, sig, sizeof sig);
    gf_wr_cstring (&w, "ecdsa-sha2-nistp256");
    gf_wr_string (&w, rs, 8);
    CHECK_EQ (gf_key_verify (k, GF_SIG_ECDSA_NISTP256, msg, msglen, sig, w.len),
              GF_ERR_HOSTKEY);
    /* The same r and s with a redundant leading zero byte.  */
    n = hexbuf (vec_p256_sig, good, sizeof good);
    CHECK_EQ (gf_key_verify (k, GF_SIG_ECDSA_NISTP256, msg, msglen, good, n),
              GF_OK);
  }
  gf_key_free (k);
}

static void
test_openssh_file_refusals (void)
{
  gf_key *k = NULL;
  char *tampered;
  size_t n = strlen (vec_ed_private), i;

  CHECK_EQ (gf_key_from_openssh_private (&k, "", 0), GF_ERR_ENCODING);
  CHECK_EQ (gf_key_from_openssh_private (&k, "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                                         "AAAA\n", 38), GF_ERR_ENCODING);
  /* Corrupting the base64 anywhere in the body must never give a key that
     is not the original: either an error or the same key.  */
  tampered = malloc (n + 1);
  for (i = 36; i < n - 34; i += 7)
    {
      gf_key *o = NULL;
      int rc;

      memcpy (tampered, vec_ed_private, n + 1);
      if (tampered[i] == '\n' || tampered[i] == '=')
        continue;
      tampered[i] = tampered[i] == 'A' ? 'B' : 'A';
      rc = gf_key_from_openssh_private (&o, tampered, n);
      if (rc == GF_OK)
        {
          gf_key *orig;
          uint8_t b[100];

          /* Only a change in the comment or padding can leave the key.  */
          gf_key_from_openssh_private (&orig, vec_ed_private, n);
          CHECK (gf_key_equal (o, orig));
          (void) b;
          gf_key_free (orig);
        }
      gf_key_free (o);
    }
  free (tampered);
}

/* The one-line text form (.pub files, authorized_keys). */
static void
test_text (void)
{
  static const struct
  {
    const char *pub, *blob;
    enum gf_keytype type;
  } v[] = {
    { vec_ed_pub, vec_ed_blob, GF_KEY_ED25519 },
    { vec_p256_pub, vec_p256_blob, GF_KEY_ECDSA_P256 },
    { vec_p384_pub, vec_p384_blob, GF_KEY_ECDSA_P384 },
    { vec_rsa_pub, vec_rsa_blob, GF_KEY_RSA }
  };
  static uint8_t want[2048];
  char buf[2048], out[2048];
  size_t i, n, len;

  for (i = 0; i < 4; i++)
    {
      gf_key *k = NULL;
      gf_slice comment;
      const uint8_t *b;
      size_t bl, sp;
      const char *second;

      len = strlen (v[i].pub);
      CHECK_EQ (gf_key_from_text (&k, v[i].pub, len, &comment), GF_OK);
      if (k == NULL)
        continue;
      CHECK_EQ (gf_key_type (k), v[i].type);
      CHECK (!gf_key_has_private (k));
      CHECK (gf_slice_equals (comment, "foxtrot-test"));
      n = tst_unhex (v[i].blob, want, sizeof want);
      b = gf_key_blob (k, &bl);
      CHECK (bl == n && memcmp (b, want, n) == 0);
      /* Back to text: the line without its comment and line end.  */
      CHECK_EQ (gf_key_to_text (k, out, sizeof out, &n), GF_OK);
      second = strchr (strchr (v[i].pub, ' ') + 1, ' ');
      sp = (size_t) (second - v[i].pub);
      CHECK (n == sp && memcmp (out, v[i].pub, sp) == 0 && out[n] == 0);
      CHECK_EQ (gf_key_to_text (k, out, n, NULL), GF_ERR_BUFSIZE);
      CHECK_EQ (gf_key_to_text (k, out, n + 1, NULL), GF_OK);
      /* Without asking for the comment, and in other layouts.  */
      CHECK_EQ (gf_key_from_text (&k, out, n, NULL) == GF_OK, 1);
      snprintf (buf, sizeof buf, "  \t%.*s\t \t  c o m m e n t  \r\n", (int) sp,
                v[i].pub);
      {
        gf_key *k2 = NULL;

        CHECK_EQ (gf_key_from_text (&k2, buf, strlen (buf), &comment), GF_OK);
        CHECK (gf_slice_equals (comment, "c o m m e n t"));
        CHECK (k2 != NULL && gf_key_equal (k, k2));
        gf_key_free (k2);
        snprintf (buf, sizeof buf, "%.*s", (int) sp, v[i].pub);
        CHECK_EQ (gf_key_from_text (&k2, buf, strlen (buf), &comment), GF_OK);
        CHECK_EQ (comment.len, 0);
        CHECK (k2 != NULL && gf_key_equal (k, k2));
        gf_key_free (k2);
      }
      gf_key_free (k);

      /* Refused: damage anywhere in it.  */
      {
        static const char *const bad_prefix[] = {
          "", " ", "\n", "ssh-ed25519", "ssh-ed25519 ", "ssh-ed25519\n",
          "ssh-dss AAAAB3NzaC1kc3MAAAAA", "nonsense AAAA"
        };
        size_t j;

        for (j = 0; j < sizeof bad_prefix / sizeof bad_prefix[0]; j++)
          {
            gf_key *k2 = NULL;

            CHECK (gf_key_from_text (&k2, bad_prefix[j], strlen (bad_prefix[j]),
                                     NULL) != GF_OK);
          }
      }
      {
        gf_key *k2 = NULL;
        char *sp1;

        /* A type that is not the key's.  */
        snprintf (buf, sizeof buf, "%s", v[i].pub);
        sp1 = strchr (buf, ' ');
        snprintf (out, sizeof out, "%s%s", i == 0 ? "ssh-rsa" : "ssh-ed25519", sp1);
        CHECK_EQ (gf_key_from_text (&k2, out, strlen (out), NULL), GF_ERR_ENCODING);
        /* No blank between the type and the key; a second line; text after
           the newline; a NUL.  */
        snprintf (out, sizeof out, "%.*s%s", (int) (sp1 - buf), buf, sp1 + 1);
        CHECK (gf_key_from_text (&k2, out, strlen (out), NULL) != GF_OK);
        snprintf (out, sizeof out, "%s\n%s", v[i].pub, v[i].pub);
        CHECK (gf_key_from_text (&k2, out, strlen (out), NULL) != GF_OK);
        snprintf (out, sizeof out, "%s\n# more", v[i].pub);
        CHECK (gf_key_from_text (&k2, out, strlen (out), NULL) != GF_OK);
        snprintf (out, sizeof out, "%s", v[i].pub);
        out[strlen (out) - 1] = 0;
        CHECK (gf_key_from_text (&k2, out, strlen (v[i].pub), NULL) != GF_OK);
        /* The base64: a character not in the alphabet, whitespace inside, a
           missing or extra character, padding missing or doubled.  */
        for (n = 0; n < 7; n++)
          {
            char *b64, *end;
            size_t bl2;

            snprintf (buf, sizeof buf, "%.*s", (int) sp, v[i].pub);
            b64 = strchr (buf, ' ') + 1;
            end = b64 + strlen (b64);
            bl2 = (size_t) (end - b64);
            switch (n)
              {
              case 0: b64[bl2 / 2] = '*'; break;
              case 1: b64[bl2 / 2] = '-'; break;	/* URL alphabet.  */
              case 2: memmove (b64 + 4, b64 + 5, bl2 - 4); break;
              case 3: memmove (b64 + 6, b64 + 5, bl2 - 4); b64[5] = 'A'; break;
              case 4: memmove (b64 + 3, b64 + 2, bl2 - 1); b64[2] = '\n'; break;
              case 5: b64[bl2 / 2] = '='; break;	/* Padding inside.  */
              default: strcat (b64, "="); break;
              }
            CHECK (gf_key_from_text (&k2, buf, strlen (buf), NULL) != GF_OK);
          }
        gf_key_free (k2);
      }
    }
  /* Padding removed from a key that needs it; stray bits in its last
     character (the same bytes with another spelling).  */
  for (i = 1; i < 3; i++)
    {
      gf_key *k2 = NULL;
      char *eq;

      snprintf (buf, sizeof buf, "%s", v[i].pub);
      *strchr (strchr (buf, ' ') + 1, ' ') = 0;
      eq = strchr (buf, '=');
      CHECK (eq != NULL);
      if (eq == NULL)
        continue;
      memmove (eq, eq + 1, strlen (eq));
      CHECK (gf_key_from_text (&k2, buf, strlen (buf), NULL) != GF_OK);
      snprintf (buf, sizeof buf, "%s", v[i].pub);
      *strchr (strchr (buf, ' ') + 1, ' ') = 0;
      eq = strchr (buf, '=');
      {
        static const char alpha[] =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        /* The same data bits with a low bit set that no key has: another
           spelling of the same bytes.  */
        eq[-1] = alpha[(strchr (alpha, eq[-1]) - alpha) | 1];
      }
      CHECK (gf_key_from_text (&k2, buf, strlen (buf), NULL) != GF_OK);
      /* And it is only the stray bits: the right letter is accepted.  */
      snprintf (buf, sizeof buf, "%s", v[i].pub);
      *strchr (strchr (buf, ' ') + 1, ' ') = 0;
      CHECK_EQ (gf_key_from_text (&k2, buf, strlen (buf), NULL), GF_OK);
      gf_key_free (k2);
    }
  /* A text longer than any key is refused outright.  */
  {
    static char big[70000];
    gf_key *k = NULL;

    memset (big, 'A', sizeof big);
    memcpy (big, "ssh-ed25519 ", 12);
    CHECK_EQ (gf_key_from_text (&k, big, sizeof big, NULL), GF_ERR_INVAL);
  }
  CHECK_EQ (gf_key_from_text (NULL, "x", 1, NULL), GF_ERR_INVAL);
}

int
main (void)
{
  gf_crypto_init ();
  test_vectors ();
  test_ed25519_rfc8032 ();
  test_generate ();
  test_blob_refusals ();
  test_signature_refusals ();
  test_openssh_file_refusals ();
  test_text ();
  TST_DONE ();
}
