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

#include <gcrypt.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>

#include "tst-util.h"
#include "vectors-keyfile.h"

#define PASS "correct horse"
#define WRONG "wrong horse"

/* The KDF of the vectors: bcrypt-pbkdf, precomputed by another implementation
   for the files above; asking for anything else is a failure.  */
static int kdf_calls;
static int kdf_fail;

static int
vec_kdf (void *user, const uint8_t *pass, size_t passlen, const uint8_t *salt,
         size_t saltlen, uint32_t rounds, uint8_t *out, size_t outlen)
{
  size_t i;
  char hexsalt[160];

  (void) user;
  kdf_calls++;
  if (kdf_fail || saltlen * 2 + 1 > sizeof hexsalt)
    return 1;
  for (i = 0; i < saltlen; i++)
    snprintf (hexsalt + 2 * i, 3, "%02x", salt[i]);
  for (i = 0; i < sizeof vec_kf_kdfs / sizeof vec_kf_kdfs[0]; i++)
    {
      const struct vec_kf_kdf *v = &vec_kf_kdfs[i];

      if (strlen (v->pass) == passlen && memcmp (v->pass, pass, passlen) == 0
          && strcmp (v->salt, hexsalt) == 0 && v->rounds == rounds
          && v->outlen == outlen)
        {
          static uint8_t b[64];

          CHECK_EQ (tst_unhex (v->out, b, sizeof b), outlen);
          memcpy (out, b, outlen);
          return 0;
        }
    }
  return 1;
}

/* A KDF of our own for the files we write: PBKDF2, which is in libgcrypt.  The
   files then belong to nobody else, but the format and the cipher are the
   same.  */
static int
test_kdf (void *user, const uint8_t *pass, size_t passlen, const uint8_t *salt,
          size_t saltlen, uint32_t rounds, uint8_t *out, size_t outlen)
{
  (void) user;
  return gcry_kdf_derive (pass, passlen, GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt,
                          saltlen, rounds, outlen, out) != 0;
}

/* The same, but one that gives up on a work factor no one asked for in good
   faith, so that a library that forgot to cap it fails instead of hanging.  */
static int
guard_kdf (void *user, const uint8_t *pass, size_t passlen, const uint8_t *salt,
           size_t saltlen, uint32_t rounds, uint8_t *out, size_t outlen)
{
  if (rounds > 100000)
    return 1;
  return test_kdf (user, pass, passlen, salt, saltlen, rounds, out, outlen);
}

static int
sign_and_verify (const gf_key *priv, const gf_key *pub)
{
  static const uint8_t m[] = "a message to sign";
  uint8_t sig[GF_SIG_MAX];
  size_t n, na;
  const enum gf_sigalg *a = gf_key_sigalgs (priv, &na);

  return gf_key_sign (priv, a[0], m, sizeof m, sig, sizeof sig, &n) == GF_OK
    && gf_key_verify (pub, a[0], m, sizeof m, sig, n) == GF_OK;
}

static void
test_read (void)
{
  size_t i;

  for (i = 0; i < sizeof vec_kf_cases / sizeof vec_kf_cases[0]; i++)
    {
      const struct vec_kf_case *c = &vec_kf_cases[i];
      static uint8_t blob[2048];
      gf_key *k = NULL, *plain = NULL;
      size_t bl, bn = tst_unhex (c->pub, blob, sizeof blob);
      const uint8_t *b;
      int rc;

      kdf_calls = 0;
      rc = gf_key_from_openssh_private_encrypted (&k, c->enc, strlen (c->enc),
                                                  PASS, vec_kdf, NULL);
      if (rc != GF_OK)
        fprintf (stderr, "%s (%s): %d\n", c->name, c->cipher, rc);
      CHECK_EQ (rc, GF_OK);
      CHECK_EQ (kdf_calls, 1);
      if (k == NULL)
        continue;
      b = gf_key_blob (k, &bl);
      CHECK (bl == bn && memcmp (b, blob, bn) == 0);
      CHECK (gf_key_has_private (k));
      /* Decrypting gave the very key ssh-keygen -p wrote unprotected.  */
      CHECK_EQ (gf_key_from_openssh_private (&plain, c->plain, strlen (c->plain)),
                GF_OK);
      CHECK (plain != NULL && gf_key_equal (k, plain));
      CHECK (plain != NULL && sign_and_verify (k, plain));
      CHECK (plain != NULL && sign_and_verify (plain, k));
      gf_key_free (plain);
      gf_key_free (k);

      /* The unprotected file does not need the passphrase or the KDF. */
      kdf_calls = 0;
      k = NULL;
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, c->plain, strlen (c->plain),
                                                       NULL, NULL, NULL), GF_OK);
      CHECK_EQ (kdf_calls, 0);
      gf_key_free (k);
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, c->plain, strlen (c->plain),
                                                       WRONG, vec_kdf, NULL), GF_OK);
      CHECK_EQ (kdf_calls, 0);
      gf_key_free (k);

      /* A wrong passphrase, by the tag or by the check values; nothing
         comes out.  */
      k = NULL;
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, c->enc, strlen (c->enc),
                                                       WRONG, vec_kdf, NULL),
                GF_ERR_PASSPHRASE);
      CHECK (k == NULL);
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, c->enc, strlen (c->enc),
                                                       "", vec_kdf, NULL),
                GF_ERR_HANDLER);	/* The table has no such answer.  */
      /* No passphrase, no KDF, or the plain entry point: refused as before. */
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, c->enc, strlen (c->enc),
                                                       NULL, vec_kdf, NULL),
                GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, c->enc, strlen (c->enc),
                                                       PASS, NULL, NULL),
                GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_from_openssh_private (&k, c->enc, strlen (c->enc)),
                GF_ERR_UNSUPPORTED);
      /* A KDF that fails.  */
      kdf_fail = 1;
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&k, c->enc, strlen (c->enc),
                                                       PASS, vec_kdf, NULL),
                GF_ERR_HANDLER);
      kdf_fail = 0;
      CHECK (k == NULL);
    }
}

/* Damage to an authenticated file is always found: change any character of
   the base64 and the key does not come out.  */
static void
test_tamper_gcm (void)
{
  static const char alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t ci, i;

  for (ci = 0; ci < sizeof vec_kf_cases / sizeof vec_kf_cases[0]; ci++)
    {
      const struct vec_kf_case *c = &vec_kf_cases[ci];
      static char copy[4096];
      size_t n = strlen (c->enc), first, last, bad = 0;
      const char *nl;

      if (strstr (c->cipher, "gcm") == NULL)
        continue;
      memcpy (copy, c->enc, n + 1);
      first = strlen ("-----BEGIN OPENSSH PRIVATE KEY-----\n");
      nl = strstr (c->enc, "-----END");
      last = (size_t) (nl - c->enc) - 4;	/* The last quad has stray bits. */
      for (i = first; i < last; i++)
        {
          gf_key *k = NULL;
          char old = copy[i];

          if (old == '\n')
            continue;
          copy[i] = alpha[(strchr (alpha, old) - alpha + 1) % 64];
          if (gf_key_from_openssh_private_encrypted (&k, copy, n, PASS, vec_kdf,
                                                     NULL) == GF_OK)
            bad++;
          gf_key_free (k);
          copy[i] = old;
        }
      CHECK_EQ (bad, 0);
    }
}

/* Files shaped to be refused. */
static size_t
b64 (const uint8_t *in, size_t n, char *out)
{
  static const char a[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i, o = 0;

  for (i = 0; i < n; i += 3)
    {
      uint32_t v = (uint32_t) in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0)
        | (i + 2 < n ? in[i + 2] : 0);

      out[o++] = a[v >> 18];
      out[o++] = a[(v >> 12) & 63];
      out[o++] = i + 1 < n ? a[(v >> 6) & 63] : '=';
      out[o++] = i + 2 < n ? a[v & 63] : '=';
      if ((i / 3 + 1) % 17 == 0)
        out[o++] = '\n';
    }
  out[o++] = '\n';
  return o;
}

struct file
{
  const char *cipher, *kdf;
  size_t saltlen;
  uint32_t rounds;
  size_t privlen;
  size_t taglen;
  int trailing;
  uint32_t nkeys;
};

static int
read_built (const struct file *f)
{
  static uint8_t raw[8192], salt[128], priv[256], pub[256];
  static char pem[16384];
  gf_writer w;
  gf_key *k = NULL, *src = NULL;
  size_t pubn, o = 0;
  int rc;
  size_t km;

  /* The public key, any: the checks come first.  */
  CHECK_EQ (gf_key_generate (&src, GF_KEY_ED25519, 0), GF_OK);
  {
    size_t bl;
    const uint8_t *b = gf_key_blob (src, &bl);

    memcpy (pub, b, bl);
    pubn = bl;
  }
  memset (salt, 3, sizeof salt);
  memset (priv, 5, sizeof priv);
  gf_writer_init (&w, raw, sizeof raw);
  gf_wr_bytes (&w, "openssh-key-v1", 15);
  gf_wr_cstring (&w, f->cipher);
  gf_wr_cstring (&w, f->kdf);
  km = gf_wr_string_begin (&w);
  gf_wr_string (&w, salt, f->saltlen);
  gf_wr_u32 (&w, f->rounds);
  gf_wr_string_end (&w, km);
  gf_wr_u32 (&w, f->nkeys);
  gf_wr_string (&w, pub, pubn);
  gf_wr_string (&w, priv, f->privlen);
  gf_wr_bytes (&w, priv, f->taglen);
  if (f->trailing)
    gf_wr_u8 (&w, 0);
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  o += (size_t) snprintf (pem, sizeof pem, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
  o += b64 (raw, w.len, pem + o);
  o += (size_t) snprintf (pem + o, sizeof pem - o, "-----END OPENSSH PRIVATE KEY-----\n");
  rc = gf_key_from_openssh_private_encrypted (&k, pem, o, PASS, guard_kdf, NULL);
  CHECK (k == NULL);
  gf_key_free (src);
  return rc;
}

static void
test_refused_files (void)
{
  struct file ok = { "aes256-ctr", "bcrypt", 16, 16, 64, 0, 0, 1 };
  struct file f;

  /* Not refused by the shape; it is the passphrase (the key is nothing). */
  CHECK_EQ (read_built (&ok), GF_ERR_PASSPHRASE);
  f = ok;
  f.cipher = "aes256-gcm@openssh.com";
  f.taglen = 16;
  CHECK_EQ (read_built (&f), GF_ERR_PASSPHRASE);
  /* Ciphers we will not read for a file, whatever their name elsewhere. */
  f = ok;
  f.cipher = "aes256-cbc";
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.cipher = "3des-cbc";
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.cipher = "chacha20-poly1305@openssh.com";
  f.taglen = 16;
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.cipher = "aes256-ctr@openssh.com";
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.cipher = "AES256-CTR";
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  /* A key derivation that is not bcrypt, or none with a cipher. */
  f = ok;
  f.kdf = "none";
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.kdf = "argon2";
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.kdf = "BCRYPT";
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f = ok;
  f.cipher = "none";
  f.kdf = "bcrypt";
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  /* Work factors: none, too many; salts too short or too long. */
  f = ok;
  f.rounds = 0;
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.rounds = GF_KDF_MAX_ROUNDS + 1;
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.rounds = 0xffffffffu;
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.rounds = GF_KDF_MAX_ROUNDS;
  CHECK_EQ (read_built (&f), GF_ERR_PASSPHRASE);
  f = ok;
  f.saltlen = 7;
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.saltlen = 65;
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);
  f.saltlen = 8;
  CHECK_EQ (read_built (&f), GF_ERR_PASSPHRASE);
  f.saltlen = 64;
  CHECK_EQ (read_built (&f), GF_ERR_PASSPHRASE);
  /* Lengths: not a whole number of blocks, empty, a tag missing or extra,
     bytes after, two keys.  */
  f = ok;
  f.privlen = 63;
  CHECK_EQ (read_built (&f), GF_ERR_ENCODING);
  f.privlen = 0;
  CHECK_EQ (read_built (&f), GF_ERR_ENCODING);
  f = ok;
  f.trailing = 1;
  CHECK_EQ (read_built (&f), GF_ERR_ENCODING);
  f = ok;
  f.taglen = 16;
  CHECK_EQ (read_built (&f), GF_ERR_ENCODING);
  f = ok;
  f.cipher = "aes256-gcm@openssh.com";
  f.taglen = 15;
  CHECK_EQ (read_built (&f), GF_ERR_ENCODING);
  f.taglen = 0;
  CHECK_EQ (read_built (&f), GF_ERR_ENCODING);
  f = ok;
  f.nkeys = 2;
  CHECK_EQ (read_built (&f), GF_ERR_UNSUPPORTED);	/* One key per file. */
}

/* An unencrypted RSA key file that has the public key of a real key but
   whatever primes P and Q (as bytes; length 0 is the number zero).  The
   fuzzer found that zero primes crashed libgcrypt in the modular inverse.  */
static int
read_primes (const gf_key *src, const uint8_t *p, size_t pl, const uint8_t *q,
             size_t ql)
{
  static uint8_t raw[8192], priv[2048];
  static char pem[16384];
  gf_reader r;
  gf_slice type, e, n;
  gf_writer w, pw;
  gf_key *k = NULL;
  size_t bl, o = 0, km;
  const uint8_t *blob = gf_key_blob (src, &bl);
  int rc;

  gf_reader_init (&r, blob, bl);
  CHECK_EQ (gf_rd_string (&r, &type), GF_OK);
  CHECK_EQ (gf_rd_mpint (&r, &e), GF_OK);
  CHECK_EQ (gf_rd_mpint (&r, &n), GF_OK);
  gf_writer_init (&pw, priv, sizeof priv);
  gf_wr_u32 (&pw, 0x01020304);
  gf_wr_u32 (&pw, 0x01020304);
  gf_wr_cstring (&pw, "ssh-rsa");
  gf_wr_mpint (&pw, n.data, n.len);
  gf_wr_mpint (&pw, e.data, e.len);
  gf_wr_mpint (&pw, n.data, n.len);	/* d: anything */
  gf_wr_mpint (&pw, e.data, e.len);	/* iqmp: unused */
  gf_wr_mpint (&pw, p, pl);
  gf_wr_mpint (&pw, q, ql);
  gf_wr_cstring (&pw, "");
  while (pw.len % 8 != 0)
    gf_wr_u8 (&pw, (uint8_t) (pw.len % 8 + 1));
  CHECK_EQ (gf_wr_status (&pw), GF_OK);

  gf_writer_init (&w, raw, sizeof raw);
  gf_wr_bytes (&w, "openssh-key-v1", 15);
  gf_wr_cstring (&w, "none");
  gf_wr_cstring (&w, "none");
  km = gf_wr_string_begin (&w);
  gf_wr_string_end (&w, km);
  gf_wr_u32 (&w, 1);
  gf_wr_string (&w, blob, bl);
  gf_wr_string (&w, priv, pw.len);
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  o += (size_t) snprintf (pem, sizeof pem, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
  o += b64 (raw, w.len, pem + o);
  o += (size_t) snprintf (pem + o, sizeof pem - o, "-----END OPENSSH PRIVATE KEY-----\n");
  rc = gf_key_from_openssh_private_encrypted (&k, pem, o, NULL, NULL, NULL);
  CHECK (k == NULL);
  return rc;
}

static void
test_degenerate_primes (void)
{
  static const uint8_t one[1] = { 1 }, five[1] = { 5 }, seven[1] = { 7 };
  gf_key *src = NULL;

  CHECK_EQ (gf_key_generate (&src, GF_KEY_RSA, 2048), GF_OK);
  /* Zero, one and equal primes are refused, not fed to libgcrypt.  */
  CHECK_EQ (read_primes (src, NULL, 0, NULL, 0), GF_ERR_ENCODING);
  CHECK_EQ (read_primes (src, NULL, 0, seven, 1), GF_ERR_ENCODING);
  CHECK_EQ (read_primes (src, seven, 1, NULL, 0), GF_ERR_ENCODING);
  CHECK_EQ (read_primes (src, one, 1, seven, 1), GF_ERR_ENCODING);
  CHECK_EQ (read_primes (src, seven, 1, one, 1), GF_ERR_ENCODING);
  CHECK_EQ (read_primes (src, five, 1, five, 1), GF_ERR_ENCODING);
  gf_key_free (src);
}

/* Writing an encrypted file and reading it back, for each kind of key.  */
static void
test_write (void)
{
  static const struct
  {
    enum gf_keytype type;
    unsigned bits;
  } t[] = {
    { GF_KEY_ED25519, 0 }, { GF_KEY_ECDSA_P256, 0 }, { GF_KEY_ECDSA_P384, 0 },
    { GF_KEY_RSA, 2048 }
  };
  size_t i;

  for (i = 0; i < 4; i++)
    {
      gf_key *k = NULL, *back = NULL;
      static char file[16384], file2[16384];
      size_t n, n2;

      CHECK_EQ (gf_key_generate (&k, t[i].type, t[i].bits), GF_OK);
      CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file, sizeof file, &n,
                                                     "s3cret", 5, test_kdf, NULL),
                GF_OK);
      CHECK (strncmp (file, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 36) == 0);
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&back, file, n, "s3cret",
                                                       test_kdf, NULL), GF_OK);
      CHECK (back != NULL && gf_key_equal (k, back));
      CHECK (back != NULL && sign_and_verify (back, k));
      gf_key_free (back);
      back = NULL;
      CHECK_EQ (gf_key_from_openssh_private_encrypted (&back, file, n, "S3cret",
                                                       test_kdf, NULL),
                GF_ERR_PASSPHRASE);
      CHECK (back == NULL);
      CHECK_EQ (gf_key_from_openssh_private (&back, file, n), GF_ERR_UNSUPPORTED);
      /* A fresh salt and check values every time. */
      CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file2, sizeof file2, &n2,
                                                     "s3cret", 5, test_kdf, NULL),
                GF_OK);
      CHECK (n2 != n || memcmp (file, file2, n) != 0);
      /* Too small a buffer, once written; the default rounds. */
      CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file2, n - 1, &n2,
                                                     "s3cret", 5, test_kdf, NULL),
                GF_ERR_BUFSIZE);
      CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file2, sizeof file2, &n2,
                                                     "s3cret", 0, test_kdf, NULL),
                GF_OK);
      gf_key_free (k);
    }
  {
    gf_key *k = NULL;
    char file[16384];
    size_t n;

    CHECK_EQ (gf_key_generate (&k, GF_KEY_ED25519, 0), GF_OK);
    CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file, sizeof file, &n, NULL,
                                                   5, test_kdf, NULL), GF_ERR_INVAL);
    CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file, sizeof file, &n, "x",
                                                   5, NULL, NULL), GF_ERR_INVAL);
    CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file, sizeof file, &n, "x",
                                                   GF_KDF_MAX_ROUNDS + 1, test_kdf,
                                                   NULL), GF_ERR_RANGE);
    CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file, sizeof file, &n, "x",
                                                   GF_KDF_MAX_ROUNDS, test_kdf, NULL),
              GF_OK);
    kdf_fail = 1;
    CHECK_EQ (gf_key_to_openssh_private_encrypted (k, file, sizeof file, &n, "x", 5,
                                                   vec_kdf, NULL), GF_ERR_HANDLER);
    kdf_fail = 0;
    gf_key_free (k);
  }
}

int
main (void)
{
  gf_crypto_init ();
  test_read ();
  test_tamper_gcm ();
  test_refused_files ();
  test_degenerate_primes ();
  test_write ();
  TST_DONE ();
}
