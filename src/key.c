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

#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>

#include "internal.h"

#define ED_LEN 32

struct gf_key
{
  enum gf_keytype type;
  unsigned bits;
  uint8_t *blob;
  size_t bloblen;
  gcry_sexp_t pub;
  gcry_sexp_t priv;		/* NULL for a public key.  */
};

static const struct
{
  enum gf_keytype type;
  const char *name;		/* Key blob type name.  */
  const char *curve_id;		/* RFC 5656 identifier, ECDSA only.  */
  const char *curve;		/* libgcrypt curve name.  */
  size_t point_len;
  unsigned bits;
} types[] = {
  { GF_KEY_ED25519, "ssh-ed25519", NULL, "Ed25519", ED_LEN, 256 },
  { GF_KEY_ECDSA_P256, "ecdsa-sha2-nistp256", "nistp256", "NIST P-256", 65, 256 },
  { GF_KEY_ECDSA_P384, "ecdsa-sha2-nistp384", "nistp384", "NIST P-384", 97, 384 },
  { GF_KEY_RSA, "ssh-rsa", NULL, NULL, 0, 0 }
};

static const char *
type_name (enum gf_keytype t)
{
  size_t i;

  for (i = 0; i < sizeof types / sizeof types[0]; i++)
    if (types[i].type == t)
      return types[i].name;
  return NULL;
}

static size_t
type_index (enum gf_keytype t)
{
  size_t i;

  for (i = 0; i < sizeof types / sizeof types[0]; i++)
    if (types[i].type == t)
      return i;
  return 0;
}

void
gf_key_free (gf_key *k)
{
  if (k == NULL)
    return;
  gcry_sexp_release (k->pub);
  gcry_sexp_release (k->priv);
  free (k->blob);
  free (k);
}

enum gf_keytype
gf_key_type (const gf_key *k)
{
  return k->type;
}

unsigned
gf_key_bits (const gf_key *k)
{
  return k->bits;
}

int
gf_key_has_private (const gf_key *k)
{
  return k->priv != NULL;
}

const char *
gf_key_type_name (const gf_key *k)
{
  return type_name (k->type);
}

const uint8_t *
gf_key_blob (const gf_key *k, size_t *len)
{
  *len = k->bloblen;
  return k->blob;
}

int
gf_key_equal (const gf_key *a, const gf_key *b)
{
  return a->bloblen == b->bloblen
    && memcmp (a->blob, b->blob, a->bloblen) == 0;
}

const enum gf_sigalg *
gf_key_sigalgs (const gf_key *k, size_t *n)
{
  static const enum gf_sigalg ed[] = { GF_SIG_ED25519 };
  static const enum gf_sigalg p256[] = { GF_SIG_ECDSA_NISTP256 };
  static const enum gf_sigalg p384[] = { GF_SIG_ECDSA_NISTP384 };
  static const enum gf_sigalg rsa[] = { GF_SIG_RSA_SHA2_512,
                                        GF_SIG_RSA_SHA2_256 };

  switch (k->type)
    {
    case GF_KEY_ED25519:
      *n = 1;
      return ed;
    case GF_KEY_ECDSA_P256:
      *n = 1;
      return p256;
    case GF_KEY_ECDSA_P384:
      *n = 1;
      return p384;
    default:
      *n = 2;
      return rsa;
    }
}

/* ------------------------------------------------------------------ */
/* Small helpers over libgcrypt                                       */
/* ------------------------------------------------------------------ */

/* The binary content of the token NAME inside S, as a copy in a newly
   allocated buffer of exactly its length (so it can be wiped).  */
static uint8_t *
sexp_bytes (gcry_sexp_t s, const char *name, size_t *len)
{
  gcry_sexp_t t = gcry_sexp_find_token (s, name, 0);
  const char *d;
  uint8_t *copy;

  if (t == NULL)
    return NULL;
  d = gcry_sexp_nth_data (t, 1, len);
  if (d == NULL || *len == 0)
    {
      gcry_sexp_release (t);
      return NULL;
    }
  copy = malloc (*len);
  if (copy != NULL)
    memcpy (copy, d, *len);
  gcry_sexp_release (t);
  return copy;
}

static gcry_mpi_t
sexp_mpi (gcry_sexp_t s, const char *name)
{
  gcry_sexp_t t = gcry_sexp_find_token (s, name, 0);
  gcry_mpi_t m;

  if (t == NULL)
    return NULL;
  m = gcry_sexp_nth_mpi (t, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (t);
  return m;
}

static gcry_mpi_t
mpi_from (const uint8_t *data, size_t len)
{
  gcry_mpi_t m = NULL;

  if (gcry_mpi_scan (&m, GCRYMPI_FMT_USG, data, len, NULL))
    return NULL;
  return m;
}

/* Big-endian magnitude of M in a malloc'd buffer, without leading zeros.
   If PAD is nonzero, left-padded with zeros to PAD bytes.  */
static uint8_t *
mpi_bytes (gcry_mpi_t m, size_t pad, size_t *len)
{
  size_t n = (gcry_mpi_get_nbits (m) + 7) / 8, total = n > pad ? n : pad;
  uint8_t *buf = malloc (total ? total : 1);

  if (buf == NULL)
    return NULL;
  if (n > 0 && gcry_mpi_print (GCRYMPI_FMT_USG, buf + (total - n), n, NULL, m))
    {
      free (buf);
      return NULL;
    }
  memset (buf, 0, total - n);
  *len = total;
  return buf;
}

/* ------------------------------------------------------------------ */
/* Building a key from its parts                                      */
/* ------------------------------------------------------------------ */

static int
make_blob (gf_key *k, const uint8_t *q, size_t qlen, gcry_mpi_t n, gcry_mpi_t e)
{
  uint8_t *buf;
  size_t cap, nl = 0, el = 0;
  uint8_t *nb = NULL, *eb = NULL;
  gf_writer w;
  size_t ti = type_index (k->type);

  if (k->type == GF_KEY_RSA)
    {
      nb = mpi_bytes (n, 0, &nl);
      eb = mpi_bytes (e, 0, &el);
      if (nb == NULL || eb == NULL)
        {
          free (nb);
          free (eb);
          return GF_ERR_NOMEM;
        }
    }
  cap = 64 + qlen + nl + el;
  buf = malloc (cap);
  if (buf == NULL)
    {
      free (nb);
      free (eb);
      return GF_ERR_NOMEM;
    }
  gf_writer_init (&w, buf, cap);
  gf_wr_cstring (&w, types[ti].name);
  switch (k->type)
    {
    case GF_KEY_ED25519:
      gf_wr_string (&w, q, qlen);
      break;
    case GF_KEY_RSA:
      gf_wr_mpint (&w, eb, el);
      gf_wr_mpint (&w, nb, nl);
      break;
    default:
      gf_wr_cstring (&w, types[ti].curve_id);
      gf_wr_string (&w, q, qlen);
      break;
    }
  free (nb);
  free (eb);
  if (gf_wr_status (&w) != GF_OK)
    {
      free (buf);
      return GF_ERR_BUFSIZE;
    }
  k->blob = buf;
  k->bloblen = w.len;
  return GF_OK;
}

static int
pub_sexp (gf_key *k, const uint8_t *q, size_t qlen, gcry_mpi_t n, gcry_mpi_t e)
{
  size_t ti = type_index (k->type);
  gcry_error_t err;

  if (k->type == GF_KEY_RSA)
    err = gcry_sexp_build (&k->pub, NULL, "(public-key (rsa (n %m)(e %m)))",
                           n, e);
  else if (k->type == GF_KEY_ED25519)
    err = gcry_sexp_build (&k->pub, NULL,
                           "(public-key (ecc (curve Ed25519)(flags eddsa)(q %b)))",
                           (int) qlen, q);
  else
    err = gcry_sexp_build (&k->pub, NULL, "(public-key (ecc (curve %s)(q %b)))",
                           types[ti].curve, (int) qlen, q);
  return err ? GF_ERR_CRYPTO : GF_OK;
}

/* Fill in K's public parts from Q (EC) or N and E (RSA).  */
static int
finish_public (gf_key *k, const uint8_t *q, size_t qlen, gcry_mpi_t n,
               gcry_mpi_t e)
{
  int r;

  if (k->type == GF_KEY_RSA)
    k->bits = gcry_mpi_get_nbits (n);
  else
    k->bits = types[type_index (k->type)].bits;
  r = pub_sexp (k, q, qlen, n, e);
  if (r == GF_OK)
    r = make_blob (k, q, qlen, n, e);
  return r;
}

/* The checks on an RSA public key that policy demands.  */
static int
rsa_acceptable (gcry_mpi_t n, gcry_mpi_t e)
{
  unsigned bits = gcry_mpi_get_nbits (n);
  gcry_mpi_t min = gcry_mpi_set_ui (NULL, 65537);
  int ok = bits >= GF_MIN_RSA_BITS && bits <= GF_RSA_MAX_BITS
    && gcry_mpi_test_bit (n, 0)			/* Odd modulus.  */
    && gcry_mpi_test_bit (e, 0)			/* Odd exponent.  */
    && gcry_mpi_cmp (e, min) >= 0
    && gcry_mpi_cmp (e, n) < 0;

  gcry_mpi_release (min);
  return ok;
}

int
gfi_ec_point_ok (const char *curve, const uint8_t *q, size_t qlen)
{
  gcry_ctx_t ctx = NULL;
  gcry_mpi_t x = NULL, y = NULL, p = NULL;
  gcry_mpi_point_t pt = NULL;
  size_t c = (qlen - 1) / 2;
  int ok = 0;

  if (qlen < 3 || q[0] != 0x04 || (qlen - 1) % 2)
    return 0;
  if (gcry_mpi_ec_new (&ctx, NULL, curve))
    return 0;
  x = mpi_from (q + 1, c);
  y = mpi_from (q + 1 + c, c);
  p = gcry_mpi_ec_get_mpi ("p", ctx, 1);
  pt = gcry_mpi_point_new (0);
  if (x != NULL && y != NULL && p != NULL && pt != NULL
      && gcry_mpi_cmp (x, p) < 0 && gcry_mpi_cmp (y, p) < 0)
    {
      gcry_mpi_point_set (pt, x, y, GCRYMPI_CONST_ONE);
      ok = gcry_mpi_ec_curve_point (pt, ctx);
    }
  gcry_mpi_point_release (pt);
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (p);
  gcry_ctx_release (ctx);
  return ok;
}

int
gf_key_from_blob (gf_key **out, const uint8_t *blob, size_t len)
{
  gf_reader r;
  gf_slice name, a, b;
  gf_key *k;
  size_t ti;
  int rc = GF_ERR_UNSUPPORTED;

  if (out == NULL || blob == NULL)
    return GF_ERR_INVAL;
  rc = gf_crypto_init ();
  if (rc != GF_OK)
    return rc;
  gf_reader_init (&r, blob, len);
  if (gf_rd_string (&r, &name) != GF_OK)
    return GF_ERR_ENCODING;
  for (ti = 0; ti < sizeof types / sizeof types[0]; ti++)
    if (gf_slice_equals (name, types[ti].name))
      break;
  if (ti == sizeof types / sizeof types[0])
    return GF_ERR_UNSUPPORTED;

  k = calloc (1, sizeof *k);
  if (k == NULL)
    return GF_ERR_NOMEM;
  k->type = types[ti].type;
  rc = GF_ERR_ENCODING;

  if (k->type == GF_KEY_ED25519)
    {
      if (gf_rd_string (&r, &a) != GF_OK || a.len != ED_LEN
          || gf_rd_finish (&r) != GF_OK)
        goto fail;
      rc = finish_public (k, a.data, a.len, NULL, NULL);
    }
  else if (k->type == GF_KEY_RSA)
    {
      gcry_mpi_t e, n;

      if (gf_rd_mpint (&r, &a) != GF_OK || gf_rd_mpint (&r, &b) != GF_OK
          || gf_rd_finish (&r) != GF_OK)
        goto fail;
      e = mpi_from (a.data, a.len);
      n = mpi_from (b.data, b.len);
      if (e == NULL || n == NULL)
        rc = GF_ERR_NOMEM;
      else if (!rsa_acceptable (n, e))
        rc = GF_ERR_UNSUPPORTED;
      else
        rc = finish_public (k, NULL, 0, n, e);
      gcry_mpi_release (e);
      gcry_mpi_release (n);
    }
  else
    {
      if (gf_rd_string (&r, &a) != GF_OK || gf_rd_string (&r, &b) != GF_OK
          || gf_rd_finish (&r) != GF_OK)
        goto fail;
      if (!gf_slice_equals (a, types[ti].curve_id) || b.len != types[ti].point_len
          || !gfi_ec_point_ok (types[ti].curve, b.data, b.len))
        goto fail;
      rc = finish_public (k, b.data, b.len, NULL, NULL);
    }
  if (rc != GF_OK)
    goto fail;
  *out = k;
  return GF_OK;

fail:
  gf_key_free (k);
  return rc;
}

/* ------------------------------------------------------------------ */
/* Generation                                                         */
/* ------------------------------------------------------------------ */

int
gf_key_generate (gf_key **out, enum gf_keytype type, unsigned bits)
{
  gcry_sexp_t spec = NULL, res = NULL;
  gcry_error_t err;
  gf_key *k;
  size_t ti = type_index (type);
  int rc;

  if (out == NULL || type_name (type) == NULL)
    return GF_ERR_INVAL;
  rc = gf_crypto_init ();
  if (rc != GF_OK)
    return rc;
  if (type == GF_KEY_RSA)
    {
      if (bits == 0)
        bits = 3072;
      if (bits < GF_MIN_RSA_BITS || bits > GF_RSA_MAX_BITS)
        return GF_ERR_UNSUPPORTED;
      err = gcry_sexp_build (&spec, NULL,
                             "(genkey (rsa (nbits %d)))",
                             (int) bits);
    }
  else if (type == GF_KEY_ED25519)
    err = gcry_sexp_build (&spec, NULL,
                           "(genkey (ecc (curve Ed25519)(flags eddsa)))");
  else
    err = gcry_sexp_build (&spec, NULL, "(genkey (ecc (curve %s)))",
                           types[ti].curve);
  if (err)
    return GF_ERR_CRYPTO;
  err = gcry_pk_genkey (&res, spec);
  gcry_sexp_release (spec);
  if (err)
    return GF_ERR_CRYPTO;

  k = calloc (1, sizeof *k);
  if (k == NULL)
    {
      gcry_sexp_release (res);
      return GF_ERR_NOMEM;
    }
  k->type = type;
  k->priv = gcry_sexp_find_token (res, "private-key", 0);
  {
    gcry_sexp_t pub = gcry_sexp_find_token (res, "public-key", 0);
    uint8_t *q = NULL;
    size_t ql = 0;
    gcry_mpi_t n = NULL, e = NULL;

    gcry_sexp_release (res);
    if (pub == NULL || k->priv == NULL)
      rc = GF_ERR_CRYPTO;
    else if (type == GF_KEY_RSA)
      {
        n = sexp_mpi (pub, "n");
        e = sexp_mpi (pub, "e");
        rc = n && e ? finish_public (k, NULL, 0, n, e) : GF_ERR_CRYPTO;
      }
    else
      {
        q = sexp_bytes (pub, "q", &ql);
        rc = q ? finish_public (k, q, ql, NULL, NULL) : GF_ERR_CRYPTO;
      }
    free (q);
    gcry_mpi_release (n);
    gcry_mpi_release (e);
    gcry_sexp_release (pub);
  }
  if (rc != GF_OK)
    {
      gf_key_free (k);
      return rc;
    }
  *out = k;
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Signatures                                                         */
/* ------------------------------------------------------------------ */

static int
alg_fits_key (const gf_key *k, enum gf_sigalg alg)
{
  const char *kt = gf_sigalg_key_type (alg);

  return kt != NULL && strcmp (kt, type_name (k->type)) == 0;
}

int
gf_key_sign (const gf_key *k, enum gf_sigalg alg, const uint8_t *data,
             size_t len, uint8_t *out, size_t cap, size_t *outlen)
{
  gcry_sexp_t d = NULL, sig = NULL;
  gcry_error_t err;
  gf_writer w;
  uint8_t digest[64];
  enum gf_hash h = GF_HASH_SHA256;
  const char *hname = "sha256";
  int rc;
  size_t mark;

  if (k == NULL || (data == NULL && len > 0) || out == NULL || outlen == NULL)
    return GF_ERR_INVAL;
  if (k->priv == NULL)
    return GF_ERR_INVAL;
  if (!alg_fits_key (k, alg))
    return GF_ERR_UNSUPPORTED;
  rc = gf_crypto_init ();
  if (rc != GF_OK)
    return rc;

  switch (alg)
    {
    case GF_SIG_ED25519:
      err = gcry_sexp_build (&d, NULL,
                             "(data (flags eddsa)(hash-algo sha512)(value %b))",
                             (int) len, data);
      break;
    default:
      if (alg == GF_SIG_ECDSA_NISTP384 || alg == GF_SIG_RSA_SHA2_512)
        {
          h = alg == GF_SIG_RSA_SHA2_512 ? GF_HASH_SHA512 : GF_HASH_SHA384;
          hname = alg == GF_SIG_RSA_SHA2_512 ? "sha512" : "sha384";
        }
      rc = gf_hash_compute (h, data, len, digest, gf_hash_size (h));
      if (rc != GF_OK)
        return rc;
      err = gcry_sexp_build (&d, NULL,
                             alg == GF_SIG_RSA_SHA2_256
                             || alg == GF_SIG_RSA_SHA2_512
                             ? "(data (flags pkcs1)(hash %s %b))"
                             : "(data (flags rfc6979)(hash %s %b))",
                             hname, (int) gf_hash_size (h), digest);
      break;
    }
  if (err)
    return GF_ERR_CRYPTO;
  err = gcry_pk_sign (&sig, d, k->priv);
  gcry_sexp_release (d);
  if (err)
    return GF_ERR_CRYPTO;

  gf_writer_init (&w, out, cap);
  gf_wr_cstring (&w, gf_sigalg_name (alg));
  mark = gf_wr_string_begin (&w);
  rc = GF_OK;
  if (alg == GF_SIG_ED25519)
    {
      size_t rl, sl;
      uint8_t *r = sexp_bytes (sig, "r", &rl), *s = sexp_bytes (sig, "s", &sl);

      if (r == NULL || s == NULL || rl != ED_LEN || sl != ED_LEN)
        rc = GF_ERR_CRYPTO;
      else
        {
          gf_wr_bytes (&w, r, rl);
          gf_wr_bytes (&w, s, sl);
        }
      free (r);
      free (s);
    }
  else if (alg == GF_SIG_RSA_SHA2_256 || alg == GF_SIG_RSA_SHA2_512)
    {
      gcry_mpi_t s = sexp_mpi (sig, "s");
      size_t sl;
      uint8_t *sb = s ? mpi_bytes (s, (k->bits + 7) / 8, &sl) : NULL;

      if (sb == NULL)
        rc = GF_ERR_CRYPTO;
      else
        gf_wr_bytes (&w, sb, sl);
      free (sb);
      gcry_mpi_release (s);
    }
  else
    {
      gcry_mpi_t r = sexp_mpi (sig, "r"), s = sexp_mpi (sig, "s");
      size_t rl, sl;
      uint8_t *rb = r ? mpi_bytes (r, 0, &rl) : NULL;
      uint8_t *sb = s ? mpi_bytes (s, 0, &sl) : NULL;

      if (rb == NULL || sb == NULL)
        rc = GF_ERR_CRYPTO;
      else
        {
          gf_wr_mpint (&w, rb, rl);
          gf_wr_mpint (&w, sb, sl);
        }
      free (rb);
      free (sb);
      gcry_mpi_release (r);
      gcry_mpi_release (s);
    }
  gcry_sexp_release (sig);
  if (rc != GF_OK)
    return rc;
  gf_wr_string_end (&w, mark);
  if (gf_wr_status (&w) != GF_OK)
    return GF_ERR_BUFSIZE;
  *outlen = w.len;
  return GF_OK;
}

/* RFC 8032 section 5.1.7: S must be less than the group order L, or the
   signature can be altered into another that also verifies.  */
static int
ed25519_s_canonical (const uint8_t s[ED_LEN])
{
  static const uint8_t l[ED_LEN] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
  };
  int i;

  for (i = ED_LEN - 1; i >= 0; i--)
    if (s[i] != l[i])
      return s[i] < l[i];
  return 0;
}

int
gf_key_verify (const gf_key *k, enum gf_sigalg alg, const uint8_t *data,
               size_t len, const uint8_t *sigblob, size_t siglen)
{
  gf_reader r;
  gf_slice name, sd;
  gcry_sexp_t d = NULL, sig = NULL;
  gcry_error_t err;
  uint8_t digest[64];
  enum gf_hash h = GF_HASH_SHA256;
  const char *hname = "sha256";
  int rc;

  if (k == NULL || (data == NULL && len > 0) || sigblob == NULL)
    return GF_ERR_INVAL;
  if (!alg_fits_key (k, alg))
    return GF_ERR_UNSUPPORTED;
  rc = gf_crypto_init ();
  if (rc != GF_OK)
    return rc;

  gf_reader_init (&r, sigblob, siglen);
  if (gf_rd_string (&r, &name) != GF_OK || gf_rd_string (&r, &sd) != GF_OK
      || gf_rd_finish (&r) != GF_OK
      || !gf_slice_equals (name, gf_sigalg_name (alg)))
    return GF_ERR_HOSTKEY;

  if (alg == GF_SIG_ED25519)
    {
      if (sd.len != 2 * ED_LEN || !ed25519_s_canonical (sd.data + ED_LEN))
        return GF_ERR_HOSTKEY;
      if (gcry_sexp_build (&sig, NULL, "(sig-val (eddsa (r %b)(s %b)))",
                           ED_LEN, sd.data, ED_LEN, sd.data + ED_LEN))
        return GF_ERR_CRYPTO;
      if (gcry_sexp_build (&d, NULL,
                           "(data (flags eddsa)(hash-algo sha512)(value %b))",
                           (int) len, data))
        {
          gcry_sexp_release (sig);
          return GF_ERR_CRYPTO;
        }
    }
  else
    {
      if (alg == GF_SIG_ECDSA_NISTP384 || alg == GF_SIG_RSA_SHA2_512)
        {
          h = alg == GF_SIG_RSA_SHA2_512 ? GF_HASH_SHA512 : GF_HASH_SHA384;
          hname = alg == GF_SIG_RSA_SHA2_512 ? "sha512" : "sha384";
        }
      if (alg == GF_SIG_RSA_SHA2_256 || alg == GF_SIG_RSA_SHA2_512)
        {
          gcry_mpi_t s;

          if (sd.len != (k->bits + 7) / 8)
            return GF_ERR_HOSTKEY;
          s = mpi_from (sd.data, sd.len);
          if (s == NULL)
            return GF_ERR_NOMEM;
          err = gcry_sexp_build (&sig, NULL, "(sig-val (rsa (s %m)))", s);
          gcry_mpi_release (s);
        }
      else
        {
          gf_reader sr;
          gf_slice rs, ss;
          gcry_mpi_t rm, sm;

          gf_reader_init (&sr, sd.data, sd.len);
          if (gf_rd_mpint (&sr, &rs) != GF_OK || gf_rd_mpint (&sr, &ss) != GF_OK
              || gf_rd_finish (&sr) != GF_OK || rs.len == 0 || ss.len == 0)
            return GF_ERR_HOSTKEY;
          rm = mpi_from (rs.data, rs.len);
          sm = mpi_from (ss.data, ss.len);
          if (rm == NULL || sm == NULL)
            err = GPG_ERR_ENOMEM;
          else
            err = gcry_sexp_build (&sig, NULL,
                                   "(sig-val (ecdsa (r %m)(s %m)))", rm, sm);
          gcry_mpi_release (rm);
          gcry_mpi_release (sm);
        }
      if (err)
        return GF_ERR_CRYPTO;
      rc = gf_hash_compute (h, data, len, digest, gf_hash_size (h));
      if (rc != GF_OK)
        {
          gcry_sexp_release (sig);
          return rc;
        }
      err = gcry_sexp_build (&d, NULL,
                             alg == GF_SIG_RSA_SHA2_256
                             || alg == GF_SIG_RSA_SHA2_512
                             ? "(data (flags pkcs1)(hash %s %b))"
                             : "(data (flags rfc6979)(hash %s %b))",
                             hname, (int) gf_hash_size (h), digest);
      if (err)
        {
          gcry_sexp_release (sig);
          return GF_ERR_CRYPTO;
        }
    }
  err = gcry_pk_verify (sig, d, k->pub);
  gcry_sexp_release (sig);
  gcry_sexp_release (d);
  return err ? GF_ERR_HOSTKEY : GF_OK;
}

/* ------------------------------------------------------------------ */
/* Fingerprints and the OpenSSH private key format                    */
/* ------------------------------------------------------------------ */

static const char b64chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encode; PAD nonzero for '=' padding.  Returns the length written.  */
static size_t
b64_encode (const uint8_t *in, size_t n, char *out, int pad)
{
  size_t i, o = 0;

  for (i = 0; i + 2 < n; i += 3)
    {
      uint32_t v = (uint32_t) in[i] << 16 | in[i + 1] << 8 | in[i + 2];

      out[o++] = b64chars[v >> 18];
      out[o++] = b64chars[(v >> 12) & 63];
      out[o++] = b64chars[(v >> 6) & 63];
      out[o++] = b64chars[v & 63];
    }
  if (i < n)
    {
      uint32_t v = (uint32_t) in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0);

      out[o++] = b64chars[v >> 18];
      out[o++] = b64chars[(v >> 12) & 63];
      if (i + 1 < n)
        out[o++] = b64chars[(v >> 6) & 63];
      if (pad)
        {
          if (i + 1 >= n)
            out[o++] = '=';
          out[o++] = '=';
        }
    }
  return o;
}

/* Decode base64 text, ignoring whitespace.  Returns bytes or -1.  */
static long
b64_decode (const char *in, size_t n, uint8_t *out, size_t cap)
{
  uint32_t acc = 0;
  int bits = 0;
  size_t o = 0, i;
  int seen_pad = 0;

  for (i = 0; i < n; i++)
    {
      const char *p;
      char c = in[i];

      if (c == '\n' || c == '\r' || c == ' ' || c == '\t')
        continue;
      if (c == '=')
        {
          seen_pad = 1;
          continue;
        }
      p = c ? strchr (b64chars, c) : NULL;
      if (p == NULL || seen_pad)
        return -1;
      acc = acc << 6 | (uint32_t) (p - b64chars);
      bits += 6;
      if (bits >= 8)
        {
          bits -= 8;
          if (o >= cap)
            return -1;
          out[o++] = (uint8_t) (acc >> bits);
        }
    }
  return (long) o;
}

int
gf_key_fingerprint (const gf_key *k, char *out, size_t cap)
{
  uint8_t h[32];
  int rc;

  if (cap < 51)
    return GF_ERR_BUFSIZE;
  rc = gf_hash_compute (GF_HASH_SHA256, k->blob, k->bloblen, h, sizeof h);
  if (rc != GF_OK)
    return rc;
  memcpy (out, "SHA256:", 7);
  out[7 + b64_encode (h, sizeof h, out + 7, 0)] = '\0';
  return GF_OK;
}

#define PEM_BEGIN "-----BEGIN OPENSSH PRIVATE KEY-----"
#define PEM_END "-----END OPENSSH PRIVATE KEY-----"
#define MAGIC "openssh-key-v1"

/* The first occurrence of NEEDLE (N bytes) in the HAY (LEN bytes).  */
static const char *
find (const char *hay, size_t len, const char *needle, size_t n)
{
  size_t i;

  for (i = 0; i + n <= len; i++)
    if (memcmp (hay + i, needle, n) == 0)
      return hay + i;
  return NULL;
}

/* Build the private sexp for a key whose parts have been read.  */
static int
import_private (gf_key *k, const uint8_t *q, size_t qlen, gcry_mpi_t d,
                const uint8_t *seed, gcry_mpi_t n, gcry_mpi_t e, gcry_mpi_t p,
                gcry_mpi_t qq)
{
  gcry_error_t err;
  size_t ti = type_index (k->type);

  if (k->type == GF_KEY_ED25519)
    err = gcry_sexp_build (&k->priv, NULL,
                           "(private-key (ecc (curve Ed25519)(flags eddsa)"
                           "(q %b)(d %b)))", (int) qlen, q, ED_LEN, seed);
  else if (k->type == GF_KEY_RSA)
    {
      gcry_mpi_t u = gcry_mpi_new (0), lo = p, hi = qq;

      /* libgcrypt wants p < q and u = p^-1 mod q.  */
      if (gcry_mpi_cmp (p, qq) > 0)
        {
          lo = qq;
          hi = p;
        }
      if (!gcry_mpi_invm (u, lo, hi))
        {
          gcry_mpi_release (u);
          return GF_ERR_ENCODING;
        }
      err = gcry_sexp_build (&k->priv, NULL,
                             "(private-key (rsa (n %m)(e %m)(d %m)(p %m)"
                             "(q %m)(u %m)))", n, e, d, lo, hi, u);
      gcry_mpi_release (u);
    }
  else
    err = gcry_sexp_build (&k->priv, NULL,
                           "(private-key (ecc (curve %s)(q %b)(d %m)))",
                           types[ti].curve, (int) qlen, q, d);
  if (err)
    return GF_ERR_CRYPTO;
  if (k->type != GF_KEY_ED25519 && gcry_pk_testkey (k->priv))
    return GF_ERR_ENCODING;
  return GF_OK;
}

/* A self test that the private part belongs to the public part, for the
   types whose import does not check it.  */
static int
selftest (const gf_key *k)
{
  static const uint8_t msg[] = "foxtrot key check";
  uint8_t sig[GF_SIG_MAX];
  size_t n, na;
  const enum gf_sigalg *algs = gf_key_sigalgs (k, &na);

  if (gf_key_sign (k, algs[0], msg, sizeof msg, sig, sizeof sig, &n) != GF_OK)
    return GF_ERR_ENCODING;
  return gf_key_verify (k, algs[0], msg, sizeof msg, sig, n) == GF_OK
    ? GF_OK : GF_ERR_ENCODING;
}

int
gf_key_from_openssh_private (gf_key **out, const char *text, size_t len)
{
  const char *b, *e;
  uint8_t *der = NULL;
  long dn;
  gf_reader r, pr, kr;
  gf_slice s, cipher, kdf, kdfopts, pubblob, priv, ktype;
  uint32_t nkeys, c1, c2;
  gf_key *k = NULL, *chk = NULL;
  int rc = GF_ERR_ENCODING;
  size_t ti;

  if (out == NULL || text == NULL)
    return GF_ERR_INVAL;
  rc = gf_crypto_init ();
  if (rc != GF_OK)
    return rc;
  rc = GF_ERR_ENCODING;
  b = find (text, len, PEM_BEGIN, sizeof PEM_BEGIN - 1);
  if (b == NULL)
    return rc;
  b += sizeof PEM_BEGIN - 1;
  e = find (b, len - (size_t) (b - text), PEM_END, sizeof PEM_END - 1);
  if (e == NULL)
    return rc;
  der = malloc ((size_t) (e - b) + 1);
  if (der == NULL)
    return GF_ERR_NOMEM;
  dn = b64_decode (b, (size_t) (e - b), der, (size_t) (e - b));
  if (dn < (long) sizeof MAGIC)
    goto done;
  if (memcmp (der, MAGIC, sizeof MAGIC) != 0)	/* Includes the NUL.  */
    goto done;
  gf_reader_init (&r, der + sizeof MAGIC, (size_t) dn - sizeof MAGIC);
  if (gf_rd_string (&r, &cipher) != GF_OK || gf_rd_string (&r, &kdf) != GF_OK
      || gf_rd_string (&r, &kdfopts) != GF_OK || gf_rd_u32 (&r, &nkeys) != GF_OK
      || gf_rd_string (&r, &pubblob) != GF_OK || gf_rd_string (&r, &priv) != GF_OK
      || gf_rd_finish (&r) != GF_OK)
    goto done;
  if (!gf_slice_equals (cipher, "none") || !gf_slice_equals (kdf, "none"))
    {
      rc = GF_ERR_UNSUPPORTED;
      goto done;
    }
  if (nkeys != 1)
    {
      rc = GF_ERR_UNSUPPORTED;
      goto done;
    }
  rc = gf_key_from_blob (&chk, pubblob.data, pubblob.len);
  if (rc != GF_OK)
    goto done;
  rc = GF_ERR_ENCODING;

  gf_reader_init (&pr, priv.data, priv.len);
  if (gf_rd_u32 (&pr, &c1) != GF_OK || gf_rd_u32 (&pr, &c2) != GF_OK
      || c1 != c2 || gf_rd_string (&pr, &ktype) != GF_OK)
    goto done;
  if (!gf_slice_equals (ktype, type_name (chk->type)))
    goto done;
  ti = type_index (chk->type);
  k = calloc (1, sizeof *k);
  if (k == NULL)
    {
      rc = GF_ERR_NOMEM;
      goto done;
    }
  k->type = chk->type;
  k->bits = chk->bits;
  k->blob = malloc (chk->bloblen);
  if (k->blob == NULL)
    {
      rc = GF_ERR_NOMEM;
      goto done;
    }
  memcpy (k->blob, chk->blob, chk->bloblen);
  k->bloblen = chk->bloblen;
  k->pub = chk->pub;
  chk->pub = NULL;
  kr = pr;

  if (k->type == GF_KEY_ED25519)
    {
      gf_slice pk, sk;

      if (gf_rd_string (&kr, &pk) != GF_OK || gf_rd_string (&kr, &sk) != GF_OK
          || pk.len != ED_LEN || sk.len != 2 * ED_LEN
          || memcmp (sk.data + ED_LEN, pk.data, ED_LEN) != 0)
        goto done;
      rc = import_private (k, pk.data, pk.len, NULL, sk.data, NULL, NULL,
                           NULL, NULL);
    }
  else if (k->type == GF_KEY_RSA)
    {
      gf_slice sn, se, sd, si, sp, sq;
      gcry_mpi_t n, ee, d, p, q;

      if (gf_rd_mpint (&kr, &sn) != GF_OK || gf_rd_mpint (&kr, &se) != GF_OK
          || gf_rd_mpint (&kr, &sd) != GF_OK || gf_rd_mpint (&kr, &si) != GF_OK
          || gf_rd_mpint (&kr, &sp) != GF_OK || gf_rd_mpint (&kr, &sq) != GF_OK)
        goto done;
      n = mpi_from (sn.data, sn.len);
      ee = mpi_from (se.data, se.len);
      d = mpi_from (sd.data, sd.len);
      p = mpi_from (sp.data, sp.len);
      q = mpi_from (sq.data, sq.len);
      if (n && ee && d && p && q)
        rc = import_private (k, NULL, 0, d, NULL, n, ee, p, q);
      else
        rc = GF_ERR_NOMEM;
      gcry_mpi_release (n);
      gcry_mpi_release (ee);
      gcry_mpi_release (d);
      gcry_mpi_release (p);
      gcry_mpi_release (q);
    }
  else
    {
      gf_slice id, qs, ds;
      gcry_mpi_t d;

      if (gf_rd_string (&kr, &id) != GF_OK || gf_rd_string (&kr, &qs) != GF_OK
          || gf_rd_mpint (&kr, &ds) != GF_OK
          || !gf_slice_equals (id, types[ti].curve_id))
        goto done;
      d = mpi_from (ds.data, ds.len);
      if (d == NULL)
        rc = GF_ERR_NOMEM;
      else
        rc = import_private (k, qs.data, qs.len, d, NULL, NULL, NULL, NULL,
                             NULL);
      gcry_mpi_release (d);
    }
  if (rc != GF_OK)
    goto done;
  /* The comment and the padding (1, 2, 3, ...) follow.  */
  if (gf_rd_string (&kr, &s) != GF_OK)
    {
      rc = GF_ERR_ENCODING;
      goto done;
    }
  {
    uint8_t want = 1;

    while (gf_rd_remaining (&kr) > 0)
      {
        uint8_t pb;

        if (gf_rd_u8 (&kr, &pb) != GF_OK || pb != want++)
          {
            rc = GF_ERR_ENCODING;
            goto done;
          }
      }
  }
  rc = selftest (k);
  if (rc == GF_OK)
    {
      *out = k;
      k = NULL;
    }

done:
  if (der != NULL)
    {
      gf_wipe (der, (size_t) (e - b) + 1);
      free (der);
    }
  gf_key_free (chk);
  gf_key_free (k);
  return rc;
}

int
gf_key_to_openssh_private (const gf_key *k, char *out, size_t cap,
                           size_t *outlen)
{
  uint8_t *buf;
  size_t bufcap = 8192 + k->bloblen, privstart, mark, plen, i, o = 0, dl;
  gf_writer w;
  uint32_t check;
  size_t ti;
  int rc = GF_OK;
  char *text;

  if (k == NULL || out == NULL || outlen == NULL || k->priv == NULL)
    return GF_ERR_INVAL;
  ti = type_index (k->type);
  buf = malloc (bufcap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, bufcap);
  gf_wr_bytes (&w, MAGIC, sizeof MAGIC);
  gf_wr_cstring (&w, "none");
  gf_wr_cstring (&w, "none");
  gf_wr_cstring (&w, "");
  gf_wr_u32 (&w, 1);
  gf_wr_string (&w, k->blob, k->bloblen);
  mark = gf_wr_string_begin (&w);
  privstart = w.len;
  if (gf_random (&check, sizeof check) != GF_OK)
    check = 0x666f7874;
  gf_wr_u32 (&w, check);
  gf_wr_u32 (&w, check);
  gf_wr_cstring (&w, types[ti].name);
  if (k->type == GF_KEY_ED25519)
    {
      size_t ql, dlen;
      uint8_t *q = sexp_bytes (k->priv, "q", &ql);
      uint8_t *d = sexp_bytes (k->priv, "d", &dlen);

      if (q == NULL || d == NULL || ql != ED_LEN || dlen != ED_LEN)
        rc = GF_ERR_CRYPTO;
      else
        {
          gf_wr_string (&w, q, ql);
          gf_wr_u32 (&w, 2 * ED_LEN);
          gf_wr_bytes (&w, d, dlen);
          gf_wr_bytes (&w, q, ql);
        }
      free (q);
      if (d != NULL)
        {
          gf_wipe (d, dlen);
          free (d);
        }
    }
  else if (k->type == GF_KEY_RSA)
    {
      gcry_mpi_t n = sexp_mpi (k->priv, "n"), e = sexp_mpi (k->priv, "e");
      gcry_mpi_t d = sexp_mpi (k->priv, "d"), p = sexp_mpi (k->priv, "p");
      gcry_mpi_t q = sexp_mpi (k->priv, "q"), iq = gcry_mpi_new (0);
      gcry_mpi_t parts[5];
      size_t j;

      parts[0] = n;
      parts[1] = e;
      parts[2] = d;
      parts[3] = iq;
      parts[4] = p;
      if (!(n && e && d && p && q) || !gcry_mpi_invm (iq, q, p))
        rc = GF_ERR_CRYPTO;
      else
        {
          for (j = 0; j < 5; j++)
            {
              size_t l;
              uint8_t *b = mpi_bytes (parts[j], 0, &l);

              if (b == NULL)
                rc = GF_ERR_NOMEM;
              else
                gf_wr_mpint (&w, b, l);
              if (b != NULL)
                {
                  gf_wipe (b, l);
                  free (b);
                }
            }
          {
            size_t l;
            uint8_t *b = mpi_bytes (q, 0, &l);

            if (b == NULL)
              rc = GF_ERR_NOMEM;
            else
              {
                gf_wr_mpint (&w, b, l);
                gf_wipe (b, l);
                free (b);
              }
          }
        }
      gcry_mpi_release (n);
      gcry_mpi_release (e);
      gcry_mpi_release (d);
      gcry_mpi_release (p);
      gcry_mpi_release (q);
      gcry_mpi_release (iq);
    }
  else
    {
      size_t ql, dl2;
      uint8_t *q = sexp_bytes (k->priv, "q", &ql);
      gcry_mpi_t d = sexp_mpi (k->priv, "d");
      uint8_t *db = d ? mpi_bytes (d, 0, &dl2) : NULL;

      if (q == NULL || db == NULL)
        rc = GF_ERR_CRYPTO;
      else
        {
          gf_wr_cstring (&w, types[ti].curve_id);
          gf_wr_string (&w, q, ql);
          gf_wr_mpint (&w, db, dl2);
        }
      free (q);
      if (db != NULL)
        {
          gf_wipe (db, dl2);
          free (db);
        }
      gcry_mpi_release (d);
    }
  gf_wr_cstring (&w, "");		/* Comment.  */
  plen = w.len - privstart;
  for (i = 1; plen % 8 != 0; i++, plen++)
    gf_wr_u8 (&w, (uint8_t) i);
  gf_wr_string_end (&w, mark);
  if (rc == GF_OK && gf_wr_status (&w) != GF_OK)
    rc = GF_ERR_BUFSIZE;
  if (rc != GF_OK)
    {
      gf_wipe (buf, bufcap);
      free (buf);
      return rc;
    }
  dl = w.len;

  /* Base64 text, wrapped at 70 columns, between the markers.  */
  {
    size_t encmax = (dl + 2) / 3 * 4 + 4, el;
    char *enc = malloc (encmax);
    size_t c;

    text = malloc (encmax + encmax / 70 + 2 + 2 * sizeof PEM_END + 8);
    if (enc == NULL || text == NULL)
      {
        free (enc);
        free (text);
        gf_wipe (buf, bufcap);
        free (buf);
        return GF_ERR_NOMEM;
      }
    el = b64_encode (buf, dl, enc, 1);
    memcpy (text, PEM_BEGIN "\n", sizeof PEM_BEGIN);
    o = sizeof PEM_BEGIN;
    for (c = 0; c < el; c += 70)
      {
        size_t n = el - c < 70 ? el - c : 70;

        memcpy (text + o, enc + c, n);
        o += n;
        text[o++] = '\n';
      }
    memcpy (text + o, PEM_END "\n", sizeof PEM_END);
    o += sizeof PEM_END;
    gf_wipe (enc, encmax);
    free (enc);
  }
  gf_wipe (buf, bufcap);
  free (buf);
  if (o + 1 > cap)
    {
      free (text);
      return GF_ERR_BUFSIZE;
    }
  memcpy (out, text, o);
  out[o] = '\0';
  *outlen = o;
  free (text);
  return GF_OK;
}
