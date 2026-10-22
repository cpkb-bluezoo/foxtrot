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
#include "keyint.h"

#define ED_LEN 32

static const struct
{
  enum gf_keytype type;
  const char *name;		/* Key blob type name.  */
  const char *cert_name;	/* The name of its certificate.  */
  const char *sk_name;		/* As a security key, or NULL.  */
  const char *sk_cert_name;
  const char *curve_id;		/* RFC 5656 identifier, ECDSA only.  */
  const char *curve;		/* libgcrypt curve name.  */
  size_t point_len;
  unsigned bits;
} types[] = {
  { GF_KEY_ED25519, "ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com",
    "sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com",
    NULL, "Ed25519", ED_LEN, 256 },
  { GF_KEY_ECDSA_P256, "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "nistp256", "NIST P-256", 65, 256 },
  { GF_KEY_ECDSA_P384, "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com", NULL, NULL,
    "nistp384", "NIST P-384", 97, 384 },
  { GF_KEY_RSA, "ssh-rsa", "ssh-rsa-cert-v01@openssh.com", NULL, NULL,
    NULL, NULL, 0, 0 }
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
  gfi_cert_free (k->cert);
  gfi_x509_free (k->x509);
  free (k->blob);
  free (k->plain);
  free (k->app);
  if (k->handle != NULL)
    gf_wipe (k->handle, k->handlelen);
  free (k->handle);
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
  size_t ti = type_index (k->type);

  if (k->x509)
    return k->type == GF_KEY_RSA ? "x509v3-rsa2048-sha256"
      : k->type == GF_KEY_ECDSA_P256 ? "x509v3-ecdsa-sha2-nistp256"
      : "x509v3-ecdsa-sha2-nistp384";
  if (k->app)
    return k->cert ? types[ti].sk_cert_name : types[ti].sk_name;
  return k->cert ? types[ti].cert_name : types[ti].name;
}

int
gf_key_is_security_key (const gf_key *k)
{
  return k->app != NULL;
}

const uint8_t *
gf_key_application (const gf_key *k, size_t *len)
{
  if (k->app == NULL)
    return NULL;
  *len = k->applen;
  return k->app;
}

/* A security key's key handle is a credential ID: the token needs it to sign
   and it is not secret, but it is wiped on free as private key files are.  */
static int
set_handle (gf_key *k, uint8_t flags, const uint8_t *h, size_t len)
{
  uint8_t *copy;

  if (len == 0 || len > GF_SK_HANDLE_MAX)
    return GF_ERR_RANGE;
  copy = malloc (len);
  if (copy == NULL)
    return GF_ERR_NOMEM;
  memcpy (copy, h, len);
  if (k->handle != NULL)
    gf_wipe (k->handle, k->handlelen);
  free (k->handle);
  k->handle = copy;
  k->handlelen = len;
  k->sk_flags = flags;
  return GF_OK;
}

int
gf_key_sk_attach_handle (gf_key *k, uint8_t flags, const uint8_t *h, size_t len)
{
  if (k == NULL || h == NULL)
    return GF_ERR_INVAL;
  if (k->app == NULL)
    return GF_ERR_UNSUPPORTED;
  return set_handle (k, flags, h, len);
}

const uint8_t *
gf_key_sk_handle (const gf_key *k, size_t *len)
{
  if (k->handle == NULL)
    return NULL;
  *len = k->handlelen;
  return k->handle;
}

uint8_t
gf_key_sk_flags (const gf_key *k)
{
  return k->sk_flags;
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
  static const enum gf_sigalg ed_c[] = { GF_SIG_ED25519_CERT };
  static const enum gf_sigalg p256_c[] = { GF_SIG_ECDSA_NISTP256_CERT };
  static const enum gf_sigalg p384_c[] = { GF_SIG_ECDSA_NISTP384_CERT };
  static const enum gf_sigalg rsa_c[] = { GF_SIG_RSA_SHA2_512_CERT,
                                          GF_SIG_RSA_SHA2_256_CERT };
  static const enum gf_sigalg sk_ed[] = { GF_SIG_SK_ED25519 };
  static const enum gf_sigalg sk_p256[] = { GF_SIG_SK_ECDSA_NISTP256 };
  static const enum gf_sigalg sk_ed_c[] = { GF_SIG_SK_ED25519_CERT };
  static const enum gf_sigalg sk_p256_c[] = { GF_SIG_SK_ECDSA_NISTP256_CERT };
  static const enum gf_sigalg x_p256[] = { GF_SIG_X509_ECDSA_NISTP256 };
  static const enum gf_sigalg x_p384[] = { GF_SIG_X509_ECDSA_NISTP384 };
  static const enum gf_sigalg x_rsa[] = { GF_SIG_X509_RSA2048_SHA256 };
  int c = k->cert != NULL;

  if (k->x509)
    {
      *n = 1;
      return k->type == GF_KEY_RSA ? x_rsa
        : k->type == GF_KEY_ECDSA_P256 ? x_p256 : x_p384;
    }
  switch (k->type)
    {
    case GF_KEY_ED25519:
      *n = 1;
      return k->app ? (c ? sk_ed_c : sk_ed) : c ? ed_c : ed;
    case GF_KEY_ECDSA_P256:
      *n = 1;
      return k->app ? (c ? sk_p256_c : sk_p256) : c ? p256_c : p256;
    case GF_KEY_ECDSA_P384:
      *n = 1;
      return c ? p384_c : p384;
    default:
      *n = 2;
      return c ? rsa_c : rsa;
    }
}

int
gf_key_is_certificate (const gf_key *k)
{
  return k->cert != NULL;
}

const uint8_t *
gf_key_plain_blob (const gf_key *k, size_t *len)
{
  if (k->plain)
    {
      *len = k->plainlen;
      return k->plain;
    }
  *len = k->bloblen;
  return k->blob;
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
  cap = 64 + qlen + nl + el + k->applen;
  buf = malloc (cap);
  if (buf == NULL)
    {
      free (nb);
      free (eb);
      return GF_ERR_NOMEM;
    }
  gf_writer_init (&w, buf, cap);
  gf_wr_cstring (&w, k->app ? types[ti].sk_name : types[ti].name);
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
  if (k->app)
    gf_wr_string (&w, k->app, k->applen);
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

/* The application of a security key, the last field of its blob: it names
   the relying party the token signs for, and OpenSSH's own keys have
   "ssh:" at the front of it.  A key whose application is a web site's is a
   credential for that site and not one to log in with.  */
#define GF_SK_APP_MAX 255

static int
read_application (gf_key *k, gf_reader *r)
{
  gf_slice a;

  if (gf_rd_string (r, &a) != GF_OK || a.len < 4 || a.len > GF_SK_APP_MAX
      || memcmp (a.data, "ssh:", 4) != 0 || memchr (a.data, '\0', a.len))
    return GF_ERR_ENCODING;
  k->app = malloc (a.len);
  if (k->app == NULL)
    return GF_ERR_NOMEM;
  memcpy (k->app, a.data, a.len);
  k->applen = a.len;
  return GF_OK;
}

int
gf_key_from_blob (gf_key **out, const uint8_t *blob, size_t len)
{
  gf_reader r;
  gf_slice name, a, b;
  gf_key *k;
  size_t ti;
  int rc = GF_ERR_UNSUPPORTED, sk = 0;

  if (out == NULL || blob == NULL)
    return GF_ERR_INVAL;
  rc = gf_crypto_init ();
  if (rc != GF_OK)
    return rc;
  gf_reader_init (&r, blob, len);
  if (gf_rd_string (&r, &name) != GF_OK)
    return GF_ERR_ENCODING;
  for (ti = 0; ti < sizeof types / sizeof types[0]; ti++)
    {
      if (gf_slice_equals (name, types[ti].name))
        break;
      if (types[ti].sk_name && gf_slice_equals (name, types[ti].sk_name))
        {
          sk = 1;
          break;
        }
    }
  if (ti == sizeof types / sizeof types[0])
    {
      for (ti = 0; ti < sizeof types / sizeof types[0]; ti++)
        if (gf_slice_equals (name, types[ti].cert_name)
            || (types[ti].sk_cert_name
                && gf_slice_equals (name, types[ti].sk_cert_name)))
          return gfi_cert_parse (out, blob, len, name);
      if (gf_sigalg_is_x509 (gf_sigalg_from_name ((const char *) name.data,
                                                  name.len)))
        return gfi_x509_parse (out, blob, len, name);
      return GF_ERR_UNSUPPORTED;
    }

  k = calloc (1, sizeof *k);
  if (k == NULL)
    return GF_ERR_NOMEM;
  k->type = types[ti].type;
  rc = GF_ERR_ENCODING;

  if (k->type == GF_KEY_ED25519)
    {
      if (gf_rd_string (&r, &a) != GF_OK || a.len != ED_LEN)
        goto fail;
      if (sk && (rc = read_application (k, &r)) != GF_OK)
        goto fail;
      rc = GF_ERR_ENCODING;
      if (gf_rd_finish (&r) != GF_OK)
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
      if (gf_rd_string (&r, &a) != GF_OK || gf_rd_string (&r, &b) != GF_OK)
        goto fail;
      if (sk && (rc = read_application (k, &r)) != GF_OK)
        goto fail;
      rc = GF_ERR_ENCODING;
      if (gf_rd_finish (&r) != GF_OK)
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

  /* A certificate signs with the certificate algorithms only, and a plain
     key with the plain ones.  */
  return kt != NULL && gf_sigalg_is_cert (alg) == (k->cert != NULL)
    && strcmp (kt, gf_key_type_name (k)) == 0;
}

/* The algorithm whose arithmetic an algorithm uses: an X.509 chain signs as
   the key in its end certificate does, under the name RFC 6187 gives the
   signature (gf_sigalg_signature_name).  */
static enum gf_sigalg
crypto_alg (enum gf_sigalg alg)
{
  switch (alg)
    {
    case GF_SIG_X509_ECDSA_NISTP256:	return GF_SIG_ECDSA_NISTP256;
    case GF_SIG_X509_ECDSA_NISTP384:	return GF_SIG_ECDSA_NISTP384;
    case GF_SIG_X509_RSA2048_SHA256:	return GF_SIG_RSA_SHA2_256;
    default:				return alg;
    }
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
  const char *hname = "sha256", *signame;
  int rc;
  size_t mark;

  if (k == NULL || (data == NULL && len > 0) || out == NULL || outlen == NULL)
    return GF_ERR_INVAL;
  if (k->priv == NULL)
    return GF_ERR_INVAL;
  if (!alg_fits_key (k, alg) || gf_sigalg_is_user_only (alg))
    return GF_ERR_UNSUPPORTED;	/* A token signs security keys, not us.  */
  signame = gf_sigalg_signature_name (alg);
  alg = gf_sigalg_base (alg);	/* A certificate signs as its key does.  */
  alg = crypto_alg (alg);
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
  gf_wr_cstring (&w, signame);
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

/* The signature of any algorithm, security keys included (then FLAGS and
   COUNTER receive what the token signed, if not NULL).  */
static int
verify_impl (const gf_key *k, enum gf_sigalg alg, const uint8_t *data,
             size_t len, const uint8_t *sigblob, size_t siglen,
             uint8_t *flags_out, uint32_t *counter_out)
{
  gf_reader r;
  gf_slice name, sd;
  gcry_sexp_t d = NULL, sig = NULL;
  gcry_error_t err;
  uint8_t digest[64];
  uint8_t skdata[2 * 32 + 1 + 4];
  enum gf_hash h = GF_HASH_SHA256;
  const char *hname = "sha256", *signame;
  int rc, sk;
  uint8_t flags = 0;
  uint32_t counter = 0;

  if (k == NULL || (data == NULL && len > 0) || sigblob == NULL)
    return GF_ERR_INVAL;
  if (!alg_fits_key (k, alg))
    return GF_ERR_UNSUPPORTED;
  signame = gf_sigalg_signature_name (alg);
  alg = gf_sigalg_base (alg);
  sk = alg == GF_SIG_SK_ED25519 || alg == GF_SIG_SK_ECDSA_NISTP256;
  rc = gf_crypto_init ();
  if (rc != GF_OK)
    return rc;

  gf_reader_init (&r, sigblob, siglen);
  if (gf_rd_string (&r, &name) != GF_OK || gf_rd_string (&r, &sd) != GF_OK
      || (sk && (gf_rd_u8 (&r, &flags) != GF_OK
                 || gf_rd_u32 (&r, &counter) != GF_OK))
      || gf_rd_finish (&r) != GF_OK
      || !gf_slice_equals (name, signame))
    return GF_ERR_HOSTKEY;
  if (sk)
    {
      /* What the token signed (PROTOCOL.u2f), signed as its key's plain
         algorithm signs a message.  */
      rc = gf_hash_compute (GF_HASH_SHA256, k->app, k->applen, skdata, 32);
      if (rc == GF_OK)
        rc = gf_hash_compute (GF_HASH_SHA256, data, len, skdata + 37, 32);
      if (rc != GF_OK)
        return rc;
      skdata[32] = flags;
      skdata[33] = (uint8_t) (counter >> 24);
      skdata[34] = (uint8_t) (counter >> 16);
      skdata[35] = (uint8_t) (counter >> 8);
      skdata[36] = (uint8_t) counter;
      data = skdata;
      len = sizeof skdata;
      alg = alg == GF_SIG_SK_ED25519 ? GF_SIG_ED25519 : GF_SIG_ECDSA_NISTP256;
    }
  alg = crypto_alg (alg);

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
  if (err)
    return GF_ERR_HOSTKEY;
  if (flags_out)
    *flags_out = flags;
  if (counter_out)
    *counter_out = counter;
  return GF_OK;
}

int
gf_key_verify (const gf_key *k, enum gf_sigalg alg, const uint8_t *data,
               size_t len, const uint8_t *sigblob, size_t siglen)
{
  if (gf_sigalg_is_user_only (alg))
    return gf_key_verify_sk (k, alg, data, len, sigblob, siglen, NULL, NULL);
  return verify_impl (k, alg, data, len, sigblob, siglen, NULL, NULL);
}

int
gf_key_verify_sk (const gf_key *k, enum gf_sigalg alg, const uint8_t *data,
                  size_t len, const uint8_t *sigblob, size_t siglen,
                  uint8_t *flags, uint32_t *counter)
{
  uint8_t fl = 0;
  int rc;

  if (!gf_sigalg_is_user_only (alg))
    return GF_ERR_UNSUPPORTED;
  rc = verify_impl (k, alg, data, len, sigblob, siglen, &fl, counter);
  /* A signature the user did not touch the token for proves a token, not a
     person.  */
  if (rc == GF_OK && !(fl & GF_SK_USER_PRESENT))
    return GF_ERR_HOSTKEY;
  if (rc == GF_OK && flags)
    *flags = fl;
  return rc;
}

/* ---- A token's answer as a signature blob ---- */

/* A DER length, in the shortest form that holds it (X.690 section 10.1): a
   signature is under 128 bytes, so the one-byte long form is the most there
   can be, and indefinite lengths are not DER at all.  */
static int
der_length (const uint8_t **p, const uint8_t *end, size_t *len)
{
  if (*p == end)
    return -1;
  *len = *(*p)++;
  if (*len < 0x80)
    return 0;
  if (*len != 0x81 || *p == end)
    return -1;
  *len = *(*p)++;
  return *len < 0x80 ? -1 : 0;
}

/* A positive INTEGER of at most MAX bytes, with no unneeded leading zero.
   Its contents are what an SSH mpint holds, so they are returned as they
   are.  */
static int
der_integer (const uint8_t **p, const uint8_t *end, size_t max, gf_slice *v)
{
  size_t len;

  if (*p == end || *(*p)++ != 0x02 || der_length (p, end, &len) != 0
      || len == 0 || len > max || len > (size_t) (end - *p))
    return -1;
  v->data = *p;
  v->len = len;
  *p += len;
  if (v->data[0] & 0x80)			/* Negative.  */
    return -1;
  if (v->len == 1 ? v->data[0] == 0 : v->data[0] == 0 && !(v->data[1] & 0x80))
    return -1;					/* Zero, or not minimal.  */
  return 0;
}

/* ECDSA-Sig-Value (RFC 3279): SEQUENCE { INTEGER r, INTEGER s }, DER and
   nothing after it, as the mpint pair an SSH signature holds.  */
static int
der_to_mpints (const uint8_t *der, size_t len, size_t max, gf_writer *w)
{
  const uint8_t *p = der, *end = der + len;
  gf_slice r, s;
  size_t seq;

  if (p == end || *p++ != 0x30 || der_length (&p, end, &seq) != 0
      || seq != (size_t) (end - p)
      || der_integer (&p, end, max, &r) != 0
      || der_integer (&p, end, max, &s) != 0 || p != end)
    return GF_ERR_ENCODING;
  gf_wr_string (w, r.data, r.len);
  gf_wr_string (w, s.data, s.len);
  return GF_OK;
}

int
gf_sk_signature_pack (const gf_key *k, enum gf_sigalg alg, const uint8_t *raw,
                      size_t rawlen, uint8_t flags, uint32_t counter,
                      uint8_t *out, size_t cap, size_t *outlen)
{
  uint8_t sig[2 * (4 + 33)];
  gf_writer w, sw;
  size_t siglen;

  if (k == NULL || raw == NULL || out == NULL || outlen == NULL)
    return GF_ERR_INVAL;
  if (!gf_sigalg_is_user_only (alg) || !alg_fits_key (k, alg))
    return GF_ERR_UNSUPPORTED;
  alg = gf_sigalg_base (alg);
  if (alg == GF_SIG_SK_ED25519)
    {
      if (rawlen != 2 * ED_LEN)
        return GF_ERR_ENCODING;
      memcpy (sig, raw, rawlen);
      siglen = rawlen;
    }
  else
    {
      int rc;

      /* The integers of P-256 are 32 bytes, 33 with a zero in front.  */
      gf_writer_init (&sw, sig, sizeof sig);
      rc = der_to_mpints (raw, rawlen, 33, &sw);
      if (rc != GF_OK)
        return rc;
      siglen = sw.len;
    }
  gf_writer_init (&w, out, cap);
  gf_wr_cstring (&w, gf_sigalg_name (alg));
  gf_wr_string (&w, sig, siglen);
  gf_wr_u8 (&w, flags);
  gf_wr_u32 (&w, counter);
  if (gf_wr_status (&w) != GF_OK)
    return GF_ERR_BUFSIZE;
  *outlen = w.len;
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Fingerprints and the OpenSSH private key format                    */
/* ------------------------------------------------------------------ */

int
gf_key_fingerprint (const gf_key *k, char *out, size_t cap)
{
  uint8_t h[32];
  int rc;

  if (cap < 51)
    return GF_ERR_BUFSIZE;
  /* Like ssh-keygen -l, a certificate is known by the key it certifies, so
     that the same key has the same name with and without a certificate.  */
  if (k->plain != NULL)
    rc = gf_hash_compute (GF_HASH_SHA256, k->plain, k->plainlen, h, sizeof h);
  else
    rc = gf_hash_compute (GF_HASH_SHA256, k->blob, k->bloblen, h, sizeof h);
  if (rc != GF_OK)
    return rc;
  memcpy (out, "SHA256:", 7);
  out[7 + gfi_b64_encode (h, sizeof h, out + 7, 0)] = '\0';
  return GF_OK;
}

#define MAX_TEXT_KEY 65536

static int
is_blank (char c)
{
  return c == ' ' || c == '\t';
}

int
gf_key_from_text (gf_key **out, const char *text, size_t len, gf_slice *comment)
{
  size_t i = 0, t0, t1, b0, b1, c0, c1;
  uint8_t *blob;
  long n;
  gf_key *k = NULL;
  int rc;
  const char *name;

  if (out == NULL || text == NULL || len > MAX_TEXT_KEY)
    return GF_ERR_INVAL;
  if (comment != NULL)
    {
      comment->data = NULL;
      comment->len = 0;
    }
  while (i < len && is_blank (text[i]))
    i++;
  t0 = i;
  while (i < len && !is_blank (text[i]) && text[i] != '\n' && text[i] != '\r')
    i++;
  t1 = i;
  while (i < len && is_blank (text[i]))
    i++;
  b0 = i;
  while (i < len && !is_blank (text[i]) && text[i] != '\n' && text[i] != '\r')
    i++;
  b1 = i;
  if (t1 == t0 || b1 == b0)		/* No type, or no key after it.  */
    return GF_ERR_ENCODING;
  while (i < len && is_blank (text[i]))
    i++;
  c0 = i;
  while (i < len && text[i] != '\n' && text[i] != '\r')
    i++;
  c1 = i;
  while (c1 > c0 && is_blank (text[c1 - 1]))
    c1--;
  /* One line: at most a line end, then nothing.  */
  if (i < len && text[i] == '\r')
    i++;
  if (i < len && text[i] == '\n')
    i++;
  if (i != len || memchr (text, '\0', len) != NULL)
    return GF_ERR_ENCODING;

  blob = malloc ((b1 - b0) / 4 * 3 + 3);
  if (blob == NULL)
    return GF_ERR_NOMEM;
  n = gfi_b64_decode (text + b0, b1 - b0, blob, (b1 - b0) / 4 * 3 + 3, 1);
  if (n < 0)
    {
      free (blob);
      return GF_ERR_ENCODING;
    }
  rc = gf_key_from_blob (&k, blob, (size_t) n);
  free (blob);
  if (rc != GF_OK)
    return rc;
  /* The type in front must be the one inside, or the text lies about it.  */
  name = gf_key_type_name (k);
  if (strlen (name) != t1 - t0 || memcmp (name, text + t0, t1 - t0) != 0)
    {
      gf_key_free (k);
      return GF_ERR_ENCODING;
    }
  if (comment != NULL)
    {
      comment->data = (const uint8_t *) text + c0;
      comment->len = c1 - c0;
    }
  *out = k;
  return GF_OK;
}

int
gf_key_to_text (const gf_key *k, char *out, size_t cap, size_t *outlen)
{
  const char *name;
  size_t nl, need;

  if (k == NULL || out == NULL)
    return GF_ERR_INVAL;
  name = gf_key_type_name (k);
  nl = strlen (name);
  need = nl + 1 + (k->bloblen + 2) / 3 * 4 + 1;
  if (cap < need)
    return GF_ERR_BUFSIZE;
  memcpy (out, name, nl);
  out[nl] = ' ';
  nl += 1 + gfi_b64_encode (k->blob, k->bloblen, out + nl + 1, 1);
  out[nl] = '\0';
  if (outlen)
    *outlen = nl;
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
      gcry_mpi_t u, lo = p, hi = qq;

      /* The primes come from a file.  libgcrypt's modular inverse does not
         survive a zero modulus, and 1 or equal primes are no RSA key.  */
      if (gcry_mpi_cmp_ui (p, 1) <= 0 || gcry_mpi_cmp_ui (qq, 1) <= 0
          || gcry_mpi_cmp (p, qq) == 0)
        return GF_ERR_ENCODING;
      u = gcry_mpi_new (0);
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

/* ---- Encryption of private key files ---- */

#define KDF_MAX_OUT 48		/* The longest key and IV together.  */
#define KDF_MIN_SALT 8
#define KDF_MAX_SALT 64
#define KDF_DEFAULT_ROUNDS 16

struct file_cipher
{
  const char *name;
  int algo, mode;
  size_t keylen, ivlen, authlen, block;
};

static const struct file_cipher fciphers[] = {
  { "aes128-ctr", GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 16, 16, 0, 16 },
  { "aes192-ctr", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR, 24, 16, 0, 16 },
  { "aes256-ctr", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 32, 16, 0, 16 },
  { "aes128-gcm@openssh.com", GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
    16, 12, 16, 16 },
  { "aes256-gcm@openssh.com", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM,
    32, 12, 16, 16 }
};

static const struct file_cipher *
file_cipher (gf_slice name)
{
  size_t i;

  for (i = 0; i < sizeof fciphers / sizeof fciphers[0]; i++)
    if (gf_slice_equals (name, fciphers[i].name))
      return &fciphers[i];
  return NULL;
}

/* Encrypt or decrypt N bytes at P in place with the key and IV in KEYIV.
   A GCM tag is written to TAG_OUT when encrypting; when decrypting TAG_IN is
   checked, and GF_ERR_PASSPHRASE says it was not right.  */
static int
file_crypt (const struct file_cipher *fc, int encrypt, const uint8_t *keyiv,
            uint8_t *p, size_t n, uint8_t *tag_out, const uint8_t *tag_in)
{
  gcry_cipher_hd_t h;
  gcry_error_t err;
  int rc = GF_OK;

  if (gcry_cipher_open (&h, fc->algo, fc->mode, 0))
    return GF_ERR_CRYPTO;
  err = gcry_cipher_setkey (h, keyiv, fc->keylen);
  if (!err)
    err = fc->mode == GCRY_CIPHER_MODE_CTR
      ? gcry_cipher_setctr (h, keyiv + fc->keylen, fc->ivlen)
      : gcry_cipher_setiv (h, keyiv + fc->keylen, fc->ivlen);
  if (!err)
    err = encrypt ? gcry_cipher_encrypt (h, p, n, NULL, 0)
                  : gcry_cipher_decrypt (h, p, n, NULL, 0);
  if (!err && fc->authlen)
    {
      if (encrypt)
        err = gcry_cipher_gettag (h, tag_out, fc->authlen);
      else if (gcry_cipher_checktag (h, tag_in, fc->authlen))
        rc = GF_ERR_PASSPHRASE;
    }
  if (err)
    rc = GF_ERR_CRYPTO;
  gcry_cipher_close (h);
  return rc;
}

/* The key and IV for a file from the passphrase, by the application's KDF,
   in KEYIV.  KDFOPTS is the file's "string salt, uint32 rounds".  */
static int
file_derive (const struct file_cipher *fc, const char *pass,
             gf_bcrypt_pbkdf_fn kdf, void *kuser, const uint8_t *salt,
             size_t saltlen, uint32_t rounds, uint8_t *keyiv)
{
  if (saltlen < KDF_MIN_SALT || saltlen > KDF_MAX_SALT || rounds < 1
      || rounds > GF_KDF_MAX_ROUNDS)
    return GF_ERR_UNSUPPORTED;
  if (kdf (kuser, (const uint8_t *) pass, strlen (pass), salt, saltlen, rounds,
           keyiv, fc->keylen + fc->ivlen) != 0)
    return GF_ERR_HANDLER;
  return GF_OK;
}

/* The end of a private section: the comment, and the padding (1, 2, 3, ...)
   to the cipher's block size.  */
static int
comment_and_padding (gf_reader *r)
{
  gf_slice s;
  uint8_t want = 1;

  if (gf_rd_string (r, &s) != GF_OK)
    return GF_ERR_ENCODING;
  while (gf_rd_remaining (r) > 0)
    {
      uint8_t pb;

      if (gf_rd_u8 (r, &pb) != GF_OK || pb != want++)
        return GF_ERR_ENCODING;
    }
  return GF_OK;
}

static int
same_slice (gf_slice a, gf_slice b)
{
  return a.len == b.len && (a.len == 0 || memcmp (a.data, b.data, a.len) == 0);
}

/* The private section of a security key's file, after its type name
   (PROTOCOL.u2f): the public key again, the application, the flags, the key
   handle and a reserved string, then the comment and padding.  Each part
   must agree with K, the public key of the file, and the handle is
   attached to it.  There is no private key to import.  */
static int
sk_private_read (gf_key *k, gf_reader *r)
{
  gf_reader br;
  gf_slice name, a, b, handle, reserved;
  uint8_t flags;

  gf_reader_init (&br, k->blob, k->bloblen);
  if (gf_rd_string (&br, &name) != GF_OK)
    return GF_ERR_ENCODING;
  if (k->type != GF_KEY_ED25519		/* The curve name, then the point.  */
      && (gf_rd_string (&br, &a) != GF_OK || gf_rd_string (r, &b) != GF_OK
          || !same_slice (a, b)))
    return GF_ERR_ENCODING;
  if (gf_rd_string (&br, &a) != GF_OK || gf_rd_string (r, &b) != GF_OK
      || !same_slice (a, b))
    return GF_ERR_ENCODING;
  if (gf_rd_string (r, &a) != GF_OK || a.len != k->applen
      || memcmp (a.data, k->app, k->applen) != 0)
    return GF_ERR_ENCODING;
  if (gf_rd_u8 (r, &flags) != GF_OK || gf_rd_string (r, &handle) != GF_OK
      || handle.len == 0 || handle.len > GF_SK_HANDLE_MAX
      || gf_rd_string (r, &reserved) != GF_OK)
    return GF_ERR_ENCODING;
  if (comment_and_padding (r) != GF_OK)
    return GF_ERR_ENCODING;
  return set_handle (k, flags, handle.data, handle.len);
}

static int
private_read (gf_key **out, const char *text, size_t len, const char *pass,
              gf_bcrypt_pbkdf_fn kdf, void *kuser)
{
  const char *b, *e;
  uint8_t *der = NULL;
  long dn;
  gf_reader r, pr, kr;
  gf_slice cipher, kdfname, kdfopts, pubblob, priv, ktype, tag = { NULL, 0 };
  const struct file_cipher *fc = NULL;
  int decrypted = 0;
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
  dn = gfi_b64_decode (b, (size_t) (e - b), der, (size_t) (e - b), 0);
  if (dn < (long) sizeof MAGIC)
    goto done;
  if (memcmp (der, MAGIC, sizeof MAGIC) != 0)	/* Includes the NUL.  */
    goto done;
  gf_reader_init (&r, der + sizeof MAGIC, (size_t) dn - sizeof MAGIC);
  if (gf_rd_string (&r, &cipher) != GF_OK || gf_rd_string (&r, &kdfname) != GF_OK
      || gf_rd_string (&r, &kdfopts) != GF_OK || gf_rd_u32 (&r, &nkeys) != GF_OK
      || gf_rd_string (&r, &pubblob) != GF_OK || gf_rd_string (&r, &priv) != GF_OK)
    goto done;
  if (!gf_slice_equals (cipher, "none"))
    {
      /* A cipher that is not one of ours, or a key derivation that is not
         bcrypt, is refused, whoever asked.  */
      fc = file_cipher (cipher);
      if (fc == NULL || !gf_slice_equals (kdfname, "bcrypt"))
        {
          rc = GF_ERR_UNSUPPORTED;
          goto done;
        }
      if (fc->authlen && gf_rd_bytes (&r, fc->authlen, &tag) != GF_OK)
        goto done;
    }
  if (gf_rd_finish (&r) != GF_OK)
    goto done;
  if (fc == NULL && !gf_slice_equals (kdfname, "none"))
    {
      rc = GF_ERR_UNSUPPORTED;
      goto done;
    }
  if (fc != NULL)
    {
      gf_reader kr2;
      gf_slice salt;
      uint32_t rounds;
      uint8_t keyiv[KDF_MAX_OUT], *p = der + (size_t) (priv.data - der);

      if (pass == NULL || kdf == NULL)
        {
          rc = GF_ERR_UNSUPPORTED;
          goto done;
        }
      gf_reader_init (&kr2, kdfopts.data, kdfopts.len);
      if (gf_rd_string (&kr2, &salt) != GF_OK || gf_rd_u32 (&kr2, &rounds) != GF_OK
          || gf_rd_finish (&kr2) != GF_OK || priv.len == 0
          || priv.len % fc->block != 0)
        goto done;
      rc = file_derive (fc, pass, kdf, kuser, salt.data, salt.len, rounds, keyiv);
      if (rc == GF_OK)
        rc = file_crypt (fc, 0, keyiv, p, priv.len, NULL, tag.data);
      gf_wipe (keyiv, sizeof keyiv);
      if (rc != GF_OK)
        goto done;
      decrypted = 1;
      rc = GF_ERR_ENCODING;
    }
  if (nkeys != 1)
    {
      rc = GF_ERR_UNSUPPORTED;
      goto done;
    }
  rc = gf_key_from_blob (&chk, pubblob.data, pubblob.len);
  if (rc != GF_OK)
    goto done;
  if (chk->app != NULL && chk->cert != NULL)
    {
      /* ssh-keygen keeps a certificate in a file of its own.  */
      rc = GF_ERR_UNSUPPORTED;
      goto done;
    }
  rc = GF_ERR_ENCODING;

  gf_reader_init (&pr, priv.data, priv.len);
  if (gf_rd_u32 (&pr, &c1) != GF_OK || gf_rd_u32 (&pr, &c2) != GF_OK)
    goto done;
  if (c1 != c2)
    {
      /* Counter mode has no tag: the two check values are all that says
         the passphrase was right.  */
      rc = decrypted ? GF_ERR_PASSPHRASE : GF_ERR_ENCODING;
      goto done;
    }
  ti = type_index (chk->type);
  if (gf_rd_string (&pr, &ktype) != GF_OK
      || !gf_slice_equals (ktype, chk->app ? types[ti].sk_name
                           : type_name (chk->type)))
    goto done;
  if (chk->app != NULL)
    {
      /* A security key has no private key to keep: its file holds the
         handle the token needs to sign.  */
      rc = sk_private_read (chk, &pr);
      if (rc == GF_OK)
        {
          *out = chk;
          chk = NULL;
        }
      goto done;
    }
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
  rc = comment_and_padding (&kr);
  if (rc != GF_OK)
    goto done;
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
gf_key_from_openssh_private (gf_key **out, const char *text, size_t len)
{
  return private_read (out, text, len, NULL, NULL, NULL);
}

int
gf_key_from_openssh_private_encrypted (gf_key **out, const char *text,
                                       size_t len, const char *passphrase,
                                       gf_bcrypt_pbkdf_fn kdf, void *user)
{
  return private_read (out, text, len, passphrase, kdf, user);
}

static int
private_write (const gf_key *k, char *out, size_t cap, size_t *outlen,
               const char *pass, uint32_t rounds, gf_bcrypt_pbkdf_fn kdf,
               void *kuser)
{
  uint8_t *buf;
  size_t bufcap, privstart, mark, plen, i, o = 0, dl, block = 8;
  gf_writer w;
  uint32_t check;
  size_t ti;
  int rc = GF_OK;
  char *text;
  const struct file_cipher *fc = NULL;
  uint8_t salt[16];

  if (k == NULL || out == NULL || outlen == NULL || k->priv == NULL)
    return GF_ERR_INVAL;
  if (pass != NULL)
    {
      if (kdf == NULL)
        return GF_ERR_INVAL;
      if (rounds == 0)
        rounds = KDF_DEFAULT_ROUNDS;
      if (rounds > GF_KDF_MAX_ROUNDS)
        return GF_ERR_RANGE;
      fc = file_cipher ((gf_slice) { (const uint8_t *) "aes256-gcm@openssh.com", 22 });
      block = fc->block;
      rc = gf_random (salt, sizeof salt);
      if (rc != GF_OK)
        return rc;
    }
  bufcap = 8192 + k->bloblen;
  ti = type_index (k->type);
  buf = malloc (bufcap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, bufcap);
  gf_wr_bytes (&w, MAGIC, sizeof MAGIC);
  gf_wr_cstring (&w, fc ? fc->name : "none");
  gf_wr_cstring (&w, fc ? "bcrypt" : "none");
  if (fc)
    {
      size_t km = gf_wr_string_begin (&w);

      gf_wr_string (&w, salt, sizeof salt);
      gf_wr_u32 (&w, rounds);
      gf_wr_string_end (&w, km);
    }
  else
    gf_wr_cstring (&w, "");
  gf_wr_u32 (&w, 1);
  {
    size_t pl;
    const uint8_t *pb = gf_key_plain_blob (k, &pl);

    gf_wr_string (&w, pb, pl);
  }
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
  for (i = 1; plen % block != 0; i++, plen++)
    gf_wr_u8 (&w, (uint8_t) i);
  gf_wr_string_end (&w, mark);
  if (rc == GF_OK && gf_wr_status (&w) != GF_OK)
    rc = GF_ERR_BUFSIZE;
  if (rc == GF_OK && fc)
    {
      uint8_t keyiv[KDF_MAX_OUT], tag[16];

      rc = file_derive (fc, pass, kdf, kuser, salt, sizeof salt, rounds, keyiv);
      if (rc == GF_OK)
        rc = file_crypt (fc, 1, keyiv, buf + privstart, plen, tag, NULL);
      gf_wipe (keyiv, sizeof keyiv);
      if (rc == GF_OK)
        {
          gf_wr_bytes (&w, tag, sizeof tag);
          if (gf_wr_status (&w) != GF_OK)
            rc = GF_ERR_BUFSIZE;
        }
    }
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
    el = gfi_b64_encode (buf, dl, enc, 1);
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

int
gf_key_to_openssh_private (const gf_key *k, char *out, size_t cap,
                           size_t *outlen)
{
  return private_write (k, out, cap, outlen, NULL, 0, NULL, NULL);
}

int
gf_key_to_openssh_private_encrypted (const gf_key *k, char *out, size_t cap,
                                     size_t *outlen, const char *passphrase,
                                     uint32_t rounds, gf_bcrypt_pbkdf_fn kdf,
                                     void *user)
{
  if (passphrase == NULL)
    return GF_ERR_INVAL;
  return private_write (k, out, cap, outlen, passphrase, rounds, kdf, user);
}

/* ---- For the other file formats (keyfmt.c) ---- */

gcry_mpi_t
gfi_mpi_from (const uint8_t *data, size_t len)
{
  return mpi_from (data, len);
}

int
gfi_key_attach_private (gf_key *k, const uint8_t *q, size_t qlen, gcry_mpi_t d,
                        const uint8_t *seed, gcry_mpi_t n, gcry_mpi_t e,
                        gcry_mpi_t p, gcry_mpi_t qq)
{
  int rc;

  if (k == NULL || k->priv != NULL || k->cert != NULL || k->x509 != NULL)
    return GF_ERR_INVAL;
  rc = import_private (k, q, qlen, d, seed, n, e, p, qq);
  /* That the private part belongs to the public one is checked for every
     type, whatever the file said.  */
  if (rc == GF_OK)
    rc = selftest (k);
  if (rc != GF_OK)
    {
      gcry_sexp_release (k->priv);
      k->priv = NULL;
    }
  return rc;
}
