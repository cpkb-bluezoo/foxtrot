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
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>
#include <foxtrot/keyfmt.h>

#include "internal.h"
#include "keyint.h"

#define MAX_TEXT (256 * 1024)	/* The longest file read.  */
#define MAX_DER (64 * 1024)
#define PBKDF2_MAX_ITER 5000000UL
#define ARGON2_MAX_MEMORY (512UL * 1024)	/* KiB.  */
#define ARGON2_MAX_PASSES 1000UL
/* Memory times passes, in KiB: what one file may make a reader do.  The
   two bounds above allow 512 GiB of memory traffic together; this is 4 GiB,
   a few seconds, and puttygen asks for far less.  */
#define ARGON2_MAX_WORK (4UL * 1024 * 1024)
#define ARGON2_MAX_LANES 16UL

/* ================================================================== */
/* DER, strictly                                                      */
/* ================================================================== */

struct der
{
  const uint8_t *p;
  size_t n;
};

#define T_INT 0x02
#define T_BITS 0x03
#define T_OCTETS 0x04
#define T_NULL 0x05
#define T_OID 0x06
#define T_SEQ 0x30
#define T_CTX0 0xa0
#define T_CTX1 0xa1

/* The next element of R: its tag and content.  Definite lengths only, in
   the shortest form, and one-byte tags: what DER is.  */
static int
der_get (struct der *r, uint8_t *tag, struct der *c)
{
  size_t len, hdr = 2;
  uint8_t b;

  if (r->n < 2)
    return GF_ERR_ENCODING;
  *tag = r->p[0];
  if ((*tag & 0x1f) == 0x1f)
    return GF_ERR_ENCODING;
  b = r->p[1];
  if (b < 0x80)
    len = b;
  else
    {
      size_t nb = b & 0x7f, i;

      if (nb == 0 || nb > 3 || r->n < 2 + nb || r->p[2] == 0)
        return GF_ERR_ENCODING;
      len = 0;
      for (i = 0; i < nb; i++)
        len = len << 8 | r->p[2 + i];
      if (len < 0x80)
        return GF_ERR_ENCODING;
      hdr += nb;
    }
  if (r->n - hdr < len)
    return GF_ERR_ENCODING;
  c->p = r->p + hdr;
  c->n = len;
  r->p += hdr + len;
  r->n -= hdr + len;
  return GF_OK;
}

static int
der_expect (struct der *r, uint8_t want, struct der *c)
{
  uint8_t tag;

  if (der_get (r, &tag, c) != GF_OK || tag != want)
    return GF_ERR_ENCODING;
  return GF_OK;
}

/* A non-negative INTEGER in its shortest form: its magnitude, without the
   sign byte.  */
static int
der_int (struct der *r, struct der *mag)
{
  struct der c;

  if (der_expect (r, T_INT, &c) != GF_OK || c.n == 0 || (c.p[0] & 0x80))
    return GF_ERR_ENCODING;
  if (c.n > 1 && c.p[0] == 0 && !(c.p[1] & 0x80))
    return GF_ERR_ENCODING;
  if (c.p[0] == 0 && c.n > 1)
    {
      c.p++;
      c.n--;
    }
  *mag = c;
  return GF_OK;
}

/* A small INTEGER.  */
static int
der_small (struct der *r, unsigned long *v)
{
  struct der m;
  size_t i;

  if (der_int (r, &m) != GF_OK || m.n > 4)
    return GF_ERR_ENCODING;
  *v = 0;
  for (i = 0; i < m.n; i++)
    *v = *v << 8 | m.p[i];
  return GF_OK;
}

static int
der_done (const struct der *r)
{
  return r->n == 0 ? GF_OK : GF_ERR_ENCODING;
}

static int
oid_is (struct der c, const uint8_t *oid, size_t n)
{
  return c.n == n && memcmp (c.p, oid, n) == 0;
}

#define OID(name, ...) static const uint8_t name[] = { __VA_ARGS__ }
OID (oid_rsa, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01);
OID (oid_ec, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);
OID (oid_p256, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07);
OID (oid_p384, 0x2b, 0x81, 0x04, 0x00, 0x22);
OID (oid_ed25519, 0x2b, 0x65, 0x70);
OID (oid_pbes2, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d);
OID (oid_pbkdf2, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c);
OID (oid_hmac256, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09);
OID (oid_hmac384, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a);
OID (oid_hmac512, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b);
OID (oid_aes128cbc, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02);
OID (oid_aes192cbc, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16);
OID (oid_aes256cbc, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a);

/* Writing: the header of an element with LEN bytes of content.  */
static size_t
der_hdr (uint8_t *out, uint8_t tag, size_t len)
{
  out[0] = tag;
  if (len < 0x80)
    {
      out[1] = (uint8_t) len;
      return 2;
    }
  if (len < 0x100)
    {
      out[1] = 0x81;
      out[2] = (uint8_t) len;
      return 3;
    }
  out[1] = 0x82;
  out[2] = (uint8_t) (len >> 8);
  out[3] = (uint8_t) len;
  return 4;
}

/* The element TAG with content C (N bytes) at OUT; returns its size.  */
static size_t
der_put (uint8_t *out, uint8_t tag, const uint8_t *c, size_t n)
{
  size_t h = der_hdr (out, tag, n);

  memmove (out + h, c, n);
  return h + n;
}

/* ================================================================== */
/* Keys from their parts                                              */
/* ================================================================== */

/* The SSH public blobs.  */
static int
blob_ed25519 (uint8_t *out, size_t cap, size_t *len, const uint8_t *pk)
{
  gf_writer w;

  gf_writer_init (&w, out, cap);
  gf_wr_cstring (&w, "ssh-ed25519");
  gf_wr_string (&w, pk, 32);
  *len = w.len;
  return gf_wr_status (&w) == GF_OK ? GF_OK : GF_ERR_BUFSIZE;
}

static int
blob_ec (uint8_t *out, size_t cap, size_t *len, enum gf_keytype t,
         const uint8_t *q, size_t qn)
{
  gf_writer w;
  const char *id = t == GF_KEY_ECDSA_P256 ? "nistp256" : "nistp384";

  gf_writer_init (&w, out, cap);
  gf_wr_cstring (&w, t == GF_KEY_ECDSA_P256 ? "ecdsa-sha2-nistp256"
                                            : "ecdsa-sha2-nistp384");
  gf_wr_cstring (&w, id);
  gf_wr_string (&w, q, qn);
  *len = w.len;
  return gf_wr_status (&w) == GF_OK ? GF_OK : GF_ERR_BUFSIZE;
}

static int
blob_rsa (uint8_t *out, size_t cap, size_t *len, struct der e, struct der n)
{
  gf_writer w;

  gf_writer_init (&w, out, cap);
  gf_wr_cstring (&w, "ssh-rsa");
  gf_wr_mpint (&w, e.p, e.n);
  gf_wr_mpint (&w, n.p, n.n);
  *len = w.len;
  return gf_wr_status (&w) == GF_OK ? GF_OK : GF_ERR_BUFSIZE;
}

/* The public key of an Ed25519 SEED, which only libgcrypt can say.  */
static int
ed25519_public (const uint8_t *seed, uint8_t *pk)
{
  gcry_sexp_t s = NULL, pub = NULL, q = NULL;
  gcry_ctx_t ctx = NULL;
  const char *data;
  size_t dl;
  int rc = GF_ERR_CRYPTO;

  if (gcry_sexp_build (&s, NULL,
                       "(private-key (ecc (curve Ed25519)(flags eddsa)(d %b)))",
                       32, seed)
      || gcry_mpi_ec_new (&ctx, s, NULL)
      || gcry_pubkey_get_sexp (&pub, GCRY_PK_GET_PUBKEY, ctx))
    goto done;
  q = gcry_sexp_find_token (pub, "q", 1);
  data = q ? gcry_sexp_nth_data (q, 1, &dl) : NULL;
  if (data != NULL && dl == 32)
    {
      memcpy (pk, data, 32);
      rc = GF_OK;
    }
done:
  gcry_sexp_release (q);
  gcry_sexp_release (pub);
  gcry_ctx_release (ctx);
  gcry_sexp_release (s);
  return rc;
}

static gcry_mpi_t
mpi_of (struct der m)
{
  return gfi_mpi_from (m.p, m.n);
}

static int
make_public (gf_key **out, const uint8_t *blob, size_t n)
{
  return gf_key_from_blob (out, blob, n);
}

/* ================================================================== */
/* SPKI, PKCS#1, PKCS#8, SEC1                                         */
/* ================================================================== */

/* The curve of an ECDSA key by its OID.  */
static int
curve_of (struct der oid, enum gf_keytype *t)
{
  if (oid_is (oid, oid_p256, sizeof oid_p256))
    *t = GF_KEY_ECDSA_P256;
  else if (oid_is (oid, oid_p384, sizeof oid_p384))
    *t = GF_KEY_ECDSA_P384;
  else
    return GF_ERR_UNSUPPORTED;
  return GF_OK;
}

static size_t
curve_bytes (enum gf_keytype t)
{
  return t == GF_KEY_ECDSA_P256 ? 32 : 48;
}

/* The content of a BIT STRING of whole bytes.  */
static int
bits_whole (struct der c, struct der *out)
{
  if (c.n < 1 || c.p[0] != 0)
    return GF_ERR_ENCODING;
  out->p = c.p + 1;
  out->n = c.n - 1;
  return GF_OK;
}

/* The algorithm of an AlgorithmIdentifier in R: the key type, with the
   curve for ECDSA.  A parameter that does not fit is refused.  */
static int
alg_id (struct der *r, enum gf_keytype *t)
{
  struct der a, oid, params;
  uint8_t tag;
  int rc;

  rc = der_expect (r, T_SEQ, &a);
  if (rc != GF_OK || der_expect (&a, T_OID, &oid) != GF_OK)
    return GF_ERR_ENCODING;
  if (oid_is (oid, oid_ed25519, sizeof oid_ed25519))
    {
      *t = GF_KEY_ED25519;
      return der_done (&a);		/* No parameters.  */
    }
  if (oid_is (oid, oid_rsa, sizeof oid_rsa))
    {
      *t = GF_KEY_RSA;
      if (der_get (&a, &tag, &params) != GF_OK || tag != T_NULL || params.n != 0)
        return GF_ERR_ENCODING;
      return der_done (&a);
    }
  if (oid_is (oid, oid_ec, sizeof oid_ec))
    {
      if (der_expect (&a, T_OID, &params) != GF_OK || der_done (&a) != GF_OK)
        return GF_ERR_ENCODING;
      return curve_of (params, t);
    }
  return GF_ERR_UNSUPPORTED;
}

/* RSAPublicKey (the content of its SEQUENCE) to the SSH blob.  */
static int
rsa_public_blob (struct der seq, uint8_t *blob, size_t cap, size_t *len)
{
  struct der n, e;

  if (der_int (&seq, &n) != GF_OK || der_int (&seq, &e) != GF_OK
      || der_done (&seq) != GF_OK)
    return GF_ERR_ENCODING;
  return blob_rsa (blob, cap, len, e, n);
}

/* A SubjectPublicKeyInfo.  */
static int
spki_read (gf_key **out, struct der body)
{
  struct der outer = body, spki, bits, key, rsa;
  enum gf_keytype t;
  uint8_t blob[MAX_DER / 8];
  size_t bl;
  int rc;

  if (der_expect (&outer, T_SEQ, &spki) != GF_OK || der_done (&outer) != GF_OK)
    return GF_ERR_ENCODING;
  rc = alg_id (&spki, &t);
  if (rc != GF_OK)
    return rc;
  if (der_expect (&spki, T_BITS, &bits) != GF_OK || der_done (&spki) != GF_OK
      || bits_whole (bits, &key) != GF_OK)
    return GF_ERR_ENCODING;
  switch (t)
    {
    case GF_KEY_ED25519:
      if (key.n != 32)
        return GF_ERR_ENCODING;
      rc = blob_ed25519 (blob, sizeof blob, &bl, key.p);
      break;
    case GF_KEY_RSA:
      {
        struct der whole = key;

        if (der_expect (&whole, T_SEQ, &rsa) != GF_OK || der_done (&whole) != GF_OK)
          return GF_ERR_ENCODING;
      }
      rc = rsa_public_blob (rsa, blob, sizeof blob, &bl);
      break;
    default:
      rc = blob_ec (blob, sizeof blob, &bl, t, key.p, key.n);
      break;
    }
  if (rc != GF_OK)
    return rc;
  return make_public (out, blob, bl);
}

/* ECPrivateKey (the content of its SEQUENCE) of curve T, where the curve may
   also be named in it (then it must be the same one) and the public point
   is PUB (from PKCS#8's own field) if the key does not have it.  */
static int
ec_private (gf_key **out, struct der seq, enum gf_keytype t, int need_params,
            struct der pub)
{
  struct der d, c, inner, q = pub, oid;
  unsigned long ver;
  uint8_t tag, blob[256];
  size_t bl;
  gcry_mpi_t dm;
  gf_key *k = NULL;
  int rc, params = 0;

  if (der_small (&seq, &ver) != GF_OK || ver != 1
      || der_expect (&seq, T_OCTETS, &d) != GF_OK)
    return GF_ERR_ENCODING;
  if (d.n != curve_bytes (t))
    return GF_ERR_ENCODING;
  while (seq.n > 0)
    {
      if (der_get (&seq, &tag, &c) != GF_OK)
        return GF_ERR_ENCODING;
      if (tag == T_CTX0 && !params && q.p == pub.p)
        {
          enum gf_keytype t2;

          inner = c;
          if (der_expect (&inner, T_OID, &oid) != GF_OK
              || der_done (&inner) != GF_OK || curve_of (oid, &t2) != GF_OK
              || t2 != t)
            return GF_ERR_ENCODING;
          params = 1;
        }
      else if (tag == T_CTX1)
        {
          inner = c;
          if (der_expect (&inner, T_BITS, &c) != GF_OK
              || der_done (&inner) != GF_OK || bits_whole (c, &q) != GF_OK)
            return GF_ERR_ENCODING;
        }
      else
        return GF_ERR_ENCODING;
    }
  if (need_params && !params)
    return GF_ERR_ENCODING;
  /* Every writer includes the public point; computing it is not offered.  */
  if (q.n == 0)
    return GF_ERR_UNSUPPORTED;
  rc = blob_ec (blob, sizeof blob, &bl, t, q.p, q.n);
  if (rc == GF_OK)
    rc = make_public (&k, blob, bl);
  if (rc != GF_OK)
    return rc;
  dm = mpi_of (d);
  if (dm == NULL)
    rc = GF_ERR_NOMEM;
  else
    rc = gfi_key_attach_private (k, q.p, q.n, dm, NULL, NULL, NULL, NULL,
                                 NULL);
  gcry_mpi_release (dm);
  if (rc != GF_OK)
    {
      gf_key_free (k);
      return rc;
    }
  *out = k;
  return GF_OK;
}

/* RSAPrivateKey (the content of its SEQUENCE).  */
static int
rsa_private (gf_key **out, struct der seq)
{
  struct der n, e, d, p, q, skip;
  unsigned long ver;
  uint8_t blob[MAX_DER / 8];
  size_t bl, i;
  gcry_mpi_t nm, em, dm, pm, qm;
  gf_key *k = NULL;
  int rc;

  if (der_small (&seq, &ver) != GF_OK || ver != 0
      || der_int (&seq, &n) != GF_OK || der_int (&seq, &e) != GF_OK
      || der_int (&seq, &d) != GF_OK || der_int (&seq, &p) != GF_OK
      || der_int (&seq, &q) != GF_OK)
    return GF_ERR_ENCODING;
  /* The CRT parameters are recomputed, but must be there.  */
  for (i = 0; i < 3; i++)
    if (der_int (&seq, &skip) != GF_OK)
      return GF_ERR_ENCODING;
  if (der_done (&seq) != GF_OK)
    return GF_ERR_ENCODING;
  rc = blob_rsa (blob, sizeof blob, &bl, e, n);
  if (rc == GF_OK)
    rc = make_public (&k, blob, bl);
  if (rc != GF_OK)
    return rc;
  nm = mpi_of (n);
  em = mpi_of (e);
  dm = mpi_of (d);
  pm = mpi_of (p);
  qm = mpi_of (q);
  if (nm && em && dm && pm && qm)
    rc = gfi_key_attach_private (k, NULL, 0, dm, NULL, nm, em, pm, qm);
  else
    rc = GF_ERR_NOMEM;
  gcry_mpi_release (nm);
  gcry_mpi_release (em);
  gcry_mpi_release (dm);
  gcry_mpi_release (pm);
  gcry_mpi_release (qm);
  if (rc != GF_OK)
    {
      gf_key_free (k);
      return rc;
    }
  *out = k;
  return GF_OK;
}

static int
ed25519_private (gf_key **out, const uint8_t *seed, struct der pub)
{
  uint8_t pk[32], blob[64];
  size_t bl;
  gf_key *k = NULL;
  gcry_mpi_t none = NULL;
  int rc;

  (void) none;
  rc = ed25519_public (seed, pk);
  if (rc != GF_OK)
    return rc;
  /* A public key in the file must be the one the seed makes.  */
  if (pub.n != 0 && (pub.n != 32 || memcmp (pub.p, pk, 32) != 0))
    return GF_ERR_ENCODING;
  rc = blob_ed25519 (blob, sizeof blob, &bl, pk);
  if (rc == GF_OK)
    rc = make_public (&k, blob, bl);
  if (rc != GF_OK)
    return rc;
  rc = gfi_key_attach_private (k, pk, 32, NULL, seed, NULL, NULL, NULL, NULL);
  if (rc != GF_OK)
    {
      gf_key_free (k);
      return rc;
    }
  *out = k;
  return GF_OK;
}

/* PrivateKeyInfo (PKCS#8, versions 0 and 1).  */
static int
pkcs8_read (gf_key **out, struct der body)
{
  struct der r = body, seq, key, c, pub = { NULL, 0 }, inner;
  enum gf_keytype t;
  unsigned long ver;
  uint8_t tag;
  int rc;

  if (der_expect (&r, T_SEQ, &seq) != GF_OK || der_done (&r) != GF_OK
      || der_small (&seq, &ver) != GF_OK || ver > 1)
    return GF_ERR_ENCODING;
  rc = alg_id (&seq, &t);
  if (rc != GF_OK)
    return rc;
  if (der_expect (&seq, T_OCTETS, &key) != GF_OK)
    return GF_ERR_ENCODING;
  while (seq.n > 0)
    {
      if (der_get (&seq, &tag, &c) != GF_OK)
        return GF_ERR_ENCODING;
      if (tag == T_CTX0)
        continue;			/* Attributes: nothing here uses them.  */
      if (tag == 0x81 && ver == 1)	/* [1] IMPLICIT BIT STRING.  */
        {
          if (bits_whole (c, &pub) != GF_OK)
            return GF_ERR_ENCODING;
          continue;
        }
      return GF_ERR_ENCODING;
    }
  switch (t)
    {
    case GF_KEY_ED25519:
      inner = key;
      if (der_expect (&inner, T_OCTETS, &c) != GF_OK
          || der_done (&inner) != GF_OK || c.n != 32)
        return GF_ERR_ENCODING;
      return ed25519_private (out, c.p, pub);
    case GF_KEY_RSA:
      inner = key;
      if (der_expect (&inner, T_SEQ, &c) != GF_OK
          || der_done (&inner) != GF_OK)
        return GF_ERR_ENCODING;
      return rsa_private (out, c);
    default:
      inner = key;
      if (der_expect (&inner, T_SEQ, &c) != GF_OK
          || der_done (&inner) != GF_OK)
        return GF_ERR_ENCODING;
      return ec_private (out, c, t, 0, pub);
    }
}

/* The SEC1 "EC PRIVATE KEY": the curve is in it.  */
static int
sec1_read (gf_key **out, struct der body)
{
  struct der r = body, seq, probe, c, oid;
  enum gf_keytype t;
  unsigned long ver;
  uint8_t tag;

  if (der_expect (&r, T_SEQ, &seq) != GF_OK || der_done (&r) != GF_OK)
    return GF_ERR_ENCODING;
  probe = seq;
  if (der_small (&probe, &ver) != GF_OK
      || der_expect (&probe, T_OCTETS, &c) != GF_OK)
    return GF_ERR_ENCODING;
  /* Find the [0] parameters to learn the curve.  */
  if (der_get (&probe, &tag, &c) != GF_OK || tag != T_CTX0)
    return GF_ERR_ENCODING;
  if (der_expect (&c, T_OID, &oid) != GF_OK)
    return GF_ERR_ENCODING;
  if (curve_of (oid, &t) != GF_OK)
    return GF_ERR_UNSUPPORTED;
  return ec_private (out, seq, t, 1, (struct der) { NULL, 0 });
}

/* ================================================================== */
/* PKCS#8 under PBES2                                                 */
/* ================================================================== */

static int
pbes2_decrypt (struct der body, const char *pass, uint8_t **plain,
               size_t *plen)
{
  struct der r = body, seq, alg, oid, params, kdf, kdfparams, enc, encparams;
  struct der salt, iv, data, tmp;
  unsigned long iter, keylen = 0;
  int hash, cipher;
  size_t klen;
  uint8_t tag, key[32], *buf;
  gcry_cipher_hd_t h;
  size_t i, pad;
  int rc = GF_ERR_PASSPHRASE;

  if (der_expect (&r, T_SEQ, &seq) != GF_OK || der_done (&r) != GF_OK
      || der_expect (&seq, T_SEQ, &alg) != GF_OK
      || der_expect (&seq, T_OCTETS, &data) != GF_OK
      || der_done (&seq) != GF_OK
      || der_expect (&alg, T_OID, &oid) != GF_OK)
    return GF_ERR_ENCODING;
  if (!oid_is (oid, oid_pbes2, sizeof oid_pbes2))
    return GF_ERR_UNSUPPORTED;		/* PBES1 and the others.  */
  if (der_expect (&alg, T_SEQ, &params) != GF_OK || der_done (&alg) != GF_OK
      || der_expect (&params, T_SEQ, &kdf) != GF_OK
      || der_expect (&params, T_SEQ, &enc) != GF_OK
      || der_done (&params) != GF_OK
      || der_expect (&kdf, T_OID, &oid) != GF_OK)
    return GF_ERR_ENCODING;
  if (!oid_is (oid, oid_pbkdf2, sizeof oid_pbkdf2))
    return GF_ERR_UNSUPPORTED;		/* scrypt, say.  */
  if (der_expect (&kdf, T_SEQ, &kdfparams) != GF_OK || der_done (&kdf) != GF_OK
      || der_expect (&kdfparams, T_OCTETS, &salt) != GF_OK
      || der_small (&kdfparams, &iter) != GF_OK)
    return GF_ERR_ENCODING;
  if (salt.n < 8 || salt.n > 64 || iter == 0)
    return GF_ERR_ENCODING;
  if (iter > PBKDF2_MAX_ITER)
    return GF_ERR_UNSUPPORTED;
  /* keyLength (optional), then the hash, which must be named: without one
     it is HMAC-SHA-1.  */
  tmp = kdfparams;
  if (tmp.n > 0 && tmp.p[0] == T_INT && der_small (&tmp, &keylen) == GF_OK)
    kdfparams = tmp;
  if (kdfparams.n == 0)
    return GF_ERR_UNSUPPORTED;
  if (der_expect (&kdfparams, T_SEQ, &tmp) != GF_OK
      || der_done (&kdfparams) != GF_OK
      || der_expect (&tmp, T_OID, &oid) != GF_OK)
    return GF_ERR_ENCODING;
  if (oid_is (oid, oid_hmac256, sizeof oid_hmac256))
    hash = GCRY_MD_SHA256;
  else if (oid_is (oid, oid_hmac384, sizeof oid_hmac384))
    hash = GCRY_MD_SHA384;
  else if (oid_is (oid, oid_hmac512, sizeof oid_hmac512))
    hash = GCRY_MD_SHA512;
  else
    return GF_ERR_UNSUPPORTED;
  if (tmp.n > 0
      && (der_get (&tmp, &tag, &params) != GF_OK || tag != T_NULL
          || params.n != 0 || der_done (&tmp) != GF_OK))
    return GF_ERR_ENCODING;
  if (der_expect (&enc, T_OID, &oid) != GF_OK
      || der_expect (&enc, T_OCTETS, &iv) != GF_OK || der_done (&enc) != GF_OK)
    return GF_ERR_ENCODING;
  (void) encparams;
  if (oid_is (oid, oid_aes128cbc, sizeof oid_aes128cbc))
    {
      cipher = GCRY_CIPHER_AES128;
      klen = 16;
    }
  else if (oid_is (oid, oid_aes192cbc, sizeof oid_aes192cbc))
    {
      cipher = GCRY_CIPHER_AES192;
      klen = 24;
    }
  else if (oid_is (oid, oid_aes256cbc, sizeof oid_aes256cbc))
    {
      cipher = GCRY_CIPHER_AES256;
      klen = 32;
    }
  else
    return GF_ERR_UNSUPPORTED;
  if (iv.n != 16 || (keylen != 0 && keylen != klen) || data.n < 16
      || data.n % 16 != 0 || data.n > MAX_DER)
    return GF_ERR_ENCODING;
  if (pass == NULL)
    return GF_ERR_PASSPHRASE;
  if (gf_crypto_init () != GF_OK)
    return GF_ERR_CRYPTO;
  if (gcry_kdf_derive (pass, strlen (pass), GCRY_KDF_PBKDF2, hash, salt.p,
                       salt.n, iter, klen, key))
    return GF_ERR_CRYPTO;
  buf = malloc (data.n);
  if (buf == NULL)
    {
      gf_wipe (key, sizeof key);
      return GF_ERR_NOMEM;
    }
  memcpy (buf, data.p, data.n);
  if (gcry_cipher_open (&h, cipher, GCRY_CIPHER_MODE_CBC, 0))
    {
      free (buf);
      gf_wipe (key, sizeof key);
      return GF_ERR_CRYPTO;
    }
  if (gcry_cipher_setkey (h, key, klen) || gcry_cipher_setiv (h, iv.p, 16)
      || gcry_cipher_decrypt (h, buf, data.n, NULL, 0))
    rc = GF_ERR_CRYPTO;
  else
    {
      /* PKCS#7 padding: the only check a wrong passphrase usually fails.  */
      pad = buf[data.n - 1];
      rc = GF_OK;
      if (pad == 0 || pad > 16)
        rc = GF_ERR_PASSPHRASE;
      else
        for (i = 0; i < pad; i++)
          if (buf[data.n - 1 - i] != pad)
            rc = GF_ERR_PASSPHRASE;
      if (rc == GF_OK)
        {
          *plain = buf;
          *plen = data.n - pad;
        }
    }
  gcry_cipher_close (h);
  gf_wipe (key, sizeof key);
  if (rc != GF_OK)
    {
      gf_wipe (buf, data.n);
      free (buf);
    }
  return rc;
}

/* ================================================================== */
/* PEM                                                                */
/* ================================================================== */

static int
is_ws (char c)
{
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* The one block of TEXT: its label (up to CAP bytes) and its DER in a new
   buffer.  */
static int
pem_decode (const char *text, size_t len, char *label, size_t cap,
            uint8_t **der, size_t *derlen)
{
  static const char begin[] = "-----BEGIN ", end[] = "-----END ", dash[] = "-----";
  const char *p = text, *e = text + len, *body, *endmark;
  size_t ll, i;
  uint8_t *buf;
  long n;

  if (len > MAX_TEXT)
    return GF_ERR_RANGE;
  while (p < e && is_ws (*p))
    p++;
  if ((size_t) (e - p) < sizeof begin || memcmp (p, begin, sizeof begin - 1) != 0)
    return GF_ERR_ENCODING;
  p += sizeof begin - 1;
  for (ll = 0; p + ll < e && p[ll] != '-' && p[ll] != '\n'; ll++)
    ;
  if (ll == 0 || ll >= cap || (size_t) (e - p) < ll + 5
      || memcmp (p + ll, dash, 5) != 0)
    return GF_ERR_ENCODING;
  memcpy (label, p, ll);
  label[ll] = '\0';
  body = p + ll + 5;
  while (body < e && (*body == '\r' || *body == ' '))
    body++;
  if (body >= e || *body != '\n')
    return GF_ERR_ENCODING;
  body++;
  /* Headers: the old encryption, which is not supported, or nothing.  */
  for (i = 0; body + i < e && body[i] != '\n'; i++)
    if (body[i] == ':')
      return strncmp (body, "Proc-Type:", 10) == 0 ? GF_ERR_UNSUPPORTED
                                                    : GF_ERR_ENCODING;
  endmark = NULL;
  for (p = body; p + sizeof end - 1 <= e; p++)
    if (*p == '-' && memcmp (p, end, sizeof end - 1) == 0)
      {
        endmark = p;
        break;
      }
  if (endmark == NULL)
    return GF_ERR_ENCODING;
  p = endmark + sizeof end - 1;
  if ((size_t) (e - p) < ll + 5 || memcmp (p, label, ll) != 0
      || memcmp (p + ll, dash, 5) != 0)
    return GF_ERR_ENCODING;
  p += ll + 5;
  while (p < e && is_ws (*p))
    p++;
  if (p != e)
    return GF_ERR_ENCODING;		/* Only one block.  */
  buf = malloc ((size_t) (endmark - body) / 4 * 3 + 4);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  n = gfi_b64_decode (body, (size_t) (endmark - body), buf,
                      (size_t) (endmark - body) / 4 * 3 + 4, 0);
  if (n <= 0 || (size_t) n > MAX_DER)
    {
      free (buf);
      return GF_ERR_ENCODING;
    }
  *der = buf;
  *derlen = (size_t) n;
  return GF_OK;
}

int
gf_key_from_pem (gf_key **out, const char *text, size_t len,
                 const char *passphrase)
{
  char label[40];
  uint8_t *der = NULL, *plain = NULL;
  size_t dl = 0, pl = 0;
  struct der body;
  int rc;

  if (out == NULL || (text == NULL && len > 0))
    return GF_ERR_INVAL;
  *out = NULL;
  rc = pem_decode (text, len, label, sizeof label, &der, &dl);
  if (rc != GF_OK)
    return rc;
  body.p = der;
  body.n = dl;
  if (strcmp (label, "PUBLIC KEY") == 0)
    rc = spki_read (out, body);
  else if (strcmp (label, "RSA PUBLIC KEY") == 0)
    {
      struct der r = body, seq;
      uint8_t blob[MAX_DER / 8];
      size_t bl;

      rc = der_expect (&r, T_SEQ, &seq);
      if (rc == GF_OK && der_done (&r) == GF_OK)
        rc = rsa_public_blob (seq, blob, sizeof blob, &bl);
      else
        rc = GF_ERR_ENCODING;
      if (rc == GF_OK)
        rc = make_public (out, blob, bl);
    }
  else if (strcmp (label, "PRIVATE KEY") == 0)
    rc = pkcs8_read (out, body);
  else if (strcmp (label, "ENCRYPTED PRIVATE KEY") == 0)
    {
      rc = pbes2_decrypt (body, passphrase, &plain, &pl);
      if (rc == GF_OK)
        {
          struct der inner = { plain, pl };

          rc = pkcs8_read (out, inner);
          /* Padding that was right by luck, and then nonsense.  */
          if (rc == GF_ERR_ENCODING)
            rc = GF_ERR_PASSPHRASE;
          gf_wipe (plain, pl);
          free (plain);
        }
    }
  else if (strcmp (label, "RSA PRIVATE KEY") == 0)
    {
      struct der r = body, seq;

      rc = der_expect (&r, T_SEQ, &seq);
      rc = rc == GF_OK && der_done (&r) == GF_OK ? rsa_private (out, seq)
                                                 : GF_ERR_ENCODING;
    }
  else if (strcmp (label, "EC PRIVATE KEY") == 0)
    rc = sec1_read (out, body);
  else
    rc = GF_ERR_UNSUPPORTED;
  gf_wipe (der, dl);
  free (der);
  return rc;
}

/* ---- Writing the SPKI ---- */

int
gf_key_to_pem_public (const gf_key *key, char *out, size_t cap, size_t *len)
{
  uint8_t spki[MAX_DER / 4], a[64], bits[MAX_DER / 4], rsa[MAX_DER / 4], tmp[MAX_DER / 4];
  const uint8_t *pb;
  size_t pl, an, bn, sn, o = 0, i;
  gf_reader rd;
  gf_slice name, s1, s2;
  const char *header = "-----BEGIN PUBLIC KEY-----\n";
  const char *footer = "-----END PUBLIC KEY-----\n";
  uint8_t b64[MAX_DER / 2];
  size_t bl;

  if (key == NULL || out == NULL || len == NULL || gf_key_is_certificate (key))
    return GF_ERR_INVAL;
  pb = gf_key_blob (key, &pl);
  gf_reader_init (&rd, pb, pl);
  if (gf_rd_string (&rd, &name) != GF_OK)
    return GF_ERR_INVAL;
  switch (gf_key_type (key))
    {
    case GF_KEY_ED25519:
      if (gf_rd_string (&rd, &s1) != GF_OK || s1.len != 32)
        return GF_ERR_UNSUPPORTED;
      an = der_put (a, T_OID, oid_ed25519, sizeof oid_ed25519);
      an = der_put (tmp, T_SEQ, a, an);
      memcpy (a, tmp, an);
      tmp[0] = 0;
      memcpy (tmp + 1, s1.data, 32);
      bn = der_put (bits, T_BITS, tmp, 33);
      break;
    case GF_KEY_RSA:
      {
        struct der e, n;
        uint8_t ie[MAX_DER / 8], in[MAX_DER / 8];
        size_t ien, inn;

        if (gf_rd_mpint (&rd, &s1) != GF_OK || gf_rd_mpint (&rd, &s2) != GF_OK
            || s1.len > 16 || s2.len > MAX_DER / 8 - 8)
          return GF_ERR_UNSUPPORTED;
        /* INTEGERs: a zero byte first if the top bit is set.  */
        ien = 0;
        if (s1.data[0] & 0x80)
          ie[ien++] = 0;
        memcpy (ie + ien, s1.data, s1.len);
        ien += s1.len;
        inn = 0;
        if (s2.data[0] & 0x80)
          in[inn++] = 0;
        memcpy (in + inn, s2.data, s2.len);
        inn += s2.len;
        (void) e;
        (void) n;
        {
          uint8_t seq[MAX_DER / 4];
          size_t q = der_put (seq, T_INT, in, inn);

          q += der_put (seq + q, T_INT, ie, ien);
          sn = der_put (rsa, T_SEQ, seq, q);
        }
        tmp[0] = 0;
        memcpy (tmp + 1, rsa, sn);
        bn = der_put (bits, T_BITS, tmp, sn + 1);
        {
          uint8_t oid[32], nul[2] = { 0x05, 0x00 };

          an = der_put (oid, T_OID, oid_rsa, sizeof oid_rsa);
          memcpy (oid + an, nul, 2);
          an = der_put (a, T_SEQ, oid, an + 2);
        }
      }
      break;
    default:
      {
        const uint8_t *curve;
        size_t cn;
        uint8_t oid[32];

        if (gf_rd_string (&rd, &s1) != GF_OK || gf_rd_string (&rd, &s2) != GF_OK)
          return GF_ERR_UNSUPPORTED;
        if (gf_key_type (key) == GF_KEY_ECDSA_P256)
          {
            curve = oid_p256;
            cn = sizeof oid_p256;
          }
        else
          {
            curve = oid_p384;
            cn = sizeof oid_p384;
          }
        an = der_put (oid, T_OID, oid_ec, sizeof oid_ec);
        an += der_put (oid + an, T_OID, curve, cn);
        an = der_put (a, T_SEQ, oid, an);
        tmp[0] = 0;
        memcpy (tmp + 1, s2.data, s2.len);
        bn = der_put (bits, T_BITS, tmp, s2.len + 1);
      }
      break;
    }
  memcpy (spki, a, an);
  memcpy (spki + an, bits, bn);
  sn = der_put (tmp, T_SEQ, spki, an + bn);
  bl = gfi_b64_encode (tmp, sn, (char *) b64, 1);
  /* 64 characters to a line.  */
  if (cap < strlen (header) + bl + bl / 64 + 2 + strlen (footer) + 1)
    return GF_ERR_BUFSIZE;
  memcpy (out, header, strlen (header));
  o = strlen (header);
  for (i = 0; i < bl; i += 64)
    {
      size_t n = bl - i < 64 ? bl - i : 64;

      memcpy (out + o, b64 + i, n);
      o += n;
      out[o++] = '\n';
    }
  memcpy (out + o, footer, strlen (footer));
  o += strlen (footer);
  out[o] = '\0';
  *len = o;
  return GF_OK;
}

/* ================================================================== */
/* RFC 4716                                                           */
/* ================================================================== */

#define R4716_BEGIN "---- BEGIN SSH2 PUBLIC KEY ----"
#define R4716_END "---- END SSH2 PUBLIC KEY ----"

/* The next line of [P, END): its text without the line end, and P moved
   past it.  */
static int
next_line (const char **p, const char *end, const char **line, size_t *ln)
{
  const char *q = *p;

  if (q >= end)
    return 0;
  *line = q;
  while (q < end && *q != '\n')
    q++;
  *ln = (size_t) (q - *line);
  if (*ln > 0 && (*line)[*ln - 1] == '\r')
    (*ln)--;
  *p = q < end ? q + 1 : q;
  return 1;
}

static void
set_comment (char *comment, size_t cap, const char *v, size_t n)
{
  if (comment == NULL || cap == 0)
    return;
  if (n >= 2 && v[0] == '"' && v[n - 1] == '"')
    {
      v++;
      n -= 2;
    }
  if (n >= cap)
    n = cap - 1;
  memcpy (comment, v, n);
  comment[n] = '\0';
}

int
gf_key_from_rfc4716 (gf_key **out, const char *text, size_t len,
                     char *comment, size_t cap)
{
  const char *p = text, *end = text + len, *line = NULL;
  size_t ln = 0, bn = 0;
  char *b64, value[1100];
  size_t vn = 0;
  int in_header = 1, cont = 0, got_end = 0, is_comment = 0;
  uint8_t *blob;
  long n;
  int rc;

  if (out == NULL || (text == NULL && len > 0))
    return GF_ERR_INVAL;
  *out = NULL;
  if (comment != NULL && cap > 0)
    comment[0] = '\0';
  if (len > MAX_TEXT)
    return GF_ERR_RANGE;
  while (next_line (&p, end, &line, &ln) && ln == 0)
    ;
  if (ln != sizeof R4716_BEGIN - 1 || memcmp (line, R4716_BEGIN, ln) != 0)
    return GF_ERR_ENCODING;
  b64 = malloc (len + 1);
  if (b64 == NULL)
    return GF_ERR_NOMEM;
  while (next_line (&p, end, &line, &ln))
    {
      if (ln == sizeof R4716_END - 1 && memcmp (line, R4716_END, ln) == 0)
        {
          got_end = 1;
          break;
        }
      if (cont || (in_header && memchr (line, ':', ln) != NULL))
        {
          /* A header; a trailing backslash continues the value.  */
          size_t start = 0;

          if (!cont)
            {
              const char *colon = memchr (line, ':', ln);

              if (colon - line > 64)
                {
                  free (b64);
                  return GF_ERR_ENCODING;
                }
              is_comment = (size_t) (colon - line) == 7
                && memcmp (line, "Comment", 7) == 0;
              start = (size_t) (colon - line) + 1;
              while (start < ln && line[start] == ' ')
                start++;
              vn = 0;
            }
          cont = ln > 0 && line[ln - 1] == '\\';
          if (cont)
            ln--;
          if (vn + (ln - start) >= sizeof value)
            {
              free (b64);
              return GF_ERR_ENCODING;
            }
          memcpy (value + vn, line + start, ln - start);
          vn += ln - start;
          if (!cont && is_comment)
            set_comment (comment, cap, value, vn);
          continue;
        }
      in_header = 0;
      /* Base64 lines.  */
      if (bn + ln > len)
        {
          free (b64);
          return GF_ERR_ENCODING;
        }
      memcpy (b64 + bn, line, ln);
      bn += ln;
    }
  while (got_end && next_line (&p, end, &line, &ln))
    if (ln != 0)
      {
        got_end = 0;			/* Something after the end.  */
        break;
      }
  if (!got_end || cont || bn == 0)
    {
      free (b64);
      return GF_ERR_ENCODING;
    }
  blob = malloc (bn / 4 * 3 + 4);
  if (blob == NULL)
    {
      free (b64);
      return GF_ERR_NOMEM;
    }
  n = gfi_b64_decode (b64, bn, blob, bn / 4 * 3 + 4, 1);
  free (b64);
  if (n <= 0)
    {
      free (blob);
      return GF_ERR_ENCODING;
    }
  rc = gf_key_from_blob (out, blob, (size_t) n);
  free (blob);
  if (rc == GF_OK && gf_key_is_certificate (*out))
    {
      gf_key_free (*out);
      *out = NULL;
      rc = GF_ERR_UNSUPPORTED;
    }
  return rc;
}

int
gf_key_to_rfc4716 (const gf_key *key, const char *comment, char *out,
                   size_t cap, size_t *len)
{
  const uint8_t *blob;
  size_t bl, o = 0, i, cl;
  char *b64;
  size_t b64n;
  int rc = GF_OK;

  if (key == NULL || out == NULL || len == NULL || gf_key_is_certificate (key)
      || (comment != NULL && strlen (comment) > 900))
    return GF_ERR_INVAL;
  blob = gf_key_blob (key, &bl);
  b64 = malloc (bl / 3 * 4 + 8);
  if (b64 == NULL)
    return GF_ERR_NOMEM;
  b64n = gfi_b64_encode (blob, bl, b64, 1);
  /* Room for everything, generously.  */
  cl = comment ? strlen (comment) : 0;
  if (cap < sizeof R4716_BEGIN + sizeof R4716_END + b64n + b64n / 70 + 2 * cl / 60 + 80 + cl)
    {
      free (b64);
      return GF_ERR_BUFSIZE;
    }
  o += (size_t) snprintf (out + o, cap - o, "%s\n", R4716_BEGIN);
  if (comment != NULL)
    {
      /* Comment: "text", in lines of at most 72 characters that continue
         with a backslash.  */
      char hdr[1000];
      size_t hn = (size_t) snprintf (hdr, sizeof hdr, "Comment: \"%s\"", comment);

      for (i = 0; hn - i > 72; i += 71)
        {
          memcpy (out + o, hdr + i, 71);
          o += 71;
          out[o++] = '\\';
          out[o++] = '\n';
        }
      memcpy (out + o, hdr + i, hn - i);
      o += hn - i;
      out[o++] = '\n';
    }
  for (i = 0; i < b64n; i += 70)
    {
      size_t n = b64n - i < 70 ? b64n - i : 70;

      memcpy (out + o, b64 + i, n);
      o += n;
      out[o++] = '\n';
    }
  o += (size_t) snprintf (out + o, cap - o, "%s\n", R4716_END);
  *len = o;
  free (b64);
  return rc;
}

/* ================================================================== */
/* Randomart                                                          */
/* ================================================================== */

#define FLD_X 17
#define FLD_Y 9

int
gf_key_randomart (const gf_key *key, char *out, size_t cap, size_t *len)
{
  static const char aug[] = " .o+=*BOX@%&#/^SE";
  unsigned char field[FLD_X][FLD_Y];
  uint8_t digest[32];
  const uint8_t *pb;
  size_t pl, i, o = 0, alen = sizeof aug - 2;
  int x = FLD_X / 2, y = FLD_Y / 2, b, xx, yy;
  const char *tn;
  char title[48], base[24];
  unsigned bits;

  /* Two borders and FLD_Y rows, each FLD_X characters between two bars
     and a newline, and the NUL.  */
  if (key == NULL || out == NULL || len == NULL
      || cap < (FLD_Y + 2) * (FLD_X + 3) + 1)
    return GF_ERR_INVAL;
  tn = gf_key_type_name (key);
  if (strstr (tn, "x509v3") != NULL)
    return GF_ERR_UNSUPPORTED;
  snprintf (base, sizeof base, "%s%s%s",
            strstr (tn, "ed25519") ? "ED25519"
            : strstr (tn, "ecdsa") ? "ECDSA" : "RSA",
            strncmp (tn, "sk-", 3) == 0 ? "-SK" : "",
            gf_key_is_certificate (key) ? "-CERT" : "");
  bits = gf_key_bits (key);
  if (gf_crypto_init () != GF_OK)
    return GF_ERR_CRYPTO;
  pb = gf_key_plain_blob (key, &pl);
  gcry_md_hash_buffer (GCRY_MD_SHA256, digest, pb, pl);
  memset (field, 0, sizeof field);
  for (i = 0; i < sizeof digest; i++)
    {
      unsigned input = digest[i];

      for (b = 0; b < 4; b++)
        {
          x += (input & 1) ? 1 : -1;
          y += (input & 2) ? 1 : -1;
          x = x < 0 ? 0 : x >= FLD_X ? FLD_X - 1 : x;
          y = y < 0 ? 0 : y >= FLD_Y ? FLD_Y - 1 : y;
          if (field[x][y] < alen - 2)
            field[x][y]++;
          input >>= 2;
        }
    }
  field[FLD_X / 2][FLD_Y / 2] = (unsigned char) (alen - 1);
  field[x][y] = (unsigned char) alen;

  /* The top border has the type and size, the bottom the hash.  */
  snprintf (title, sizeof title, "[%s %u]", base, bits);
  for (yy = -1; yy <= FLD_Y; yy++)
    {
      if (yy == -1 || yy == FLD_Y)
        {
          const char *t = yy == -1 ? title : "[SHA256]";
          size_t tl = strlen (t), left, right;

          if (tl > FLD_X)
            tl = FLD_X;
          left = (FLD_X - tl) / 2;
          right = FLD_X - tl - left;
          out[o++] = '+';
          memset (out + o, '-', left);
          o += left;
          memcpy (out + o, t, tl);
          o += tl;
          memset (out + o, '-', right);
          o += right;
          out[o++] = '+';
        }
      else
        {
          out[o++] = '|';
          for (xx = 0; xx < FLD_X; xx++)
            out[o++] = aug[field[xx][yy]];
          out[o++] = '|';
        }
      out[o++] = '\n';
    }
  out[o] = '\0';
  *len = o;
  return GF_OK;
}

/* ================================================================== */
/* PuTTY                                                              */
/* ================================================================== */

static int
hex_digit (char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Hex text to bytes, exactly N of them.  */
static int
hex_exact (const char *s, size_t sn, uint8_t *out, size_t n)
{
  size_t i;

  if (sn != 2 * n)
    return 0;
  for (i = 0; i < n; i++)
    {
      int hi = hex_digit (s[2 * i]), lo = hex_digit (s[2 * i + 1]);

      if (hi < 0 || lo < 0)
        return 0;
      out[i] = (uint8_t) (hi << 4 | lo);
    }
  return 1;
}

struct ppk
{
  char alg[40], enc[24], comment[512], kdf[16];
  size_t algn, encn, commentn;
  uint8_t *pub, *priv;
  size_t publen, privlen;
  unsigned long mem, passes, lanes;
  uint8_t salt[64];
  size_t saltn;
  uint8_t mac[32];
  int have_mac;
};

static void
ppk_free (struct ppk *k)
{
  if (k->priv)
    {
      gf_wipe (k->priv, k->privlen);
      free (k->priv);
    }
  free (k->pub);
}

/* A header line "Name: value".  */
static int
ppk_header (const char **p, const char *end, const char *name, const char **v,
            size_t *vn)
{
  const char *line;
  size_t ln, nl = strlen (name);

  if (!next_line (p, end, &line, &ln) || ln < nl + 1
      || memcmp (line, name, nl) != 0 || line[nl] != ':')
    return 0;
  *v = line + nl + 1;
  *vn = ln - nl - 1;
  while (*vn > 0 && **v == ' ')
    {
      (*v)++;
      (*vn)--;
    }
  return 1;
}

static int
number (const char *s, size_t n, unsigned long max, unsigned long *v)
{
  size_t i;

  if (n == 0 || n > 10)
    return 0;
  *v = 0;
  for (i = 0; i < n; i++)
    {
      if (s[i] < '0' || s[i] > '9')
        return 0;
      *v = *v * 10 + (unsigned long) (s[i] - '0');
    }
  return *v <= max;
}

/* N lines of base64 to bytes.  */
static int
ppk_lines (const char **p, const char *end, unsigned long n, uint8_t **out,
           size_t *outn)
{
  const char *line;
  size_t ln, total = 0, cap = (size_t) n * 96 + 4;
  char *b64 = malloc (cap);
  unsigned long i;
  long r;

  if (b64 == NULL)
    return GF_ERR_NOMEM;
  for (i = 0; i < n; i++)
    {
      if (!next_line (p, end, &line, &ln) || total + ln > cap - 4)
        {
          free (b64);
          return GF_ERR_ENCODING;
        }
      memcpy (b64 + total, line, ln);
      total += ln;
    }
  *out = malloc (total / 4 * 3 + 4);
  if (*out == NULL)
    {
      free (b64);
      return GF_ERR_NOMEM;
    }
  r = gfi_b64_decode (b64, total, *out, total / 4 * 3 + 4, 0);
  free (b64);
  if (r <= 0)
    {
      free (*out);
      *out = NULL;
      return GF_ERR_ENCODING;
    }
  *outn = (size_t) r;
  return GF_OK;
}

static int
ppk_parse (struct ppk *k, const char *text, size_t len)
{
  const char *p = text, *end = text + len, *v;
  size_t vn;
  unsigned long n, maxlines = 128;
  int rc;

  memset (k, 0, sizeof *k);
  if (len > MAX_TEXT)
    return GF_ERR_RANGE;
  if (len < 24 || memcmp (text, "PuTTY-User-Key-File-", 20) != 0)
    return GF_ERR_ENCODING;
  /* "PuTTY-User-Key-File-3: ssh-ed25519".  */
  if (text[21] != ':')
    return GF_ERR_ENCODING;
  if (text[20] != '3')
    return text[20] == '1' || text[20] == '2' ? GF_ERR_UNSUPPORTED
                                              : GF_ERR_ENCODING;
  p = text + 22;
  while (p < end && *p == ' ')
    p++;
  for (vn = 0; p + vn < end && p[vn] != '\n' && p[vn] != '\r'; vn++)
    ;
  if (vn == 0 || vn >= sizeof k->alg)
    return GF_ERR_ENCODING;
  memcpy (k->alg, p, vn);
  k->algn = vn;
  p += vn;
  if (p < end && *p == '\r')
    p++;
  if (p < end && *p == '\n')
    p++;
  if (!ppk_header (&p, end, "Encryption", &v, &vn) || vn >= sizeof k->enc)
    return GF_ERR_ENCODING;
  memcpy (k->enc, v, vn);
  k->encn = vn;
  if (!ppk_header (&p, end, "Comment", &v, &vn) || vn >= sizeof k->comment)
    return GF_ERR_ENCODING;
  memcpy (k->comment, v, vn);
  k->commentn = vn;
  if (!ppk_header (&p, end, "Public-Lines", &v, &vn)
      || !number (v, vn, maxlines, &n) || n == 0)
    return GF_ERR_ENCODING;
  rc = ppk_lines (&p, end, n, &k->pub, &k->publen);
  if (rc != GF_OK)
    return rc;
  if (k->encn == 4 && memcmp (k->enc, "none", 4) == 0)
    ;
  else if (k->encn == 10 && memcmp (k->enc, "aes256-cbc", 10) == 0)
    {
      unsigned long sl;

      if (!ppk_header (&p, end, "Key-Derivation", &v, &vn) || vn >= sizeof k->kdf)
        return GF_ERR_ENCODING;
      memcpy (k->kdf, v, vn);
      if (!ppk_header (&p, end, "Argon2-Memory", &v, &vn)
          || !number (v, vn, ARGON2_MAX_MEMORY, &k->mem) || k->mem == 0)
        return GF_ERR_UNSUPPORTED;
      if (!ppk_header (&p, end, "Argon2-Passes", &v, &vn)
          || !number (v, vn, ARGON2_MAX_PASSES, &k->passes) || k->passes == 0
          || k->mem * k->passes > ARGON2_MAX_WORK)
        return GF_ERR_UNSUPPORTED;
      if (!ppk_header (&p, end, "Argon2-Parallelism", &v, &vn)
          || !number (v, vn, ARGON2_MAX_LANES, &k->lanes) || k->lanes == 0)
        return GF_ERR_UNSUPPORTED;
      if (!ppk_header (&p, end, "Argon2-Salt", &v, &vn) || vn % 2 != 0
          || vn / 2 < 8 || vn / 2 > sizeof k->salt
          || !hex_exact (v, vn, k->salt, vn / 2))
        return GF_ERR_ENCODING;
      sl = (unsigned long) vn / 2;
      k->saltn = sl;
    }
  else
    return GF_ERR_UNSUPPORTED;
  if (!ppk_header (&p, end, "Private-Lines", &v, &vn)
      || !number (v, vn, maxlines, &n) || n == 0)
    return GF_ERR_ENCODING;
  rc = ppk_lines (&p, end, n, &k->priv, &k->privlen);
  if (rc != GF_OK)
    return rc;
  if (!ppk_header (&p, end, "Private-MAC", &v, &vn)
      || !hex_exact (v, vn, k->mac, 32))
    return GF_ERR_ENCODING;
  while (p < end && is_ws (*p))
    p++;
  return p == end ? GF_OK : GF_ERR_ENCODING;
}

/* HMAC-SHA-256 of the five strings the MAC covers.  */
static int
ppk_mac (const struct ppk *k, const uint8_t *key, size_t keyn, uint8_t *out)
{
  gcry_mac_hd_t h;
  uint8_t four[4];
  size_t outn = 32;
  uint8_t zero = 0;
  const struct { const uint8_t *d; size_t n; } parts[5] = {
    { (const uint8_t *) k->alg, k->algn }, { (const uint8_t *) k->enc, k->encn },
    { (const uint8_t *) k->comment, k->commentn }, { k->pub, k->publen },
    { k->priv, k->privlen }
  };
  size_t i;
  int rc = GF_OK;

  if (gcry_mac_open (&h, GCRY_MAC_HMAC_SHA256, 0, NULL))
    return GF_ERR_CRYPTO;
  /* An empty key is a key of one zero byte to HMAC, which pads with them.  */
  if (gcry_mac_setkey (h, keyn ? key : &zero, keyn ? keyn : 1))
    rc = GF_ERR_CRYPTO;
  for (i = 0; rc == GF_OK && i < 5; i++)
    {
      four[0] = (uint8_t) (parts[i].n >> 24);
      four[1] = (uint8_t) (parts[i].n >> 16);
      four[2] = (uint8_t) (parts[i].n >> 8);
      four[3] = (uint8_t) parts[i].n;
      if (gcry_mac_write (h, four, 4)
          || (parts[i].n && gcry_mac_write (h, parts[i].d, parts[i].n)))
        rc = GF_ERR_CRYPTO;
    }
  if (rc == GF_OK && (gcry_mac_read (h, out, &outn) || outn != 32))
    rc = GF_ERR_CRYPTO;
  gcry_mac_close (h);
  return rc;
}

int
gf_key_from_ppk (gf_key **out, const char *text, size_t len,
                 const char *passphrase, char *comment, size_t cap)
{
  struct ppk k;
  uint8_t derived[80], mac[32];
  const uint8_t *macwith = NULL;
  size_t macn = 0;
  gf_key *key = NULL;
  gf_reader pr, rr;
  gf_slice alg, s1, s2, s3;
  int rc, enc;
  uint8_t blob[MAX_DER / 8];

  if (out == NULL || (text == NULL && len > 0))
    return GF_ERR_INVAL;
  *out = NULL;
  if (comment != NULL && cap > 0)
    comment[0] = '\0';
  rc = ppk_parse (&k, text, len);
  if (rc != GF_OK)
    {
      ppk_free (&k);
      return rc;
    }
  enc = k.encn == 10;
  if (gf_crypto_init () != GF_OK)
    {
      ppk_free (&k);
      return GF_ERR_CRYPTO;
    }
  if (enc)
    {
      unsigned long param[4];
      gcry_kdf_hd_t kh;
      int sub;
      gcry_cipher_hd_t ch;

      if (passphrase == NULL)
        {
          ppk_free (&k);
          return GF_ERR_PASSPHRASE;
        }
      if (strcmp (k.kdf, "Argon2id") == 0)
        sub = GCRY_KDF_ARGON2ID;
      else if (strcmp (k.kdf, "Argon2i") == 0)
        sub = GCRY_KDF_ARGON2I;
      else if (strcmp (k.kdf, "Argon2d") == 0)
        sub = GCRY_KDF_ARGON2D;
      else
        {
          ppk_free (&k);
          return GF_ERR_UNSUPPORTED;
        }
      if (k.privlen % 16 != 0)
        {
          ppk_free (&k);
          return GF_ERR_ENCODING;
        }
      param[0] = 80;
      param[1] = k.passes;
      param[2] = k.mem;
      param[3] = k.lanes;
      if (gcry_kdf_open (&kh, GCRY_KDF_ARGON2, sub, param, 4, passphrase,
                         strlen (passphrase), k.salt, k.saltn, NULL, 0, NULL, 0))
        {
          ppk_free (&k);
          return GF_ERR_CRYPTO;
        }
      if (gcry_kdf_compute (kh, NULL) || gcry_kdf_final (kh, 80, derived))
        rc = GF_ERR_CRYPTO;
      gcry_kdf_close (kh);
      if (rc != GF_OK)
        {
          ppk_free (&k);
          return rc;
        }
      /* AES-256-CBC with the first 32 bytes and the next 16 as IV; the last
         32 bytes key the MAC.  */
      if (gcry_cipher_open (&ch, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0))
        rc = GF_ERR_CRYPTO;
      else
        {
          if (gcry_cipher_setkey (ch, derived, 32)
              || gcry_cipher_setiv (ch, derived + 32, 16)
              || gcry_cipher_decrypt (ch, k.priv, k.privlen, NULL, 0))
            rc = GF_ERR_CRYPTO;
          gcry_cipher_close (ch);
        }
      if (rc != GF_OK)
        {
          gf_wipe (derived, sizeof derived);
          ppk_free (&k);
          return rc;
        }
      macwith = derived + 48;
      macn = 32;
    }
  rc = ppk_mac (&k, macwith, macn, mac);
  if (rc == GF_OK && !gf_ct_equal (mac, k.mac, 32))
    rc = enc ? GF_ERR_PASSPHRASE : GF_ERR_ENCODING;
  gf_wipe (derived, sizeof derived);
  if (rc != GF_OK)
    {
      ppk_free (&k);
      return rc;
    }

  /* The public blob must be of the type the header says.  */
  gf_reader_init (&pr, k.pub, k.publen);
  if (gf_rd_string (&pr, &alg) != GF_OK || alg.len != k.algn
      || memcmp (alg.data, k.alg, k.algn) != 0)
    {
      ppk_free (&k);
      return GF_ERR_ENCODING;
    }
  rc = gf_key_from_blob (&key, k.pub, k.publen);
  if (rc != GF_OK || gf_key_is_certificate (key))
    {
      gf_key_free (key);
      ppk_free (&k);
      return rc != GF_OK ? rc : GF_ERR_UNSUPPORTED;
    }
  (void) blob;
  gf_reader_init (&rr, k.priv, k.privlen);
  switch (gf_key_type (key))
    {
    case GF_KEY_ED25519:
      if (gf_rd_string (&rr, &s1) != GF_OK || s1.len != 32)
        rc = GF_ERR_ENCODING;
      else
        {
          const uint8_t *pb;
          size_t pl;
          gf_reader br;

          pb = gf_key_blob (key, &pl);
          gf_reader_init (&br, pb, pl);
          if (gf_rd_string (&br, &s2) != GF_OK || gf_rd_string (&br, &s3) != GF_OK
              || s3.len != 32)
            rc = GF_ERR_ENCODING;
          else
            rc = gfi_key_attach_private (key, s3.data, 32, NULL, s1.data, NULL,
                                         NULL, NULL, NULL);
        }
      break;
    case GF_KEY_RSA:
      {
        gf_slice d, p, q, iq;
        gcry_mpi_t dm, pm, qm, nm, em;
        const uint8_t *pb;
        size_t pl;
        gf_reader br;
        gf_slice e, n;

        if (gf_rd_mpint (&rr, &d) != GF_OK || gf_rd_mpint (&rr, &p) != GF_OK
            || gf_rd_mpint (&rr, &q) != GF_OK || gf_rd_mpint (&rr, &iq) != GF_OK)
          {
            rc = GF_ERR_ENCODING;
            break;
          }
        pb = gf_key_blob (key, &pl);
        gf_reader_init (&br, pb, pl);
        if (gf_rd_string (&br, &s1) != GF_OK || gf_rd_mpint (&br, &e) != GF_OK
            || gf_rd_mpint (&br, &n) != GF_OK)
          {
            rc = GF_ERR_ENCODING;
            break;
          }
        dm = gfi_mpi_from (d.data, d.len);
        pm = gfi_mpi_from (p.data, p.len);
        qm = gfi_mpi_from (q.data, q.len);
        nm = gfi_mpi_from (n.data, n.len);
        em = gfi_mpi_from (e.data, e.len);
        if (dm && pm && qm && nm && em)
          rc = gfi_key_attach_private (key, NULL, 0, dm, NULL, nm, em, pm, qm);
        else
          rc = GF_ERR_NOMEM;
        gcry_mpi_release (dm);
        gcry_mpi_release (pm);
        gcry_mpi_release (qm);
        gcry_mpi_release (nm);
        gcry_mpi_release (em);
      }
      break;
    default:
      {
        gf_slice d, q;
        gcry_mpi_t dm;
        const uint8_t *pb;
        size_t pl;
        gf_reader br;

        if (gf_rd_mpint (&rr, &d) != GF_OK)
          {
            rc = GF_ERR_ENCODING;
            break;
          }
        pb = gf_key_blob (key, &pl);
        gf_reader_init (&br, pb, pl);
        if (gf_rd_string (&br, &s1) != GF_OK || gf_rd_string (&br, &s2) != GF_OK
            || gf_rd_string (&br, &q) != GF_OK)
          {
            rc = GF_ERR_ENCODING;
            break;
          }
        dm = gfi_mpi_from (d.data, d.len);
        if (dm == NULL)
          rc = GF_ERR_NOMEM;
        else
          rc = gfi_key_attach_private (key, q.data, q.len, dm, NULL, NULL, NULL,
                                       NULL, NULL);
        gcry_mpi_release (dm);
      }
      break;
    }
  if (rc == GF_OK)
    {
      set_comment (comment, cap, k.comment, k.commentn);
      *out = key;
    }
  else
    gf_key_free (key);
  ppk_free (&k);
  return rc;
}
