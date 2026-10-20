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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>
#include <foxtrot/x509.h>

#include "internal.h"
#include "keyint.h"

void
gfi_x509_free (struct gf_x509 *x)
{
  size_t i;

  if (x == NULL)
    return;
  for (i = 0; i < x->n; i++)
    free (x->der[i]);
  free (x);
}

size_t
gf_x509_chain_length (const gf_key *k)
{
  return k && k->x509 ? k->x509->n : 0;
}

int
gf_x509_chain_cert (const gf_key *k, size_t i, const uint8_t **der, size_t *len)
{
  if (k == NULL || k->x509 == NULL || i >= k->x509->n || der == NULL
      || len == NULL)
    return GF_ERR_INVAL;
  *der = k->x509->der[i];
  *len = k->x509->len[i];
  return GF_OK;
}

#ifdef HAVE_GNUTLS

#define MAX_DER 16384
#define MAX_OCSP 8
#define MAX_OCSP_LEN 16384
#define OID_SSH_SERVER "1.3.6.1.5.5.7.3.22"
#define OID_SSH_CLIENT "1.3.6.1.5.5.7.3.21"

static int
import_crt (gnutls_x509_crt_t *crt, const uint8_t *der, size_t len)
{
  gnutls_datum_t d;

  if (len == 0 || len > MAX_DER || gnutls_x509_crt_init (crt) != 0)
    return GF_ERR_ENCODING;
  d.data = (unsigned char *) (uintptr_t) der;
  d.size = (unsigned) len;
  if (gnutls_x509_crt_import (*crt, &d, GNUTLS_X509_FMT_DER) != 0)
    {
      gnutls_x509_crt_deinit (*crt);
      *crt = NULL;
      return GF_ERR_ENCODING;
    }
  return GF_OK;
}

/* Left-pad N bytes of V to WIDTH.  */
static int
put_padded (const gnutls_datum_t *v, size_t width, uint8_t *tmp)
{
  const uint8_t *p = v->data;
  size_t n = v->size;

  while (n > width && *p == 0)
    p++, n--;
  if (n > width)
    return 0;
  memset (tmp, 0, width - n);
  memcpy (tmp + width - n, p, n);
  return 1;
}

/* The plain SSH public key blob of the key in CRT, for the algorithm ALG.  */
static int
plain_blob (gnutls_x509_crt_t crt, enum gf_sigalg alg, uint8_t *buf, size_t cap,
            size_t *outlen)
{
  gf_writer w;
  unsigned bits = 0;
  int pk = gnutls_x509_crt_get_pk_algorithm (crt, &bits);

  gf_writer_init (&w, buf, cap);
  if (alg == GF_SIG_X509_RSA2048_SHA256)
    {
      gnutls_datum_t m, e;

      if (pk != GNUTLS_PK_RSA || gnutls_x509_crt_get_pk_rsa_raw (crt, &m, &e) != 0)
        return GF_ERR_UNSUPPORTED;
      gf_wr_cstring (&w, "ssh-rsa");
      gf_wr_mpint (&w, e.data, e.size);
      gf_wr_mpint (&w, m.data, m.size);
      gnutls_free (m.data);
      gnutls_free (e.data);
    }
  else
    {
      gnutls_ecc_curve_t curve;
      gnutls_datum_t x, y;
      size_t width = alg == GF_SIG_X509_ECDSA_NISTP256 ? 32 : 48;
      uint8_t pt[1 + 2 * 48];
      int rc = GF_OK;

      if (pk != GNUTLS_PK_ECDSA
          || gnutls_x509_crt_get_pk_ecc_raw (crt, &curve, &x, &y) != 0)
        return GF_ERR_UNSUPPORTED;
      if (curve != (alg == GF_SIG_X509_ECDSA_NISTP256
                    ? GNUTLS_ECC_CURVE_SECP256R1 : GNUTLS_ECC_CURVE_SECP384R1))
        rc = GF_ERR_UNSUPPORTED;
      else if (!put_padded (&x, width, pt + 1)
               || !put_padded (&y, width, pt + 1 + width))
        rc = GF_ERR_ENCODING;
      gnutls_free (x.data);
      gnutls_free (y.data);
      if (rc != GF_OK)
        return rc;
      pt[0] = 4;
      gf_wr_cstring (&w, alg == GF_SIG_X509_ECDSA_NISTP256
                     ? "ecdsa-sha2-nistp256" : "ecdsa-sha2-nistp384");
      gf_wr_cstring (&w, alg == GF_SIG_X509_ECDSA_NISTP256 ? "nistp256" : "nistp384");
      gf_wr_string (&w, pt, 1 + 2 * width);
    }
  if (gf_wr_status (&w) != GF_OK)
    return GF_ERR_ENCODING;
  *outlen = w.len;
  return GF_OK;
}

int
gfi_x509_parse (gf_key **out, const uint8_t *blob, size_t len, gf_slice name)
{
  gf_reader r;
  gf_slice a, der;
  uint32_t count, ocsp, i;
  enum gf_sigalg alg = gf_sigalg_from_name ((const char *) name.data, name.len);
  struct gf_x509 *x = NULL;
  gnutls_x509_crt_t crt = NULL;
  uint8_t plain[1024];
  size_t plen = 0;
  gf_key *k = NULL;
  uint8_t *copy = NULL;
  int rc;

  if (out == NULL || !gf_sigalg_is_x509 (alg))
    return GF_ERR_UNSUPPORTED;
  rc = gf_crypto_init ();
  if (rc != GF_OK)
    return rc;
  gf_reader_init (&r, blob, len);
  if (gf_rd_string (&r, &a) != GF_OK || gf_rd_u32 (&r, &count) != GF_OK
      || count < 1 || count > GFI_X509_MAX_CHAIN)
    return GF_ERR_ENCODING;
  x = calloc (1, sizeof *x);
  if (x == NULL)
    return GF_ERR_NOMEM;
  for (i = 0; i < count; i++)
    {
      gnutls_x509_crt_t c = NULL;

      if (gf_rd_string (&r, &der) != GF_OK)
        goto bad_encoding;
      /* Every certificate must be one.  */
      if (import_crt (&c, der.data, der.len) != GF_OK)
        goto bad_encoding;
      if (i == 0)
        crt = c;
      else
        gnutls_x509_crt_deinit (c);
      x->der[i] = malloc (der.len);
      if (x->der[i] == NULL)
        {
          rc = GF_ERR_NOMEM;
          goto fail;
        }
      memcpy (x->der[i], der.data, der.len);
      x->len[i] = der.len;
      x->n = i + 1;
    }
  /* OCSP responses: well formed, and left alone.  */
  if (gf_rd_u32 (&r, &ocsp) != GF_OK || ocsp > MAX_OCSP)
    goto bad_encoding;
  for (i = 0; i < ocsp; i++)
    if (gf_rd_string (&r, &der) != GF_OK || der.len > MAX_OCSP_LEN)
      goto bad_encoding;
  if (gf_rd_finish (&r) != GF_OK)
    goto bad_encoding;

  rc = plain_blob (crt, alg, plain, sizeof plain, &plen);
  if (rc != GF_OK)
    goto fail;
  /* The key must be one the policy takes (point on the curve, RSA at least
     2048 bits, odd exponent) and an ECDSA/RSA type that matches the name.  */
  rc = gf_key_from_blob (&k, plain, plen);
  if (rc != GF_OK)
    goto fail;
  copy = malloc (len);
  if (copy == NULL)
    {
      rc = GF_ERR_NOMEM;
      goto fail;
    }
  memcpy (copy, blob, len);
  k->plain = k->blob;
  k->plainlen = k->bloblen;
  k->blob = copy;
  k->bloblen = len;
  k->x509 = x;
  gnutls_x509_crt_deinit (crt);
  *out = k;
  return GF_OK;

bad_encoding:
  rc = GF_ERR_ENCODING;
fail:
  if (crt)
    gnutls_x509_crt_deinit (crt);
  gf_key_free (k);
  gfi_x509_free (x);
  return rc;
}

/* ---- keys with a chain ---- */

int
gf_key_with_x509 (const gf_key *key, const uint8_t *const *certs,
                  const size_t *lens, size_t n, gf_key **out)
{
  uint8_t *buf;
  size_t cap = 64, i, pl;
  const char *name;
  gf_writer w;
  gf_key *k = NULL;
  const uint8_t *pb;
  int rc;

  if (key == NULL || certs == NULL || lens == NULL || out == NULL || n < 1
      || n > GFI_X509_MAX_CHAIN || key->priv == NULL || key->cert != NULL
      || key->app != NULL || key->x509 != NULL)
    return GF_ERR_INVAL;
  switch (key->type)
    {
    case GF_KEY_ECDSA_P256:
      name = "x509v3-ecdsa-sha2-nistp256";
      break;
    case GF_KEY_ECDSA_P384:
      name = "x509v3-ecdsa-sha2-nistp384";
      break;
    case GF_KEY_RSA:
      name = "x509v3-rsa2048-sha256";
      break;
    default:
      return GF_ERR_UNSUPPORTED;
    }
  for (i = 0; i < n; i++)
    {
      if (certs[i] == NULL || lens[i] == 0 || lens[i] > MAX_DER)
        return GF_ERR_INVAL;
      cap += lens[i] + 4;
    }
  buf = malloc (cap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, cap);
  gf_wr_cstring (&w, name);
  gf_wr_u32 (&w, (uint32_t) n);
  for (i = 0; i < n; i++)
    gf_wr_string (&w, certs[i], lens[i]);
  gf_wr_u32 (&w, 0);
  if (gf_wr_status (&w) != GF_OK)
    {
      free (buf);
      return GF_ERR_BUFSIZE;
    }
  rc = gf_key_from_blob (&k, buf, w.len);
  free (buf);
  if (rc != GF_OK)
    return rc;
  pb = gf_key_blob (key, &pl);
  if (k->plainlen != pl || memcmp (k->plain, pb, pl) != 0)
    {
      gf_key_free (k);
      return GF_ERR_INVAL;		/* The certificate is for another key.  */
    }
  k->priv = gcry_sexp_find_token (key->priv, "private-key", 0);
  if (k->priv == NULL)
    {
      gf_key_free (k);
      return GF_ERR_CRYPTO;
    }
  *out = k;
  return GF_OK;
}

/* ---- trust ---- */

struct gf_x509_trust
{
  gnutls_x509_trust_list_t list;
  gnutls_x509_crt_t *cas;
  size_t nca;
};

int
gf_x509_trust_new (gf_x509_trust **out)
{
  gf_x509_trust *t;

  if (out == NULL)
    return GF_ERR_INVAL;
  t = calloc (1, sizeof *t);
  if (t == NULL)
    return GF_ERR_NOMEM;
  if (gnutls_x509_trust_list_init (&t->list, 0) != 0)
    {
      free (t);
      return GF_ERR_CRYPTO;
    }
  *out = t;
  return GF_OK;
}

void
gf_x509_trust_free (gf_x509_trust *t)
{
  size_t i;

  if (t == NULL)
    return;
  for (i = 0; i < t->nca; i++)
    gnutls_x509_crt_deinit (t->cas[i]);
  free (t->cas);
  gnutls_x509_trust_list_deinit (t->list, 1);
  free (t);
}

int
gf_x509_trust_add_ca (gf_x509_trust *t, const uint8_t *der, size_t len)
{
  gnutls_x509_crt_t c = NULL, c2 = NULL, *p;
  int rc;

  if (t == NULL || der == NULL)
    return GF_ERR_INVAL;
  rc = import_crt (&c, der, len);
  if (rc != GF_OK)
    return rc;
  /* The list owns the certificate it is given; we keep one of our own for
     the dates of the CA.  */
  rc = import_crt (&c2, der, len);
  if (rc != GF_OK)
    {
      gnutls_x509_crt_deinit (c);
      return rc;
    }
  p = realloc (t->cas, (t->nca + 1) * sizeof *p);
  if (p == NULL)
    {
      gnutls_x509_crt_deinit (c);
      gnutls_x509_crt_deinit (c2);
      return GF_ERR_NOMEM;
    }
  t->cas = p;
  if (gnutls_x509_trust_list_add_cas (t->list, &c, 1, 0) != 1)
    {
      gnutls_x509_crt_deinit (c);
      gnutls_x509_crt_deinit (c2);
      return GF_ERR_CRYPTO;
    }
  t->cas[t->nca++] = c2;
  return GF_OK;
}

int
gf_x509_trust_add_crl (gf_x509_trust *t, const uint8_t *der, size_t len)
{
  gnutls_x509_crl_t crl;
  gnutls_datum_t d;
  int r;

  if (t == NULL || der == NULL || len == 0 || len > 1048576)
    return GF_ERR_INVAL;
  if (gnutls_x509_crl_init (&crl) != 0)
    return GF_ERR_NOMEM;
  d.data = (unsigned char *) (uintptr_t) der;
  d.size = (unsigned) len;
  if (gnutls_x509_crl_import (crl, &d, GNUTLS_X509_FMT_DER) != 0)
    {
      gnutls_x509_crl_deinit (crl);
      return GF_ERR_ENCODING;
    }
  /* The list takes the CRL on success, after checking who signed it.  */
  r = gnutls_x509_trust_list_add_crls (t->list, &crl, 1,
                                       GNUTLS_TL_VERIFY_CRL, 0);
  if (r != 1)
    {
      gnutls_x509_crl_deinit (crl);
      return GF_ERR_HOSTKEY;
    }
  return GF_OK;
}

static int
in_dates (gnutls_x509_crt_t c, uint64_t now, const char **why)
{
  time_t act = gnutls_x509_crt_get_activation_time (c);
  time_t exp = gnutls_x509_crt_get_expiration_time (c);

  if (act == (time_t) -1 || exp == (time_t) -1)
    {
      *why = "unreadable validity";
      return 0;
    }
  if (act > 0 && now < (uint64_t) act)
    {
      *why = "not yet valid";
      return 0;
    }
  if (exp != GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION && now >= (uint64_t) exp)
    {
      *why = "expired";
      return 0;
    }
  return 1;
}

/* A dNSName from a certificate against a host name: case-blind, and a
   "*." in front covers exactly one label.  */
static int
dns_match (const char *pat, const char *host)
{
  size_t pl = strlen (pat), hl = strlen (host), i;

  if (pl >= 2 && pat[0] == '*' && pat[1] == '.')
    {
      const char *dot = strchr (host, '.');

      if (dot == NULL || dot == host)
        return 0;
      pat += 1;
      pl -= 1;
      host = dot;
      hl = strlen (host);
      /* "*.com" is no wildcard anyone should honour: at least two labels
         must follow the star.  */
      if (strchr (pat + 1, '.') == NULL)
        return 0;
    }
  else if (strchr (pat, '*') != NULL)
    return 0;
  if (pl != hl)
    return 0;
  for (i = 0; i < pl; i++)
    {
      char a = pat[i], b = host[i];

      if (a >= 'A' && a <= 'Z')
        a = (char) (a - 'A' + 'a');
      if (b >= 'A' && b <= 'Z')
        b = (char) (b - 'A' + 'a');
      if (a != b)
        return 0;
    }
  return 1;
}

static int
name_matches (gnutls_x509_crt_t crt, const char *name)
{
  unsigned char addr[16];
  int is4 = inet_pton (AF_INET, name, addr) == 1;
  int is6 = !is4 && inet_pton (AF_INET6, name, addr) == 1;
  unsigned i;

  for (i = 0;; i++)
    {
      char buf[512];
      size_t sz = sizeof buf;
      unsigned int crit;
      int t = gnutls_x509_crt_get_subject_alt_name2 (crt, i, buf, &sz,
                                                     NULL, &crit);

      if (t < 0)
        {
          if (t == GNUTLS_E_SHORT_MEMORY_BUFFER)
            continue;
          break;
        }
      if (t == GNUTLS_SAN_DNSNAME && !is4 && !is6 && sz > 0
          && strlen (buf) == sz && dns_match (buf, name))
        return 1;
      if (t == GNUTLS_SAN_IPADDRESS
          && ((is4 && sz == 4) || (is6 && sz == 16))
          && memcmp (buf, addr, sz) == 0)
        return 1;
    }
  return 0;
}

int
gf_x509_verify (const gf_x509_trust *t, const gf_key *key, int purpose,
                const char *name, uint64_t now, const char **why)
{
  gnutls_x509_crt_t crt[GFI_X509_MAX_CHAIN];
  size_t n = 0, i;
  const char *w = NULL;
  unsigned int status = 0;
  gnutls_typed_vdata_st vd;
  char oid[32];
  int r = GF_ERR_HOSTKEY, ok = 0;
  unsigned int ku;
  unsigned int crit;

  if (why)
    *why = NULL;
  if (t == NULL || key == NULL || key->x509 == NULL
      || (purpose != GF_X509_SERVER && purpose != GF_X509_CLIENT))
    return GF_ERR_INVAL;
  for (i = 0; i < key->x509->n; i++)
    {
      if (import_crt (&crt[i], key->x509->der[i], key->x509->len[i]) != GF_OK)
        {
          w = "unreadable certificate";
          goto out;
        }
      n++;
    }
  /* Dates by our clock, not the system's, for every certificate and for the
     CA that vouches for the last one.  */
  for (i = 0; i < n; i++)
    if (!in_dates (crt[i], now, &w))
      goto out;
  vd.type = GNUTLS_DT_KEY_PURPOSE_OID;
  snprintf (oid, sizeof oid, "%s", purpose == GF_X509_SERVER ? OID_SSH_SERVER
                                                            : OID_SSH_CLIENT);
  vd.data = (unsigned char *) oid;
  vd.size = (unsigned) strlen (oid);
  if (gnutls_x509_trust_list_verify_crt2 (t->list, crt, (unsigned) n, &vd, 1,
        GNUTLS_VERIFY_DISABLE_TIME_CHECKS | GNUTLS_VERIFY_DO_NOT_ALLOW_UNSORTED_CHAIN
        | GNUTLS_PROFILE_TO_VFLAGS (GNUTLS_PROFILE_MEDIUM),
        &status, NULL) != 0)
    {
      w = "chain could not be checked";
      goto out;
    }
  if (status != 0)
    {
      if (status & GNUTLS_CERT_REVOKED)
        w = "revoked";
      else if (status & GNUTLS_CERT_PURPOSE_MISMATCH)
        w = "not for this purpose";
      else if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
        w = "weak algorithm";
      else if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
        w = "unknown signer";
      else if (status & GNUTLS_CERT_SIGNER_NOT_CA)
        w = "signer is not a CA";
      else
        w = "chain not trusted";
      goto out;
    }
  /* The CA's dates: some CA in the store that issued the last certificate
     and is itself in its dates.  (GnuTLS found the chain trusted; time was
     left to us.)  */
  {
    int found = 0;
    const char *cw = "no valid CA";

    for (i = 0; i < t->nca && !found; i++)
      {
        unsigned int st = 0;

        if (gnutls_x509_crt_check_issuer (crt[n - 1], t->cas[i]) <= 0)
          continue;
        if (gnutls_x509_crt_verify (crt[n - 1], &t->cas[i], 1,
                                    GNUTLS_VERIFY_DISABLE_TIME_CHECKS, &st) != 0
            || st != 0)
          continue;
        if (in_dates (t->cas[i], now, &cw))
          found = 1;
      }
    if (!found)
      {
        w = cw;
        goto out;
      }
  }
  /* The end certificate's own purposes, if it lists any, must name this one:
     GnuTLS lets "any" pass for everything, and here it does not.  */
  {
    int have = 0, mine = 0;
    unsigned idx;

    for (idx = 0;; idx++)
      {
        char eoid[64];
        size_t osz = sizeof eoid;
        unsigned int c2;
        int er = gnutls_x509_crt_get_key_purpose_oid (crt[0], (int) idx, eoid,
                                                      &osz, &c2);

        if (er < 0)
          break;
        have = 1;
        if (strcmp (eoid, oid) == 0)
          mine = 1;
      }
    if (have && !mine)
      {
        w = "not for this purpose";
        goto out;
      }
  }
  /* The key may sign, if it says what it may do.  */
  if (gnutls_x509_crt_get_key_usage (crt[0], &ku, &crit) >= 0
      && !(ku & GNUTLS_KEY_DIGITAL_SIGNATURE))
    {
      w = "key usage lacks digitalSignature";
      goto out;
    }
  if (purpose == GF_X509_SERVER && name != NULL && !name_matches (crt[0], name))
    {
      w = "name does not match";
      goto out;
    }
  ok = 1;
out:
  for (i = 0; i < n; i++)
    gnutls_x509_crt_deinit (crt[i]);
  if (ok)
    return GF_OK;
  if (why)
    *why = w ? w : "chain not trusted";
  return r;
}

int
gf_x509_subject (const gf_key *key, char *out, size_t cap)
{
  gnutls_x509_crt_t crt;
  gnutls_datum_t d;
  int rc;

  if (key == NULL || key->x509 == NULL || out == NULL || cap == 0)
    return GF_ERR_INVAL;
  rc = import_crt (&crt, key->x509->der[0], key->x509->len[0]);
  if (rc != GF_OK)
    return rc;
  if (gnutls_x509_crt_get_dn3 (crt, &d, 0) != 0)
    {
      gnutls_x509_crt_deinit (crt);
      return GF_ERR_ENCODING;
    }
  if (d.size + 1 > cap)
    rc = GF_ERR_BUFSIZE;
  else
    {
      memcpy (out, d.data, d.size);
      out[d.size] = '\0';
    }
  gnutls_free (d.data);
  gnutls_x509_crt_deinit (crt);
  return rc;
}

int
gf_x509_san (const gf_key *key, size_t *pos, int *type, char *out, size_t cap)
{
  gnutls_x509_crt_t crt;
  int found = 0;

  if (key == NULL || key->x509 == NULL || pos == NULL || type == NULL
      || out == NULL || cap < 2)
    return 0;
  if (import_crt (&crt, key->x509->der[0], key->x509->len[0]) != GF_OK)
    return 0;
  while (!found)
    {
      char buf[512];
      size_t sz = sizeof buf - 1;
      unsigned int crit;
      int t = gnutls_x509_crt_get_subject_alt_name2 (crt, (unsigned) *pos, buf, &sz,
                                                     NULL, &crit);
      int ours = 0;

      if (t < 0 && t != GNUTLS_E_SHORT_MEMORY_BUFFER)
        break;
      (*pos)++;
      if (t < 0)
        continue;
      buf[sz] = '\0';
      switch (t)
        {
        case GNUTLS_SAN_DNSNAME: ours = GF_X509_SAN_DNS; break;
        case GNUTLS_SAN_RFC822NAME: ours = GF_X509_SAN_EMAIL; break;
        case GNUTLS_SAN_URI: ours = GF_X509_SAN_URI; break;
        case GNUTLS_SAN_IPADDRESS:
          {
            char text[64];

            if ((sz == 4 && inet_ntop (AF_INET, buf, text, sizeof text))
                || (sz == 16 && inet_ntop (AF_INET6, buf, text, sizeof text)))
              {
                snprintf (buf, sizeof buf, "%s", text);
                ours = GF_X509_SAN_IP;
              }
            break;
          }
        case GNUTLS_SAN_OTHERNAME_MSUSERPRINCIPAL: ours = GF_X509_SAN_UPN; break;
        default: break;
        }
      if (ours && strlen (buf) + 1 <= cap)
        {
          memcpy (out, buf, strlen (buf) + 1);
          *type = ours;
          found = 1;
        }
    }
  gnutls_x509_crt_deinit (crt);
  return found;
}

#else /* !HAVE_GNUTLS */

int
gfi_x509_parse (gf_key **out, const uint8_t *blob, size_t len, gf_slice name)
{
  (void) out;
  (void) blob;
  (void) len;
  (void) name;
  return GF_ERR_UNAVAILABLE;
}

int
gf_key_with_x509 (const gf_key *key, const uint8_t *const *certs,
                  const size_t *lens, size_t n, gf_key **out)
{
  (void) key;
  (void) certs;
  (void) lens;
  (void) n;
  (void) out;
  return GF_ERR_UNAVAILABLE;
}

int
gf_x509_trust_new (gf_x509_trust **out)
{
  (void) out;
  return GF_ERR_UNAVAILABLE;
}

void
gf_x509_trust_free (gf_x509_trust *t)
{
  (void) t;
}

int
gf_x509_trust_add_ca (gf_x509_trust *t, const uint8_t *der, size_t len)
{
  (void) t;
  (void) der;
  (void) len;
  return GF_ERR_UNAVAILABLE;
}

int
gf_x509_trust_add_crl (gf_x509_trust *t, const uint8_t *der, size_t len)
{
  (void) t;
  (void) der;
  (void) len;
  return GF_ERR_UNAVAILABLE;
}

int
gf_x509_verify (const gf_x509_trust *t, const gf_key *key, int purpose,
                const char *name, uint64_t now, const char **why)
{
  (void) t;
  (void) key;
  (void) purpose;
  (void) name;
  (void) now;
  (void) why;
  return GF_ERR_UNAVAILABLE;
}

int
gf_x509_subject (const gf_key *key, char *out, size_t cap)
{
  (void) key;
  (void) out;
  (void) cap;
  return GF_ERR_UNAVAILABLE;
}

int
gf_x509_san (const gf_key *key, size_t *pos, int *type, char *out, size_t cap)
{
  (void) key;
  (void) pos;
  (void) type;
  (void) out;
  (void) cap;
  return 0;
}

#endif
