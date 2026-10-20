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

/* The representation of a key, shared by key.c and cert.c.  Not exported.  */

#ifndef GF_KEYINT_H
#define GF_KEYINT_H

#include <stddef.h>
#include <stdint.h>

#include <gcrypt.h>

#include <foxtrot/key.h>
#include <foxtrot/wire.h>

/* An OpenSSH certificate (PROTOCOL.certkeys).  The slices point into the
   key's blob, which is the certificate itself.  */
struct gf_cert
{
  uint64_t serial;
  uint32_t type;		/* 1: user, 2: host.  */
  gf_slice key_id;
  gf_slice principals;		/* Packed strings.  */
  uint64_t valid_after, valid_before;
  gf_slice critical;		/* Packed (name, data) string pairs.  */
  gf_slice extensions;
  gf_key *ca;			/* The key that signed it.  */
};

/* An X.509 chain (RFC 6187): the DER of each certificate, the end
   certificate first.  The key's blob is the RFC 6187 public key.  */
#define GFI_X509_MAX_CHAIN 8
#define GFI_X509_MAX_OCSP 8
struct gf_x509
{
  size_t n;
  uint8_t *der[GFI_X509_MAX_CHAIN];
  size_t len[GFI_X509_MAX_CHAIN];
  /* OCSP responses that came with the chain (stapled), DER.  */
  size_t nocsp;
  uint8_t *ocsp[GFI_X509_MAX_OCSP];
  size_t ocsplen[GFI_X509_MAX_OCSP];
};

struct gf_key
{
  enum gf_keytype type;		/* Of the key itself, certificate or not.  */
  unsigned bits;
  uint8_t *blob;		/* What goes on the wire: the certificate for
				   a certificate.  */
  size_t bloblen;
  uint8_t *plain;		/* A certificate's key as a plain blob.  */
  size_t plainlen;
  gcry_sexp_t pub;
  gcry_sexp_t priv;		/* NULL for a public key.  */
  struct gf_cert *cert;
  uint8_t *app;			/* A security key's application, else NULL.  */
  size_t applen;
  struct gf_x509 *x509;		/* An X.509 chain, else NULL.  */
};

/* Parse a certificate blob whose type name is NAME (already read), check
   its structure and its signature by the key inside, and return it as a
   key.  Defined in cert.c.  */
int gfi_cert_parse (gf_key **out, const uint8_t *blob, size_t len,
                    gf_slice name);
void gfi_cert_free (struct gf_cert *c);

/* The same for an RFC 6187 chain, named NAME (x509v3-...).  Defined in
   x509.c.  */
int gfi_x509_parse (gf_key **out, const uint8_t *blob, size_t len,
                    gf_slice name);
void gfi_x509_free (struct gf_x509 *x);

#endif /* GF_KEYINT_H */
