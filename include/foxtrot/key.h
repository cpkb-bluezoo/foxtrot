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

/* Host keys and user keys: SSH public key blobs (RFC 4253 section 6.6),
   signatures, and the unencrypted OpenSSH private key file format.

   Key types are Ed25519, ECDSA over NIST P-256 and P-384, and RSA of at
   least GF_MIN_RSA_BITS bits.  Everything is libgcrypt's; no X.509 is
   involved (RFC 6187 keys, if they come, will sit behind the same
   interface with the GnuTLS backend).

   What is refused, and where:
     - gf_key_from_blob refuses an RSA key under GF_MIN_RSA_BITS or over
       16384 bits, one with a public exponent under 65537 or even, an
       ECDSA point that is not on its curve or not in uncompressed form,
       and every key type not listed above (ssh-dss, ECDSA over P-521,
       certificates, security-key types).
     - gf_key_verify and gf_key_sign take the signature algorithm
       explicitly and refuse "ssh-rsa" (RSA with SHA-1): an RSA key signs
       with rsa-sha2-256 or rsa-sha2-512 only, and the signature blob must
       name the algorithm that was negotiated.
     - Ed25519 signatures with a non-canonical S are rejected.  */

#ifndef FOXTROT_KEY_H
#define FOXTROT_KEY_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/policy.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gf_keytype
{
  GF_KEY_ED25519 = 1,
  GF_KEY_ECDSA_P256,
  GF_KEY_ECDSA_P384,
  GF_KEY_RSA
};

#define GF_RSA_MAX_BITS 16384

typedef struct gf_key gf_key;

/* Generate a key.  BITS is used for RSA only (at least GF_MIN_RSA_BITS,
   default 3072 if 0).  */
int gf_key_generate (gf_key **out, enum gf_keytype type, unsigned bits);

/* Parse a public key blob.  The result has no private part.  */
int gf_key_from_blob (gf_key **out, const uint8_t *blob, size_t len);

/* Read an unencrypted OpenSSH private key file ("-----BEGIN OPENSSH
   PRIVATE KEY-----", the format of ssh-keygen -N ''), given as text.
   A passphrase-protected key is refused with GF_ERR_UNSUPPORTED; decrypt it
   first.  */
int gf_key_from_openssh_private (gf_key **out, const char *text, size_t len);

/* Write the private key in the same format, as PEM text.  */
int gf_key_to_openssh_private (const gf_key *key, char *out, size_t cap,
                               size_t *outlen);

void gf_key_free (gf_key *key);

enum gf_keytype gf_key_type (const gf_key *key);
unsigned gf_key_bits (const gf_key *key);
int gf_key_has_private (const gf_key *key);
/* The name in the key blob: "ssh-ed25519", "ecdsa-sha2-nistp256",
   "ecdsa-sha2-nistp384" or "ssh-rsa".  */
const char *gf_key_type_name (const gf_key *key);
/* The signature algorithms the key can make, in preference order.  *N
   receives the count.  */
const enum gf_sigalg *gf_key_sigalgs (const gf_key *key, size_t *n);

/* The public key blob.  The pointer is valid until the key is freed.  */
const uint8_t *gf_key_blob (const gf_key *key, size_t *len);

/* "SHA256:" and the unpadded base64 of the SHA-256 of the blob, as
   ssh-keygen -l prints it.  CAP must be at least 51.  */
int gf_key_fingerprint (const gf_key *key, char *out, size_t cap);

/* 1 if the two keys have the same public part.  */
int gf_key_equal (const gf_key *a, const gf_key *b);

/* Sign DATA with ALG.  The signature blob (RFC 4253 section 6.6: string
   algorithm name, string signature) is written to OUT.  The key must
   have a private part and ALG must belong to its type.  */
int gf_key_sign (const gf_key *key, enum gf_sigalg alg, const uint8_t *data,
                 size_t len, uint8_t *out, size_t cap, size_t *outlen);

/* Verify a signature blob on DATA.  The blob must carry the name of ALG.
   Returns GF_OK, or GF_ERR_HOSTKEY for a signature that does not verify
   or is malformed.  */
int gf_key_verify (const gf_key *key, enum gf_sigalg alg, const uint8_t *data,
                   size_t len, const uint8_t *sig, size_t siglen);

/* Largest signature blob a key of this size makes.  */
#define GF_SIG_MAX (4 + 19 + 4 + GF_RSA_MAX_BITS / 8)

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_KEY_H */
