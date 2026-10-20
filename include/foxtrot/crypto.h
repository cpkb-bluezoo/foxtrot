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

/* Thin cryptographic layer.

   Every primitive (hash, random, ChaCha20, AES, Poly1305, GCM, X25519,
   ECDH, ML-KEM, sntrup761, EdDSA, ECDSA, RSA) is delegated to libgcrypt.
   This module holds only the helpers the rest of the library needs around
   them: initialization, random bytes, constant-time comparison, secret
   wiping and incremental hashing.  SSH-specific constructions live in
   packet.h (the binary packet protocol), kex.h (key exchange and key
   derivation) and key.h (host and user keys).

   There is deliberately no MD5 and no SHA-1 here, and no HMAC: SSH
   integrity comes from AEAD ciphers only.

   All functions return a gf_status.  Call gf_crypto_init once, before
   creating threads, or let the first use do it.  */

#ifndef FOXTROT_CRYPTO_H
#define FOXTROT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize libgcrypt if the application has not already done so.
   Idempotent.  Returns GF_OK or GF_ERR_CRYPTO (library too old).  */
int gf_crypto_init (void);

/* Fill BUF with LEN cryptographically strong random bytes.  */
int gf_random (void *buf, size_t len);

/* Constant-time comparison of two N-byte buffers: 1 if equal, else 0.
   Use for every comparison involving a MAC, tag or secret.  */
int gf_ct_equal (const void *a, const void *b, size_t n);

/* Overwrite SECRET with zeros in a way the compiler may not elide.  */
void gf_wipe (void *secret, size_t len);

/* ---- Hashes ---- */

enum gf_hash
{
  GF_HASH_SHA256 = 1,
  GF_HASH_SHA384,
  GF_HASH_SHA512
};

/* Digest length in bytes, or 0 for an unknown algorithm.  */
size_t gf_hash_size (enum gf_hash alg);

/* Hash DATA into OUT, which must be exactly gf_hash_size (ALG) bytes.  */
int gf_hash_compute (enum gf_hash alg, const void *data, size_t len,
                     uint8_t *out, size_t outlen);

/* An incremental hash, for the exchange hash and key derivation
   (RFC 4253 sections 7.2 and 8).  */
typedef struct gf_hash_ctx gf_hash_ctx;

int gf_hash_new (gf_hash_ctx **out, enum gf_hash alg);
int gf_hash_update (gf_hash_ctx *h, const void *data, size_t len);
/* The data written so far is encoded as an SSH string, uint32 or mpint,
   see wire.h; these save building the encoding in a buffer.  */
int gf_hash_update_u32 (gf_hash_ctx *h, uint32_t v);
int gf_hash_update_string (gf_hash_ctx *h, const void *data, size_t len);
/* DATA is a big-endian unsigned magnitude, which need not be minimal.  */
int gf_hash_update_mpint (gf_hash_ctx *h, const void *data, size_t len);
/* Finish and write the digest (exactly gf_hash_size bytes).  The context
   can no longer be updated, but may be freed.  */
int gf_hash_final (gf_hash_ctx *h, uint8_t *out, size_t outlen);
void gf_hash_free (gf_hash_ctx *h);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_CRYPTO_H */
