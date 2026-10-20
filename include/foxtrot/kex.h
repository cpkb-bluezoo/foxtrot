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

/* Key exchange (RFC 4253 section 8, RFC 5656, RFC 8731 and the hybrid
   drafts), as computations on byte strings.

   This is the cryptography of a key exchange without its messages: the
   ephemeral values that go in SSH_MSG_KEX_ECDH_INIT and _REPLY (called
   KEX_HYBRID_INIT and _REPLY for the hybrid methods; both are messages 30
   and 31), the shared secret K, the exchange hash H, and the derivation
   of keys from them.  conn.h drives the message flow.

   The methods are those of policy.h.  Each has a client value (Q_C, the
   "init" value) and a server value (Q_S, the "reply" value):

     curve25519-sha256        X25519 public key, 32 bytes
     ecdh-sha2-nistp256/384   uncompressed point, 65 / 97 bytes
     hybrids                  the post-quantum part first (the KEM public
                              key from the client, the ciphertext from the
                              server), then the classical part

   K is an mpint for the plain methods and a string (the hash of the two
   shared secrets) for the hybrids; gf_kex_secret remembers which.  */

#ifndef FOXTROT_KEX_H
#define FOXTROT_KEX_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The largest init and reply values of any method (mlkem1024nistp384).  */
#define GF_KEX_MAX_INIT 1700
#define GF_KEX_MAX_REPLY 1700
#define GF_KEX_MAX_HASH 64

typedef struct gf_kex_secret
{
  uint8_t data[64];
  size_t len;
  int as_string;		/* K is encoded as a string, else an mpint.  */
} gf_kex_secret;

/* The hash of the method (SHA-256, SHA-384 or SHA-512): of the exchange
   hash and of the key derivation.  */
enum gf_hash gf_kex_hash (enum gf_kex kex);

/* Sizes of the init and reply values.  0 for an unknown method.  */
size_t gf_kex_init_len (enum gf_kex kex);
size_t gf_kex_reply_len (enum gf_kex kex);

/* Client side: an ephemeral key pair.  */
typedef struct gf_kex_client gf_kex_client;

/* Generate the ephemeral key and write Q_C to INIT.  */
int gf_kex_client_start (gf_kex_client **out, enum gf_kex kex, uint8_t *init,
                         size_t cap, size_t *initlen);
/* Complete from the server's Q_S.  Fails if it is the wrong length or an
   invalid value, or yields a degenerate shared secret.  */
int gf_kex_client_finish (gf_kex_client *c, const uint8_t *reply, size_t len,
                          gf_kex_secret *k);
void gf_kex_client_free (gf_kex_client *c);

/* Server side, in one step: from Q_C produce Q_S and K.  */
int gf_kex_server_respond (enum gf_kex kex, const uint8_t *init, size_t len,
                           uint8_t *reply, size_t cap, size_t *replylen,
                           gf_kex_secret *k);

/* The inputs of the exchange hash.  V_C, V_S are the identification
   lines without CR LF, I_C, I_S the KEXINIT payloads (including the
   message number), K_S the server's host key blob.  Writes
   gf_hash_size (gf_kex_hash (KEX)) bytes to H.  */
struct gf_kex_transcript
{
  gf_slice v_c, v_s, i_c, i_s, k_s, q_c, q_s;
};

int gf_kex_exchange_hash (enum gf_kex kex, const struct gf_kex_transcript *t,
                          const gf_kex_secret *k, uint8_t *h, size_t hlen);

/* RFC 4253 section 7.2: derive OUTLEN bytes for the key or IV named
   LETTER ('A' to 'F').  SESSION_ID is the first exchange hash of the
   connection.  */
int gf_kex_derive (enum gf_hash alg, const gf_kex_secret *k, const uint8_t *h,
                   size_t hlen, const uint8_t *session_id, size_t sidlen,
                   char letter, uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_KEX_H */
