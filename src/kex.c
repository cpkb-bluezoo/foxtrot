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
#include <foxtrot/kex.h>

#include "internal.h"

#define TRY(expr) do { int r_ = (expr); if (r_ != GF_OK) return r_; } while (0)

/* A method as its classical and post-quantum halves.  A plain method has
   no post-quantum half (pq_algo is 0).  */
struct method
{
  enum gf_kex kex;
  enum gf_hash hash;
  int ec_algo;			/* gcry_kem algo of the classical half.  */
  const char *curve;		/* NIST curve name, NULL for X25519.  */
  size_t ec_pub, ec_sec;	/* Public value and secret sizes.  */
  size_t ec_raw, ec_out;	/* Raw KEM shared size, and bytes we keep.  */
  int is_x25519;
  int pq_algo;
  size_t pq_pub, pq_sec, pq_ct;
};

static const struct method methods[] = {
  { GF_KEX_CURVE25519_SHA256, GF_HASH_SHA256,
    GCRY_KEM_RAW_X25519, NULL, 32, 32, 32, 32, 1, 0, 0, 0, 0 },
  { GF_KEX_ECDH_NISTP256_SHA256, GF_HASH_SHA256,
    GCRY_KEM_RAW_P256R1, "NIST P-256", 65, 32, 65, 32, 0, 0, 0, 0, 0 },
  { GF_KEX_ECDH_NISTP384_SHA384, GF_HASH_SHA384,
    GCRY_KEM_RAW_P384R1, "NIST P-384", 97, 48, 97, 48, 0, 0, 0, 0, 0 },
  { GF_KEX_MLKEM768X25519_SHA256, GF_HASH_SHA256,
    GCRY_KEM_RAW_X25519, NULL, 32, 32, 32, 32, 1,
    GCRY_KEM_MLKEM768, GCRY_KEM_MLKEM768_PUBKEY_LEN,
    GCRY_KEM_MLKEM768_SECKEY_LEN, GCRY_KEM_MLKEM768_CIPHER_LEN },
  { GF_KEX_MLKEM768NISTP256_SHA256, GF_HASH_SHA256,
    GCRY_KEM_RAW_P256R1, "NIST P-256", 65, 32, 65, 32, 0,
    GCRY_KEM_MLKEM768, GCRY_KEM_MLKEM768_PUBKEY_LEN,
    GCRY_KEM_MLKEM768_SECKEY_LEN, GCRY_KEM_MLKEM768_CIPHER_LEN },
  { GF_KEX_MLKEM1024NISTP384_SHA384, GF_HASH_SHA384,
    GCRY_KEM_RAW_P384R1, "NIST P-384", 97, 48, 97, 48, 0,
    GCRY_KEM_MLKEM1024, GCRY_KEM_MLKEM1024_PUBKEY_LEN,
    GCRY_KEM_MLKEM1024_SECKEY_LEN, GCRY_KEM_MLKEM1024_CIPHER_LEN },
  { GF_KEX_SNTRUP761X25519_SHA512, GF_HASH_SHA512,
    GCRY_KEM_RAW_X25519, NULL, 32, 32, 32, 32, 1,
    GCRY_KEM_SNTRUP761, GCRY_KEM_SNTRUP761_PUBKEY_LEN,
    GCRY_KEM_SNTRUP761_SECKEY_LEN, GCRY_KEM_SNTRUP761_CIPHER_LEN }
};

#define PQ_SS 32

static const struct method *
find_method (enum gf_kex kex)
{
  size_t i;

  for (i = 0; i < sizeof methods / sizeof methods[0]; i++)
    if (methods[i].kex == kex)
      return &methods[i];
  return NULL;
}

enum gf_hash
gf_kex_hash (enum gf_kex kex)
{
  const struct method *m = find_method (kex);

  return m ? m->hash : 0;
}

size_t
gf_kex_init_len (enum gf_kex kex)
{
  const struct method *m = find_method (kex);

  return m ? m->pq_pub + m->ec_pub : 0;
}

size_t
gf_kex_reply_len (enum gf_kex kex)
{
  const struct method *m = find_method (kex);

  return m ? m->pq_ct + m->ec_pub : 0;
}

static int
all_zero (const uint8_t *p, size_t n)
{
  uint8_t acc = 0;

  while (n--)
    acc |= *p++;
  return acc == 0;
}

/* The peer's classical public value must be a valid point (RFC 5656
   section 4); libgcrypt's ECDH takes anything.  X25519 accepts every
   32 bytes, and its low-order results are caught after the fact.  */
static int
ec_peer_ok (const struct method *m, const uint8_t *q)
{
  return m->curve == NULL || gfi_ec_point_ok (m->curve, q, m->ec_pub);
}

/* The classical shared secret from the KEM's raw output.  For the NIST
   curves libgcrypt returns the whole point (0x04 x y) and ECDH uses x
   alone (RFC 5656 section 4).  X25519 outputs are checked for the
   all-zero result a low-order point produces (RFC 7748 section 6.1).  */
static int
ec_extract (const struct method *m, const uint8_t *raw, uint8_t *out)
{
  if (m->is_x25519)
    {
      if (all_zero (raw, 32))
        return GF_ERR_CRYPTO;
      memcpy (out, raw, 32);
    }
  else
    {
      if (raw[0] != 0x04)
        return GF_ERR_CRYPTO;
      memcpy (out, raw + 1, m->ec_out);
    }
  return GF_OK;
}

/* K from the halves: the classical secret as an mpint for a plain
   method; for a hybrid, HASH (K_PQ || K_CL) as a string (the drafts'
   "K = HASH (K_PQ || K_CL)").  */
static int
combine (const struct method *m, const uint8_t *ec_ss, const uint8_t *pq_ss,
         gf_kex_secret *k)
{
  memset (k, 0, sizeof *k);
  if (m->pq_algo == 0)
    {
      memcpy (k->data, ec_ss, m->ec_out);
      k->len = m->ec_out;
      k->as_string = 0;
      return GF_OK;
    }
  {
    gf_hash_ctx *h;
    int r = gf_hash_new (&h, m->hash);

    if (r != GF_OK)
      return r;
    r = gf_hash_update (h, pq_ss, PQ_SS);
    if (r == GF_OK)
      r = gf_hash_update (h, ec_ss, m->ec_out);
    if (r == GF_OK)
      r = gf_hash_final (h, k->data, gf_hash_size (m->hash));
    gf_hash_free (h);
    k->len = gf_hash_size (m->hash);
    k->as_string = 1;
    return r;
  }
}

/* ------------------------------------------------------------------ */
/* Client                                                             */
/* ------------------------------------------------------------------ */

struct gf_kex_client
{
  const struct method *m;
  uint8_t ec_secret[48];
  uint8_t pq_secret[GCRY_KEM_MLKEM1024_SECKEY_LEN];
};

void
gf_kex_client_free (gf_kex_client *c)
{
  if (c == NULL)
    return;
  gf_wipe (c, sizeof *c);
  free (c);
}

int
gf_kex_client_start (gf_kex_client **out, enum gf_kex kex, uint8_t *init,
                     size_t cap, size_t *initlen)
{
  const struct method *m = find_method (kex);
  gf_kex_client *c;
  uint8_t ec_pub[97];
  uint8_t pq_pub[GCRY_KEM_MLKEM1024_PUBKEY_LEN];
  int r = GF_OK;

  if (out == NULL || init == NULL || initlen == NULL)
    return GF_ERR_INVAL;
  if (m == NULL)
    return GF_ERR_UNSUPPORTED;
  if (cap < m->pq_pub + m->ec_pub)
    return GF_ERR_BUFSIZE;
  TRY (gf_crypto_init ());
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GF_ERR_NOMEM;
  c->m = m;

  if (gcry_kem_keypair (m->ec_algo, ec_pub, m->ec_pub, c->ec_secret,
                        m->ec_sec))
    r = GF_ERR_CRYPTO;
  else if (m->pq_algo
           && gcry_kem_keypair (m->pq_algo, pq_pub, m->pq_pub, c->pq_secret,
                                m->pq_sec))
    r = GF_ERR_CRYPTO;
  if (r != GF_OK)
    {
      gf_kex_client_free (c);
      return r;
    }
  /* Post-quantum part first.  */
  if (m->pq_algo)
    memcpy (init, pq_pub, m->pq_pub);
  memcpy (init + m->pq_pub, ec_pub, m->ec_pub);
  *initlen = m->pq_pub + m->ec_pub;
  *out = c;
  return GF_OK;
}

int
gf_kex_client_finish (gf_kex_client *c, const uint8_t *reply, size_t len,
                      gf_kex_secret *k)
{
  const struct method *m;
  uint8_t ec_raw[97], ec_ss[48], pq_ss[PQ_SS];
  int r;

  if (c == NULL || reply == NULL || k == NULL)
    return GF_ERR_INVAL;
  m = c->m;
  if (len != m->pq_ct + m->ec_pub)
    return GF_ERR_ENCODING;
  TRY (gf_crypto_init ());

  if (!ec_peer_ok (m, reply + m->pq_ct))
    return GF_ERR_CRYPTO;
  if (gcry_kem_decap (m->ec_algo, c->ec_secret, m->ec_sec,
                      reply + m->pq_ct, m->ec_pub, ec_raw, m->ec_raw,
                      NULL, 0))
    return GF_ERR_CRYPTO;
  r = ec_extract (m, ec_raw, ec_ss);
  if (r == GF_OK && m->pq_algo
      && gcry_kem_decap (m->pq_algo, c->pq_secret, m->pq_sec, reply,
                         m->pq_ct, pq_ss, PQ_SS, NULL, 0))
    r = GF_ERR_CRYPTO;
  if (r == GF_OK)
    r = combine (m, ec_ss, pq_ss, k);
  gf_wipe (ec_raw, sizeof ec_raw);
  gf_wipe (ec_ss, sizeof ec_ss);
  gf_wipe (pq_ss, sizeof pq_ss);
  return r;
}

/* ------------------------------------------------------------------ */
/* Server                                                             */
/* ------------------------------------------------------------------ */

int
gf_kex_server_respond (enum gf_kex kex, const uint8_t *init, size_t len,
                       uint8_t *reply, size_t cap, size_t *replylen,
                       gf_kex_secret *k)
{
  const struct method *m = find_method (kex);
  uint8_t ec_ct[97], ec_raw[97], ec_ss[48];
  uint8_t pq_ct[GCRY_KEM_MLKEM1024_CIPHER_LEN], pq_ss[PQ_SS];
  int r;

  if (init == NULL || reply == NULL || replylen == NULL || k == NULL)
    return GF_ERR_INVAL;
  if (m == NULL)
    return GF_ERR_UNSUPPORTED;
  if (len != m->pq_pub + m->ec_pub)
    return GF_ERR_ENCODING;
  if (cap < m->pq_ct + m->ec_pub)
    return GF_ERR_BUFSIZE;
  TRY (gf_crypto_init ());

  if (!ec_peer_ok (m, init + m->pq_pub))
    return GF_ERR_CRYPTO;
  if (gcry_kem_encap (m->ec_algo, init + m->pq_pub, m->ec_pub, ec_ct,
                      m->ec_pub, ec_raw, m->ec_raw, NULL, 0))
    return GF_ERR_CRYPTO;
  r = ec_extract (m, ec_raw, ec_ss);
  if (r == GF_OK && m->pq_algo
      && gcry_kem_encap (m->pq_algo, init, m->pq_pub, pq_ct, m->pq_ct, pq_ss,
                         PQ_SS, NULL, 0))
    r = GF_ERR_CRYPTO;
  if (r == GF_OK)
    r = combine (m, ec_ss, pq_ss, k);
  if (r == GF_OK)
    {
      if (m->pq_algo)
        memcpy (reply, pq_ct, m->pq_ct);
      memcpy (reply + m->pq_ct, ec_ct, m->ec_pub);
      *replylen = m->pq_ct + m->ec_pub;
    }
  gf_wipe (ec_raw, sizeof ec_raw);
  gf_wipe (ec_ss, sizeof ec_ss);
  gf_wipe (pq_ss, sizeof pq_ss);
  return r;
}

/* ------------------------------------------------------------------ */
/* Exchange hash and key derivation                                   */
/* ------------------------------------------------------------------ */

static int
hash_k (gf_hash_ctx *h, const gf_kex_secret *k)
{
  return k->as_string ? gf_hash_update_string (h, k->data, k->len)
                      : gf_hash_update_mpint (h, k->data, k->len);
}

int
gf_kex_exchange_hash (enum gf_kex kex, const struct gf_kex_transcript *t,
                      const gf_kex_secret *k, uint8_t *out, size_t outlen)
{
  const struct method *m = find_method (kex);
  gf_hash_ctx *h;
  int r;

  if (t == NULL || k == NULL || out == NULL)
    return GF_ERR_INVAL;
  if (m == NULL)
    return GF_ERR_UNSUPPORTED;
  if (outlen != gf_hash_size (m->hash))
    return GF_ERR_INVAL;
  r = gf_hash_new (&h, m->hash);
  if (r != GF_OK)
    return r;
  r = gf_hash_update_string (h, t->v_c.data, t->v_c.len);
  if (r == GF_OK)
    r = gf_hash_update_string (h, t->v_s.data, t->v_s.len);
  if (r == GF_OK)
    r = gf_hash_update_string (h, t->i_c.data, t->i_c.len);
  if (r == GF_OK)
    r = gf_hash_update_string (h, t->i_s.data, t->i_s.len);
  if (r == GF_OK)
    r = gf_hash_update_string (h, t->k_s.data, t->k_s.len);
  if (r == GF_OK)
    r = gf_hash_update_string (h, t->q_c.data, t->q_c.len);
  if (r == GF_OK)
    r = gf_hash_update_string (h, t->q_s.data, t->q_s.len);
  if (r == GF_OK)
    r = hash_k (h, k);
  if (r == GF_OK)
    r = gf_hash_final (h, out, outlen);
  gf_hash_free (h);
  return r;
}

int
gf_kex_derive (enum gf_hash alg, const gf_kex_secret *k, const uint8_t *h,
               size_t hlen, const uint8_t *session_id, size_t sidlen,
               char letter, uint8_t *out, size_t outlen)
{
  size_t dl = gf_hash_size (alg), have = 0;
  uint8_t block[GF_KEX_MAX_HASH];
  int r = GF_OK;

  if (k == NULL || h == NULL || session_id == NULL || out == NULL
      || dl == 0 || letter < 'A' || letter > 'F')
    return dl == 0 ? GF_ERR_UNSUPPORTED : GF_ERR_INVAL;

  while (have < outlen && r == GF_OK)
    {
      gf_hash_ctx *c;
      size_t n;

      r = gf_hash_new (&c, alg);
      if (r != GF_OK)
        break;
      r = hash_k (c, k);
      if (r == GF_OK)
        r = gf_hash_update (c, h, hlen);
      if (r == GF_OK)
        {
          if (have == 0)
            {
              r = gf_hash_update (c, &letter, 1);
              if (r == GF_OK)
                r = gf_hash_update (c, session_id, sidlen);
            }
          else
            r = gf_hash_update (c, out, have);
        }
      if (r == GF_OK)
        r = gf_hash_final (c, block, dl);
      gf_hash_free (c);
      if (r != GF_OK)
        break;
      n = outlen - have < dl ? outlen - have : dl;
      memcpy (out + have, block, n);
      have += n;
    }
  gf_wipe (block, sizeof block);
  if (r != GF_OK)
    gf_wipe (out, outlen);
  return r;
}
