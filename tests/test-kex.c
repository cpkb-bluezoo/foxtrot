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

#include <gcrypt.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/kex.h>

#include "tst-util.h"
#include "vectors-kex.h"

static const enum gf_kex all[] = {
  GF_KEX_CURVE25519_SHA256, GF_KEX_MLKEM768X25519_SHA256,
  GF_KEX_MLKEM768NISTP256_SHA256, GF_KEX_MLKEM1024NISTP384_SHA384,
  GF_KEX_SNTRUP761X25519_SHA512, GF_KEX_ECDH_NISTP256_SHA256,
  GF_KEX_ECDH_NISTP384_SHA384
};

static gf_slice
sl (const uint8_t *p, size_t n)
{
  gf_slice s;

  s.data = p;
  s.len = n;
  return s;
}

static void
test_sizes (void)
{
  CHECK_EQ (gf_kex_init_len (GF_KEX_CURVE25519_SHA256), 32);
  CHECK_EQ (gf_kex_reply_len (GF_KEX_CURVE25519_SHA256), 32);
  CHECK_EQ (gf_kex_init_len (GF_KEX_ECDH_NISTP256_SHA256), 65);
  CHECK_EQ (gf_kex_init_len (GF_KEX_ECDH_NISTP384_SHA384), 97);
  /* draft-josefsson-ntruprime-ssh: Q_C is 1190 bytes, Q_S 1071.  */
  CHECK_EQ (gf_kex_init_len (GF_KEX_SNTRUP761X25519_SHA512), 1190);
  CHECK_EQ (gf_kex_reply_len (GF_KEX_SNTRUP761X25519_SHA512), 1071);
  /* ML-KEM-768: 1184 and 1088 plus X25519.  */
  CHECK_EQ (gf_kex_init_len (GF_KEX_MLKEM768X25519_SHA256), 1184 + 32);
  CHECK_EQ (gf_kex_reply_len (GF_KEX_MLKEM768X25519_SHA256), 1088 + 32);
  CHECK_EQ (gf_kex_init_len (GF_KEX_MLKEM768NISTP256_SHA256), 1184 + 65);
  CHECK_EQ (gf_kex_reply_len (GF_KEX_MLKEM1024NISTP384_SHA384), 1568 + 97);
  CHECK_EQ (gf_kex_init_len (GF_KEX_MLKEM1024NISTP384_SHA384), 1568 + 97);
  CHECK (gf_kex_init_len (GF_KEX_MLKEM1024NISTP384_SHA384) <= GF_KEX_MAX_INIT);
  CHECK_EQ (gf_kex_init_len (0), 0);
  CHECK_EQ (gf_kex_init_len (99), 0);
  CHECK_EQ (gf_kex_hash (GF_KEX_SNTRUP761X25519_SHA512), GF_HASH_SHA512);
  CHECK_EQ (gf_kex_hash (GF_KEX_MLKEM1024NISTP384_SHA384), GF_HASH_SHA384);
  CHECK_EQ (gf_kex_hash (GF_KEX_CURVE25519_SHA256), GF_HASH_SHA256);
}

/* Client and server arrive at the same K, for every method, and the
   values have the announced sizes.  */
static void
test_agreement (void)
{
  size_t i;

  for (i = 0; i < sizeof all / sizeof all[0]; i++)
    {
      uint8_t init[GF_KEX_MAX_INIT], reply[GF_KEX_MAX_REPLY];
      size_t initlen, replylen;
      gf_kex_client *c = NULL;
      gf_kex_secret ks, kc;

      CHECK_EQ (gf_kex_client_start (&c, all[i], init, sizeof init, &initlen),
                GF_OK);
      CHECK_EQ (initlen, gf_kex_init_len (all[i]));
      CHECK_EQ (gf_kex_server_respond (all[i], init, initlen, reply,
                                       sizeof reply, &replylen, &ks), GF_OK);
      CHECK_EQ (replylen, gf_kex_reply_len (all[i]));
      CHECK_EQ (gf_kex_client_finish (c, reply, replylen, &kc), GF_OK);
      CHECK (kc.len == ks.len && kc.len > 0);
      CHECK (kc.as_string == ks.as_string);
      CHECK (memcmp (kc.data, ks.data, kc.len) == 0);
      CHECK_EQ (ks.as_string, all[i] != GF_KEX_CURVE25519_SHA256
                              && all[i] != GF_KEX_ECDH_NISTP256_SHA256
                              && all[i] != GF_KEX_ECDH_NISTP384_SHA384);

      /* Wrong lengths, and a reply from another exchange.  */
      CHECK_EQ (gf_kex_client_finish (c, reply, replylen - 1, &kc),
                GF_ERR_ENCODING);
      CHECK_EQ (gf_kex_server_respond (all[i], init, initlen - 1, reply,
                                       sizeof reply, &replylen, &ks),
                GF_ERR_ENCODING);
      CHECK_EQ (gf_kex_server_respond (all[i], init, initlen, reply, 10,
                                       &replylen, &ks), GF_ERR_BUFSIZE);
      {
        uint8_t reply2[GF_KEX_MAX_REPLY], init2[GF_KEX_MAX_INIT];
        size_t rl2, il2;
        gf_kex_client *c2 = NULL;
        gf_kex_secret k2, k3;

        CHECK_EQ (gf_kex_client_start (&c2, all[i], init2, sizeof init2, &il2),
                  GF_OK);
        CHECK_EQ (gf_kex_server_respond (all[i], init2, il2, reply2,
                                         sizeof reply2, &rl2, &k2), GF_OK);
        CHECK (k2.len != ks.len || memcmp (k2.data, ks.data, ks.len) != 0);
        /* A reply to someone else's init gives the client a different K
           (or, for ML-KEM, the implicit-rejection secret).  */
        if (gf_kex_client_finish (c, reply2, rl2, &k3) == GF_OK)
          CHECK (k3.len != ks.len || memcmp (k3.data, ks.data, ks.len) != 0);
        gf_kex_client_free (c2);
      }
      gf_kex_client_free (c);
    }
}

/* X25519 low-order points give an all-zero secret and must be refused, on
   both sides (RFC 8731 section 3.1 and RFC 7748 section 6.1).  */
static void
test_x25519_low_order (void)
{
  static const char *const bad[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
  };
  size_t i;

  for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      uint8_t pt[32], reply[64], init[GF_KEX_MAX_INIT];
      size_t rl, il;
      gf_kex_secret k;
      gf_kex_client *c = NULL;

      tst_unhex (bad[i], pt, sizeof pt);
      CHECK (gf_kex_server_respond (GF_KEX_CURVE25519_SHA256, pt, 32, reply,
                                    sizeof reply, &rl, &k) != GF_OK);
      CHECK_EQ (gf_kex_client_start (&c, GF_KEX_CURVE25519_SHA256, init,
                                     sizeof init, &il), GF_OK);
      CHECK (gf_kex_client_finish (c, pt, 32, &k) != GF_OK);
      gf_kex_client_free (c);
    }
}

/* ECDH with points that are not on the curve, or not uncompressed.  */
static void
test_ecdh_bad_points (void)
{
  uint8_t pt[65], reply[100];
  size_t rl;
  gf_kex_secret k;

  memset (pt, 0, sizeof pt);
  pt[0] = 0x04;
  CHECK (gf_kex_server_respond (GF_KEX_ECDH_NISTP256_SHA256, pt, 65, reply,
                                sizeof reply, &rl, &k) != GF_OK);
  memset (pt, 1, sizeof pt);
  pt[0] = 0x04;
  CHECK (gf_kex_server_respond (GF_KEX_ECDH_NISTP256_SHA256, pt, 65, reply,
                                sizeof reply, &rl, &k) != GF_OK);
  pt[0] = 0x02;
  CHECK (gf_kex_server_respond (GF_KEX_ECDH_NISTP256_SHA256, pt, 65, reply,
                                sizeof reply, &rl, &k) != GF_OK);
}

/* The hybrid composition checked from the outside: build a client init by
   hand from libgcrypt's KEM, let the server answer, decapsulate both
   halves ourselves and check K = HASH (K_PQ || K_CL), as a string.  */
static void
test_hybrid_composition (void)
{
  static const struct
  {
    enum gf_kex kex;
    int pq, ec;
    size_t pq_pub, pq_sec, pq_ct, ec_pub, ec_sec, ec_raw, ec_out;
    enum gf_hash hash;
  } v[] = {
    { GF_KEX_MLKEM768X25519_SHA256, GCRY_KEM_MLKEM768, GCRY_KEM_RAW_X25519,
      GCRY_KEM_MLKEM768_PUBKEY_LEN, GCRY_KEM_MLKEM768_SECKEY_LEN,
      GCRY_KEM_MLKEM768_CIPHER_LEN, 32, 32, 32, 32, GF_HASH_SHA256 },
    { GF_KEX_SNTRUP761X25519_SHA512, GCRY_KEM_SNTRUP761, GCRY_KEM_RAW_X25519,
      GCRY_KEM_SNTRUP761_PUBKEY_LEN, GCRY_KEM_SNTRUP761_SECKEY_LEN,
      GCRY_KEM_SNTRUP761_CIPHER_LEN, 32, 32, 32, 32, GF_HASH_SHA512 },
    { GF_KEX_MLKEM768NISTP256_SHA256, GCRY_KEM_MLKEM768, GCRY_KEM_RAW_P256R1,
      GCRY_KEM_MLKEM768_PUBKEY_LEN, GCRY_KEM_MLKEM768_SECKEY_LEN,
      GCRY_KEM_MLKEM768_CIPHER_LEN, 65, 32, 65, 32, GF_HASH_SHA256 },
    { GF_KEX_MLKEM1024NISTP384_SHA384, GCRY_KEM_MLKEM1024, GCRY_KEM_RAW_P384R1,
      GCRY_KEM_MLKEM1024_PUBKEY_LEN, GCRY_KEM_MLKEM1024_SECKEY_LEN,
      GCRY_KEM_MLKEM1024_CIPHER_LEN, 97, 48, 97, 48, GF_HASH_SHA384 }
  };
  size_t i;

  gf_crypto_init ();
  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      static uint8_t pq_pub[2000], pq_sec[4000], init[GF_KEX_MAX_INIT];
      static uint8_t reply[GF_KEX_MAX_REPLY];
      uint8_t ec_pub[97], ec_sec[48], ec_raw[97], pq_ss[32], concat[80];
      uint8_t want[64];
      size_t rl;
      gf_kex_secret k;

      CHECK_EQ (gcry_kem_keypair (v[i].pq, pq_pub, v[i].pq_pub, pq_sec,
                                  v[i].pq_sec), 0);
      CHECK_EQ (gcry_kem_keypair (v[i].ec, ec_pub, v[i].ec_pub, ec_sec,
                                  v[i].ec_sec), 0);
      /* C_INIT = C_PK2 || C_PK1: the ML-KEM or sntrup key, then the
         classical one.  */
      memcpy (init, pq_pub, v[i].pq_pub);
      memcpy (init + v[i].pq_pub, ec_pub, v[i].ec_pub);
      CHECK_EQ (gf_kex_server_respond (v[i].kex, init, v[i].pq_pub + v[i].ec_pub,
                                       reply, sizeof reply, &rl, &k), GF_OK);
      /* S_REPLY = S_CT2 || S_PK1.  */
      CHECK_EQ (rl, v[i].pq_ct + v[i].ec_pub);
      CHECK_EQ (gcry_kem_decap (v[i].pq, pq_sec, v[i].pq_sec, reply,
                                v[i].pq_ct, pq_ss, 32, NULL, 0), 0);
      CHECK_EQ (gcry_kem_decap (v[i].ec, ec_sec, v[i].ec_sec,
                                reply + v[i].pq_ct, v[i].ec_pub, ec_raw,
                                v[i].ec_raw, NULL, 0), 0);
      memcpy (concat, pq_ss, 32);
      /* The NIST curves keep x only.  */
      memcpy (concat + 32, v[i].ec_raw == v[i].ec_out ? ec_raw : ec_raw + 1,
              v[i].ec_out);
      CHECK_EQ (gf_hash_compute (v[i].hash, concat, 32 + v[i].ec_out, want,
                                 gf_hash_size (v[i].hash)), GF_OK);
      CHECK (k.as_string);
      CHECK_EQ (k.len, gf_hash_size (v[i].hash));
      CHECK (memcmp (k.data, want, k.len) == 0);
    }
}

static void
kat (enum gf_kex kex, const char *tag_k, const char *tag_h, const char *tag_sid,
     const char *const *keys, int as_string)
{
  struct gf_kex_transcript t;
  uint8_t vc[100], vs[100], ic[300], is[300], ksb[100], qc[64], qs[64];
  uint8_t kraw[64], hwant[64], h[64], sid[64], out[80], want[80];
  gf_kex_secret k;
  size_t hl = gf_hash_size (gf_kex_hash (kex)), kl, i;

  t.v_c = sl (vc, tst_unhex (vec_v_c, vc, sizeof vc));
  t.v_s = sl (vs, tst_unhex (vec_v_s, vs, sizeof vs));
  t.i_c = sl (ic, tst_unhex (vec_i_c, ic, sizeof ic));
  t.i_s = sl (is, tst_unhex (vec_i_s, is, sizeof is));
  t.k_s = sl (ksb, tst_unhex (vec_k_s, ksb, sizeof ksb));
  t.q_c = sl (qc, tst_unhex (vec_q_c, qc, sizeof qc));
  t.q_s = sl (qs, tst_unhex (vec_q_s, qs, sizeof qs));
  kl = tst_unhex (tag_k, kraw, sizeof kraw);
  memset (&k, 0, sizeof k);
  memcpy (k.data, kraw, kl);
  k.len = kl;
  k.as_string = as_string;
  tst_unhex (tag_h, hwant, sizeof hwant);
  tst_unhex (tag_sid, sid, sizeof sid);

  CHECK_EQ (gf_kex_exchange_hash (kex, &t, &k, h, hl), GF_OK);
  CHECK (memcmp (h, hwant, hl) == 0);
  CHECK_EQ (gf_kex_exchange_hash (kex, &t, &k, h, hl - 1), GF_ERR_INVAL);

  for (i = 0; i < 6; i++)
    {
      size_t n = tst_unhex (keys[i], want, sizeof want);

      /* 80 bytes needs two or three hash blocks; also shorter lengths,
         which must be prefixes.  */
      CHECK_EQ (gf_kex_derive (gf_kex_hash (kex), &k, h, hl, sid, hl,
                               (char) ('A' + i), out, n), GF_OK);
      CHECK (memcmp (out, want, n) == 0);
      CHECK_EQ (gf_kex_derive (gf_kex_hash (kex), &k, h, hl, sid, hl,
                               (char) ('A' + i), out, 12), GF_OK);
      CHECK (memcmp (out, want, 12) == 0);
      CHECK_EQ (gf_kex_derive (gf_kex_hash (kex), &k, h, hl, sid, hl,
                               (char) ('A' + i), out, hl), GF_OK);
      CHECK (memcmp (out, want, hl) == 0);
    }
  CHECK_EQ (gf_kex_derive (gf_kex_hash (kex), &k, h, hl, sid, hl, 'G', out, 8),
            GF_ERR_INVAL);
}

#define KEYS(tag) { vec_##tag##_keyA, vec_##tag##_keyB, vec_##tag##_keyC, \
                    vec_##tag##_keyD, vec_##tag##_keyE, vec_##tag##_keyF }

static void
test_kat (void)
{
  const char *const a[] = KEYS (sha256_mpint);
  const char *const b[] = KEYS (sha256_mpint0);
  const char *const c[] = KEYS (sha384_mpint);
  const char *const d[] = KEYS (sha512_string);
  const char *const e[] = KEYS (sha256_string);

  kat (GF_KEX_CURVE25519_SHA256, vec_sha256_mpint_k, vec_sha256_mpint_h,
       vec_sha256_mpint_sid, a, 0);
  kat (GF_KEX_CURVE25519_SHA256, vec_sha256_mpint0_k, vec_sha256_mpint0_h,
       vec_sha256_mpint0_sid, b, 0);
  kat (GF_KEX_ECDH_NISTP384_SHA384, vec_sha384_mpint_k, vec_sha384_mpint_h,
       vec_sha384_mpint_sid, c, 0);
  kat (GF_KEX_SNTRUP761X25519_SHA512, vec_sha512_string_k, vec_sha512_string_h,
       vec_sha512_string_sid, d, 1);
  kat (GF_KEX_MLKEM768X25519_SHA256, vec_sha256_string_k, vec_sha256_string_h,
       vec_sha256_string_sid, e, 1);
}

int
main (void)
{
  gf_crypto_init ();
  test_sizes ();
  test_kat ();
  test_agreement ();
  test_x25519_low_order ();
  test_ecdh_bad_points ();
  test_hybrid_composition ();
  TST_DONE ();
}
