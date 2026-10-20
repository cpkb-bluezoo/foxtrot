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

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/packet.h>

#include "tst-util.h"
#include "vectors-packet.h"

#define MAXBUF 40000

struct log
{
  size_t count;
  size_t total;			/* Payload bytes seen.  */
  uint8_t hash;			/* Cheap digest of the payloads.  */
  uint8_t first[8];		/* First bytes of the first payload.  */
};

static int
log_cb (void *user, const uint8_t *payload, size_t len)
{
  struct log *l = user;
  size_t i;

  if (l->count == 0)
    memcpy (l->first, payload, len < sizeof l->first ? len : sizeof l->first);
  l->count++;
  l->total += len;
  for (i = 0; i < len; i++)
    l->hash = (uint8_t) (l->hash * 31 + payload[i]);
  return 0;
}

static void
set_both (gf_packet *p, enum gf_dir dir, enum gf_cipher c)
{
  uint8_t key[64], iv[12];
  size_t i;

  tst_unhex (vec_key64, key, sizeof key);
  if (c == GF_CIPHER_AES256_GCM)
    tst_unhex (vec_key32, key, sizeof key);
  if (c == GF_CIPHER_AES128_GCM)
    tst_unhex (vec_key16, key, sizeof key);
  tst_unhex (vec_iv, iv, sizeof iv);
  (void) i;
  CHECK_EQ (gf_packet_set_keys (p, dir, c, key, gf_cipher_key_len (c), iv,
                                gf_cipher_iv_len (c), 0), GF_OK);
}

/* Seal PAYLOAD with the given padding, compare with the hex vector, then
   open the vector and compare the payload.  */
static void
kat (gf_packet *w, gf_packet *r, const char *payload_hex, const char *pad_hex,
     const char *vec_hex)
{
  uint8_t payload[64], pad[32], out[256], want[256], *buf;
  size_t pn = tst_unhex (payload_hex, payload, sizeof payload);
  size_t padn = tst_unhex (pad_hex, pad, sizeof pad);
  size_t outlen = 0, wn = tst_unhex (vec_hex, want, sizeof want), len;
  struct log l;

  CHECK_EQ (gf_packet_send_padded (w, payload, pn, pad, padn, out,
                                   sizeof out, &outlen), GF_OK);
  CHECK (outlen == wn && memcmp (out, want, wn) == 0);

  memset (&l, 0, sizeof l);
  buf = want;
  len = wn;
  CHECK_EQ (gf_packet_receive (r, &buf, &len, log_cb, &l), GF_OK);
  CHECK_EQ (len, 0);
  CHECK_EQ (l.count, 1);
  CHECK_EQ (l.total, pn);
  CHECK (memcmp (l.first, payload, pn < 8 ? pn : 8) == 0);
}

static void
test_kat (void)
{
  gf_packet w, r;
  uint8_t key[64], iv[12];

  /* Plaintext.  */
  gf_packet_init (&w);
  gf_packet_init (&r);
  kat (&w, &r, vec_payload1, vec_none1_pad, vec_none1);

  /* chacha20-poly1305@openssh.com at sequence number 0, then 7 and 8.  */
  gf_packet_init (&w);
  gf_packet_init (&r);
  set_both (&w, GF_DIR_WRITE, GF_CIPHER_CHACHA20_POLY1305);
  set_both (&r, GF_DIR_READ, GF_CIPHER_CHACHA20_POLY1305);
  kat (&w, &r, vec_payload1, vec_chacha_seq0_pad1, vec_chacha_seq0_1);

  gf_packet_init (&w);
  gf_packet_init (&r);
  w.write.seq = r.read.seq = 7;
  set_both (&w, GF_DIR_WRITE, GF_CIPHER_CHACHA20_POLY1305);
  set_both (&r, GF_DIR_READ, GF_CIPHER_CHACHA20_POLY1305);
  kat (&w, &r, vec_payload1, vec_chacha_seq7_pad1, vec_chacha_seq7_1);
  kat (&w, &r, vec_payload2, vec_chacha_seq7_pad2, vec_chacha_seq7_2);
  CHECK_EQ (gf_packet_seq (&w, GF_DIR_WRITE), 9);
  CHECK_EQ (gf_packet_seq (&r, GF_DIR_READ), 9);
  CHECK_EQ (gf_packet_count (&w, GF_DIR_WRITE), 2);

  /* AES-GCM, with an invocation counter that carries across bytes.  */
  gf_packet_init (&w);
  gf_packet_init (&r);
  set_both (&w, GF_DIR_WRITE, GF_CIPHER_AES128_GCM);
  set_both (&r, GF_DIR_READ, GF_CIPHER_AES128_GCM);
  kat (&w, &r, vec_payload1, vec_pad16_1, vec_gcm128_1);
  kat (&w, &r, vec_payload2, vec_pad16_2, vec_gcm128_2);
  kat (&w, &r, vec_payload1, vec_pad16_1, vec_gcm128_3);

  gf_packet_init (&w);
  gf_packet_init (&r);
  set_both (&w, GF_DIR_WRITE, GF_CIPHER_AES256_GCM);
  set_both (&r, GF_DIR_READ, GF_CIPHER_AES256_GCM);
  kat (&w, &r, vec_payload1, vec_pad16_1, vec_gcm256_1);
  kat (&w, &r, vec_payload2, vec_pad16_2, vec_gcm256_2);
  kat (&w, &r, vec_payload1, vec_pad16_1, vec_gcm256_3);

  /* The key and IV lengths must be exactly right.  */
  gf_packet_init (&w);
  tst_unhex (vec_key64, key, sizeof key);
  tst_unhex (vec_iv, iv, sizeof iv);
  CHECK_EQ (gf_packet_set_keys (&w, GF_DIR_WRITE, GF_CIPHER_AES256_GCM, key,
                                16, iv, 12, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_packet_set_keys (&w, GF_DIR_WRITE, GF_CIPHER_AES256_GCM, key,
                                32, iv, 8, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_packet_set_keys (&w, GF_DIR_WRITE, GF_CIPHER_CHACHA20_POLY1305,
                                key, 32, NULL, 0, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_packet_set_keys (&w, GF_DIR_WRITE, GF_CIPHER_NONE, key, 0,
                                NULL, 0, 0), GF_ERR_UNSUPPORTED);
}

static const enum gf_cipher all_ciphers[] = {
  GF_CIPHER_NONE, GF_CIPHER_CHACHA20_POLY1305, GF_CIPHER_AES256_GCM,
  GF_CIPHER_AES128_GCM
};

static void
keyed (gf_packet *w, gf_packet *r, enum gf_cipher c)
{
  uint8_t key[64], iv[12];

  gf_packet_init (w);
  gf_packet_init (r);
  if (c == GF_CIPHER_NONE)
    return;
  gf_random (key, sizeof key);
  gf_random (iv, sizeof iv);
  CHECK_EQ (gf_packet_set_keys (w, GF_DIR_WRITE, c, key, gf_cipher_key_len (c),
                                iv, gf_cipher_iv_len (c), 0), GF_OK);
  CHECK_EQ (gf_packet_set_keys (r, GF_DIR_READ, c, key, gf_cipher_key_len (c),
                                iv, gf_cipher_iv_len (c), 0), GF_OK);
}

/* Build a stream of packets of assorted sizes.  Returns its length.  */
static size_t
make_stream (gf_packet *w, uint8_t *stream, struct log *expect)
{
  static const size_t sizes[] = { 1, 2, 5, 16, 17, 31, 32, 33, 200, 1500,
                                  4000, GF_MAX_PAYLOAD };
  static uint8_t payload[GF_MAX_PAYLOAD];
  size_t i, n = 0, j;

  memset (expect, 0, sizeof *expect);
  for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++)
    {
      size_t outlen;

      for (j = 0; j < sizes[i]; j++)
        payload[j] = (uint8_t) (j * 7 + i);
      CHECK_EQ (gf_packet_send (w, payload, sizes[i], stream + n,
                                MAXBUF - n, &outlen), GF_OK);
      CHECK (outlen <= sizes[i] + GF_PKT_OVERHEAD);
      n += outlen;
      log_cb (expect, payload, sizes[i]);
    }
  return n;
}

/* Feed STREAM in chunks of CHUNK bytes the way a connection does: append
   to an accumulation buffer, parse, keep the tail.  */
static int
feed_chunked (gf_packet *r, const uint8_t *stream, size_t n, size_t chunk,
              struct log *l)
{
  static uint8_t acc[MAXBUF + 8];
  size_t fill = 0, off = 0;
  int rc = GF_OK;

  memset (l, 0, sizeof *l);
  while (off < n)
    {
      size_t take = n - off < chunk ? n - off : chunk;
      uint8_t *b = acc;
      size_t len;

      memcpy (acc + fill, stream + off, take);
      fill += take;
      off += take;
      len = fill;
      rc = gf_packet_receive (r, &b, &len, log_cb, l);
      if (rc != GF_OK && rc != GF_NEED_MORE)
        return rc;
      memmove (acc, b, len);
      fill = len;
    }
  return fill == 0 ? GF_OK : GF_NEED_MORE;
}

static void
test_roundtrip_and_chunks (void)
{
  size_t k;

  for (k = 0; k < sizeof all_ciphers / sizeof all_ciphers[0]; k++)
    {
      static uint8_t stream[MAXBUF];
      gf_packet w, r;
      struct log expect, got;
      size_t n, chunk;

      keyed (&w, &r, all_ciphers[k]);
      n = make_stream (&w, stream, &expect);

      /* Whole, and in every chunk size from 1 up (sparser above 64).  */
      for (chunk = 1; chunk <= n; chunk += chunk < 64 ? 1 : 997)
        {
          gf_packet r2 = r;

          CHECK_EQ (feed_chunked (&r2, stream, n, chunk, &got), GF_OK);
          CHECK_EQ (got.count, expect.count);
          CHECK_EQ (got.total, expect.total);
          CHECK_EQ (got.hash, expect.hash);
          CHECK_EQ (gf_packet_seq (&r2, GF_DIR_READ), expect.count);
        }
      {
        gf_packet r2 = r;
        CHECK_EQ (feed_chunked (&r2, stream, n, n, &got), GF_OK);
        CHECK_EQ (got.count, expect.count);
        CHECK_EQ (gf_packet_bytes (&r2, GF_DIR_READ), n);
      }
    }
}

/* Any single changed byte of a protected packet must make it fail.  */
static void
test_tamper (void)
{
  size_t k;

  for (k = 1; k < sizeof all_ciphers / sizeof all_ciphers[0]; k++)
    {
      gf_packet w, r;
      uint8_t payload[40], pkt[200];
      size_t outlen, i;

      keyed (&w, &r, all_ciphers[k]);
      memset (payload, 0x42, sizeof payload);
      CHECK_EQ (gf_packet_send (&w, payload, sizeof payload, pkt, sizeof pkt,
                                &outlen), GF_OK);
      for (i = 0; i < outlen; i++)
        {
          uint8_t copy[200], *b = copy;
          size_t len = outlen;
          gf_packet r2 = r;
          struct log l;
          int rc;

          memcpy (copy, pkt, outlen);
          copy[i] ^= 0x01;
          memset (&l, 0, sizeof l);
          rc = gf_packet_receive (&r2, &b, &len, log_cb, &l);
          CHECK (rc != GF_OK);
          CHECK_EQ (l.count, 0);
        }
      /* ChaCha20's nonce is the sequence number, so a packet opened
         under another number fails.  (AES-GCM uses its own counter.)  */
      if (all_ciphers[k] == GF_CIPHER_CHACHA20_POLY1305)
      {
        uint8_t *b = pkt;
        size_t len = outlen;
        struct log l;

        memset (&l, 0, sizeof l);
        r.read.seq = 1;
        CHECK (gf_packet_receive (&r, &b, &len, log_cb, &l) != GF_OK);
        CHECK_EQ (l.count, 0);
      }
    }
}

/* A plaintext packet with packet_length PL and padding length PADLEN, zero
   filled, of which only AVAIL bytes are present.  */
static size_t
mkpkt (uint8_t *buf, uint32_t pl, uint8_t padlen, size_t avail)
{
  size_t i, total = 4 + (size_t) pl;

  memset (buf, 0, 64);
  buf[0] = (uint8_t) (pl >> 24);
  buf[1] = (uint8_t) (pl >> 16);
  buf[2] = (uint8_t) (pl >> 8);
  buf[3] = (uint8_t) pl;
  buf[4] = padlen;
  for (i = 5; i < total && i < 64; i++)
    buf[i] = 0x11;
  return avail < total ? avail : total;
}

/* Plaintext packets: every malformed length or padding is refused, and a
   huge announced length is refused from the first four bytes.  */
static void
test_plaintext_validation (void)
{
  static const struct
  {
    uint32_t pl;
    uint8_t padlen;
    size_t avail;
    int rc;
  } v[] = {
    { 0xffffffff, 4, 8, GF_ERR_ENCODING },	/* Absurd length.  */
    { 35520, 4, 8, GF_ERR_ENCODING },		/* Over the maximum.  */
    { 0, 4, 8, GF_ERR_ENCODING },
    { 4, 4, 8, GF_ERR_ENCODING },		/* Too small.  */
    { 13, 4, 17, GF_ERR_ENCODING },		/* Misaligned.  */
    { 12, 3, 16, GF_ERR_ENCODING },		/* Padding under four.  */
    { 12, 11, 16, GF_ERR_ENCODING },		/* No payload.  */
    { 12, 12, 16, GF_ERR_ENCODING },		/* Padding past the end.  */
    { 12, 10, 16, GF_OK },			/* One byte of payload.  */
    { 12, 10, 15, GF_NEED_MORE },		/* Incomplete.  */
    { 12, 10, 3, GF_NEED_MORE },		/* Length unreadable.  */
    { 20, 4, 24, GF_OK }
  };
  size_t i;

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      gf_packet r;
      uint8_t buf[64], *b = buf;
      size_t len = mkpkt (buf, v[i].pl, v[i].padlen, v[i].avail);
      struct log l;

      gf_packet_init (&r);
      memset (&l, 0, sizeof l);
      CHECK_EQ (gf_packet_receive (&r, &b, &len, log_cb, &l), v[i].rc);
      CHECK_EQ (l.count, v[i].rc == GF_OK ? 1 : 0);
      if (v[i].rc == GF_OK)
        CHECK_EQ (l.total, v[i].pl - v[i].padlen - 1);
    }
}

static void
test_encrypted_lengths (void)
{
  /* Lengths are validated before the packet has arrived, for the ciphers
     that send the length in the clear (AES-GCM) and for ChaCha20, which
     encrypts it: a forged first four bytes either decrypt to something
     out of range or leave us waiting for a tag that cannot verify, and in
     no case deliver anything.  */
  gf_packet w, r;
  uint8_t pkt[8] = { 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 }, *b = pkt;
  size_t len = 4;
  struct log l;

  memset (&l, 0, sizeof l);
  keyed (&w, &r, GF_CIPHER_AES128_GCM);
  CHECK_EQ (gf_packet_receive (&r, &b, &len, log_cb, &l), GF_ERR_ENCODING);
  b = pkt;
  len = 4;
  /* Not a multiple of 16.  */
  pkt[0] = pkt[1] = pkt[2] = 0;
  pkt[3] = 40;
  CHECK_EQ (gf_packet_receive (&r, &b, &len, log_cb, &l), GF_ERR_ENCODING);
  b = pkt;
  len = 4;
  pkt[3] = 48;
  CHECK_EQ (gf_packet_receive (&r, &b, &len, log_cb, &l), GF_NEED_MORE);
  CHECK_EQ (len, 4);
  CHECK_EQ (l.count, 0);
}

static void
test_limits (void)
{
  gf_packet w, r;
  static uint8_t payload[GF_MAX_PACKET], out[GF_MAX_PACKET + 64];
  size_t outlen, k;

  for (k = 0; k < sizeof all_ciphers / sizeof all_ciphers[0]; k++)
    {
      keyed (&w, &r, all_ciphers[k]);
      CHECK_EQ (gf_packet_send (&w, payload, 0, out, sizeof out, &outlen),
                GF_ERR_INVAL);
      CHECK_EQ (gf_packet_send (&w, payload, GF_MAX_PACKET + 1, out,
                                sizeof out, &outlen), GF_ERR_RANGE);
      /* The packet as a whole is limited, not just the payload.  */
      CHECK_EQ (gf_packet_send (&w, payload, GF_MAX_PACKET - 3, out,
                                sizeof out, &outlen), GF_ERR_RANGE);
      CHECK_EQ (gf_packet_send (&w, payload, 100, out, 50, &outlen),
                GF_ERR_BUFSIZE);
      CHECK_EQ (gf_packet_send (&w, payload, GF_MAX_PAYLOAD, out, sizeof out,
                                &outlen), GF_OK);
      CHECK (outlen <= GF_MAX_PAYLOAD + GF_PKT_OVERHEAD);

      /* A sequence number about to wrap refuses to go on.  */
      w.write.seq = UINT32_MAX;
      CHECK_EQ (gf_packet_send (&w, payload, 10, out, sizeof out, &outlen),
                GF_ERR_RANGE);
      w.write.seq = UINT32_MAX - 1;
      CHECK_EQ (gf_packet_send (&w, payload, 10, out, sizeof out, &outlen),
                GF_OK);
      CHECK_EQ (gf_packet_send (&w, payload, 10, out, sizeof out, &outlen),
                GF_ERR_RANGE);
    }
}

/* The callback installs new keys after the first packet; the second, sealed
   with them, must open.  With a sequence reset (strict key exchange) the
   numbering restarts.  */
struct rekey_ctx
{
  gf_packet *r;
  uint8_t key[64];
  int calls;
  int reset;
};

static int
rekey_cb (void *user, const uint8_t *payload, size_t len)
{
  struct rekey_ctx *c = user;

  (void) payload;
  (void) len;
  if (c->calls++ == 0)
    gf_packet_set_keys (c->r, GF_DIR_READ, GF_CIPHER_AES256_GCM, c->key, 32,
                        c->key + 32, 12, c->reset);
  return 0;
}

static void
test_rekey_in_callback (void)
{
  int reset;

  for (reset = 0; reset <= 1; reset++)
    {
      gf_packet w, r;
      struct rekey_ctx c;
      uint8_t stream[400], payload[10] = { 1 }, *b = stream;
      size_t n = 0, outlen, len;

      gf_random (c.key, sizeof c.key);
      c.calls = 0;
      c.reset = reset;
      c.r = &r;
      keyed (&w, &r, GF_CIPHER_CHACHA20_POLY1305);
      CHECK_EQ (gf_packet_send (&w, payload, 10, stream, sizeof stream,
                                &outlen), GF_OK);
      n += outlen;
      CHECK_EQ (gf_packet_set_keys (&w, GF_DIR_WRITE, GF_CIPHER_AES256_GCM,
                                    c.key, 32, c.key + 32, 12, reset), GF_OK);
      CHECK_EQ (gf_packet_send (&w, payload, 10, stream + n,
                                sizeof stream - n, &outlen), GF_OK);
      n += outlen;
      CHECK_EQ (gf_packet_seq (&w, GF_DIR_WRITE), reset ? 1 : 2);

      len = n;
      CHECK_EQ (gf_packet_receive (&r, &b, &len, rekey_cb, &c), GF_OK);
      CHECK_EQ (c.calls, 2);
      CHECK_EQ (gf_packet_seq (&r, GF_DIR_READ), reset ? 1 : 2);
      CHECK_EQ (gf_packet_count (&r, GF_DIR_READ), 1);
    }
}

static int
stop_cb (void *user, const uint8_t *payload, size_t len)
{
  (void) payload;
  (void) len;
  return ++*(int *) user == 2;
}

static void
test_handler_stop (void)
{
  gf_packet w, r;
  uint8_t stream[300], payload[5] = { 1 }, *b = stream;
  size_t n = 0, outlen, len, i;
  int calls = 0;

  keyed (&w, &r, GF_CIPHER_NONE);
  for (i = 0; i < 3; i++)
    {
      CHECK_EQ (gf_packet_send (&w, payload, 5, stream + n,
                                sizeof stream - n, &outlen), GF_OK);
      n += outlen;
    }
  len = n;
  CHECK_EQ (gf_packet_receive (&r, &b, &len, stop_cb, &calls), GF_ERR_HANDLER);
  CHECK_EQ (calls, 2);
  CHECK_EQ (len, n / 3);		/* The third packet is left.  */
  CHECK_EQ (b, stream + 2 * (n / 3));
}

static void
test_sizes (void)
{
  CHECK_EQ (gf_cipher_key_len (GF_CIPHER_CHACHA20_POLY1305), 64);
  CHECK_EQ (gf_cipher_key_len (GF_CIPHER_AES256_GCM), 32);
  CHECK_EQ (gf_cipher_key_len (GF_CIPHER_AES128_GCM), 16);
  CHECK_EQ (gf_cipher_key_len (GF_CIPHER_NONE), 0);
  CHECK_EQ (gf_cipher_iv_len (GF_CIPHER_CHACHA20_POLY1305), 0);
  CHECK_EQ (gf_cipher_iv_len (GF_CIPHER_AES128_GCM), 12);
  CHECK_EQ (gf_cipher_block_len (GF_CIPHER_CHACHA20_POLY1305), 8);
  CHECK_EQ (gf_cipher_block_len (GF_CIPHER_AES256_GCM), 16);
}

int
main (void)
{
  test_sizes ();
  test_kat ();
  test_roundtrip_and_chunks ();
  test_tamper ();
  test_plaintext_validation ();
  test_encrypted_lengths ();
  test_limits ();
  test_rekey_in_callback ();
  test_handler_stop ();
  TST_DONE ();
}
