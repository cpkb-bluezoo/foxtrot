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

#include <string.h>

#include <gcrypt.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/packet.h>

#define POLY_KEY_LEN 32
#define CHACHA_KEY_LEN 32

size_t
gf_cipher_key_len (enum gf_cipher cipher)
{
  switch (cipher)
    {
    case GF_CIPHER_CHACHA20_POLY1305:	return 64;	/* K_2 then K_1.  */
    case GF_CIPHER_AES256_GCM:		return 32;
    case GF_CIPHER_AES128_GCM:		return 16;
    default:				return 0;
    }
}

size_t
gf_cipher_iv_len (enum gf_cipher cipher)
{
  switch (cipher)
    {
    case GF_CIPHER_AES256_GCM:
    case GF_CIPHER_AES128_GCM:		return 12;
    default:				return 0;
    }
}

/* Alignment of the encrypted part of a packet (everything after the
   length field), or of the whole packet for the plaintext direction.  */
size_t
gf_cipher_block_len (enum gf_cipher cipher)
{
  switch (cipher)
    {
    case GF_CIPHER_CHACHA20_POLY1305:	return 8;
    case GF_CIPHER_AES256_GCM:
    case GF_CIPHER_AES128_GCM:		return 16;
    default:				return 0;
    }
}

static int
is_gcm (enum gf_cipher c)
{
  return c == GF_CIPHER_AES128_GCM || c == GF_CIPHER_AES256_GCM;
}

void
gf_packet_init (gf_packet *p)
{
  memset (p, 0, sizeof *p);
}

void
gf_packet_wipe (gf_packet *p)
{
  gf_wipe (p, sizeof *p);
}

int
gf_packet_set_keys (gf_packet *p, enum gf_dir dir, enum gf_cipher cipher,
                    const uint8_t *key, size_t keylen,
                    const uint8_t *iv, size_t ivlen, int reset_seq)
{
  struct gf_pkt_dir *d;

  if (p == NULL || (dir != GF_DIR_READ && dir != GF_DIR_WRITE))
    return GF_ERR_INVAL;
  if (gf_cipher_key_len (cipher) == 0)
    return GF_ERR_UNSUPPORTED;
  if (keylen != gf_cipher_key_len (cipher)
      || ivlen != gf_cipher_iv_len (cipher) || key == NULL
      || (ivlen > 0 && iv == NULL))
    return GF_ERR_INVAL;
  d = dir == GF_DIR_READ ? &p->read : &p->write;
  /* A shorter key or an IV the new cipher does not use must not leave the
     previous epoch's material in the tail of these arrays.  */
  gf_wipe (d->key, sizeof d->key);
  gf_wipe (d->iv, sizeof d->iv);
  d->cipher = cipher;
  memcpy (d->key, key, keylen);
  d->keylen = keylen;
  if (ivlen > 0)
    memcpy (d->iv, iv, ivlen);
  if (reset_seq)
    d->seq = 0;
  d->packets = 0;
  d->bytes = 0;
  return GF_OK;
}

uint32_t
gf_packet_seq (const gf_packet *p, enum gf_dir dir)
{
  return dir == GF_DIR_READ ? p->read.seq : p->write.seq;
}

uint64_t
gf_packet_count (const gf_packet *p, enum gf_dir dir)
{
  return dir == GF_DIR_READ ? p->read.packets : p->write.packets;
}

uint64_t
gf_packet_bytes (const gf_packet *p, enum gf_dir dir)
{
  return dir == GF_DIR_READ ? p->read.bytes : p->write.bytes;
}

static void
put_be32 (uint8_t *b, uint32_t v)
{
  b[0] = (uint8_t) (v >> 24);
  b[1] = (uint8_t) (v >> 16);
  b[2] = (uint8_t) (v >> 8);
  b[3] = (uint8_t) v;
}

static uint32_t
get_be32 (const uint8_t *b)
{
  return (uint32_t) b[0] << 24 | (uint32_t) b[1] << 16
    | (uint32_t) b[2] << 8 | b[3];
}

/* The GCM invocation counter is the last eight bytes of the IV, a
   big-endian integer incremented after every packet (RFC 5647 section
   7.1).  */
static void
gcm_next_iv (uint8_t iv[12])
{
  int i;

  for (i = 11; i >= 4; i--)
    if (++iv[i] != 0)
      break;
}

/* ------------------------------------------------------------------ */
/* chacha20-poly1305@openssh.com                                      */
/* ------------------------------------------------------------------ */

/* The nonce of both ChaCha20 instances is the sequence number as a
   64-bit big-endian integer.  K_2 (the first 32 bytes of the key
   material) protects the payload and, with block counter zero, gives the
   Poly1305 key; the payload uses counter one onward.  K_1 (the next 32
   bytes) encrypts the length with counter zero.  The tag covers the
   encrypted length and the encrypted rest of the packet.  */
static void
chacha_nonce (uint8_t nonce[8], uint32_t seq)
{
  memset (nonce, 0, 4);
  put_be32 (nonce + 4, seq);
}

static int
chacha_open (gcry_cipher_hd_t *h, const uint8_t *key, uint32_t seq)
{
  uint8_t nonce[8];

  if (gcry_cipher_open (h, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM,
                        GCRY_CIPHER_SECURE))
    return GF_ERR_CRYPTO;
  chacha_nonce (nonce, seq);
  if (gcry_cipher_setkey (*h, key, CHACHA_KEY_LEN)
      || gcry_cipher_setiv (*h, nonce, sizeof nonce))
    {
      gcry_cipher_close (*h);
      return GF_ERR_CRYPTO;
    }
  return GF_OK;
}

/* Encrypt or decrypt the four length bytes (a stream cipher does both).  */
static int
chacha_length (const struct gf_pkt_dir *d, const uint8_t in[4],
               uint8_t out[4])
{
  gcry_cipher_hd_t h;
  int r = chacha_open (&h, d->key + CHACHA_KEY_LEN, d->seq);

  if (r != GF_OK)
    return r;
  if (gcry_cipher_encrypt (h, out, 4, in, 4))
    r = GF_ERR_CRYPTO;
  gcry_cipher_close (h);
  return r;
}

/* Start the main cipher: consume block zero for the Poly1305 key.  */
static int
chacha_main (const struct gf_pkt_dir *d, gcry_cipher_hd_t *h,
             uint8_t polykey[POLY_KEY_LEN])
{
  static const uint8_t zeros[64];
  uint8_t block[64];
  int r = chacha_open (h, d->key, d->seq);

  if (r != GF_OK)
    return r;
  if (gcry_cipher_encrypt (*h, block, sizeof block, zeros, sizeof zeros))
    {
      gcry_cipher_close (*h);
      return GF_ERR_CRYPTO;
    }
  memcpy (polykey, block, POLY_KEY_LEN);
  gf_wipe (block, sizeof block);
  return GF_OK;
}

static int
poly_tag (const uint8_t polykey[POLY_KEY_LEN], const uint8_t *data,
          size_t len, uint8_t tag[GF_TAG_LEN])
{
  gcry_mac_hd_t m;
  size_t n = GF_TAG_LEN;
  int r = GF_ERR_CRYPTO;

  if (gcry_mac_open (&m, GCRY_MAC_POLY1305, GCRY_MAC_FLAG_SECURE, NULL))
    return GF_ERR_CRYPTO;
  if (gcry_mac_setkey (m, polykey, POLY_KEY_LEN) == 0
      && gcry_mac_write (m, data, len) == 0
      && gcry_mac_read (m, tag, &n) == 0 && n == GF_TAG_LEN)
    r = GF_OK;
  gcry_mac_close (m);
  return r;
}

/* PKT holds the length field and, after it, the plaintext of the rest
   (LEN bytes); seal in place.  */
static int
chacha_seal (const struct gf_pkt_dir *d, uint8_t *pkt, size_t len)
{
  gcry_cipher_hd_t h;
  uint8_t polykey[POLY_KEY_LEN], lenbuf[4];
  int r = chacha_main (d, &h, polykey);

  if (r != GF_OK)
    return r;
  if (gcry_cipher_encrypt (h, pkt + 4, len, NULL, 0))
    r = GF_ERR_CRYPTO;
  gcry_cipher_close (h);
  if (r == GF_OK)
    r = chacha_length (d, pkt, lenbuf);
  if (r == GF_OK)
    {
      memcpy (pkt, lenbuf, 4);
      r = poly_tag (polykey, pkt, 4 + len, pkt + 4 + len);
    }
  gf_wipe (polykey, sizeof polykey);
  return r;
}

/* PKT holds the whole packet with the encrypted length; LEN is the
   packet_length.  Verify the tag, then decrypt PKT + 4 in place.  */
static int
chacha_open_packet (const struct gf_pkt_dir *d, uint8_t *pkt, size_t len)
{
  gcry_cipher_hd_t h;
  uint8_t polykey[POLY_KEY_LEN], tag[GF_TAG_LEN];
  int r = chacha_main (d, &h, polykey);

  if (r != GF_OK)
    return r;
  r = poly_tag (polykey, pkt, 4 + len, tag);
  gf_wipe (polykey, sizeof polykey);
  if (r == GF_OK && !gf_ct_equal (tag, pkt + 4 + len, GF_TAG_LEN))
    r = GF_ERR_CRYPTO;
  if (r == GF_OK && gcry_cipher_decrypt (h, pkt + 4, len, NULL, 0))
    r = GF_ERR_CRYPTO;
  gcry_cipher_close (h);
  return r;
}

/* ------------------------------------------------------------------ */
/* AES-GCM                                                            */
/* ------------------------------------------------------------------ */

static int
gcm_open (const struct gf_pkt_dir *d, gcry_cipher_hd_t *h, const uint8_t *aad)
{
  if (gcry_cipher_open (h, d->cipher == GF_CIPHER_AES128_GCM
                           ? GCRY_CIPHER_AES128 : GCRY_CIPHER_AES256,
                        GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_SECURE))
    return GF_ERR_CRYPTO;
  if (gcry_cipher_setkey (*h, d->key, d->keylen)
      || gcry_cipher_setiv (*h, d->iv, 12)
      || gcry_cipher_authenticate (*h, aad, 4))
    {
      gcry_cipher_close (*h);
      return GF_ERR_CRYPTO;
    }
  return GF_OK;
}

static int
gcm_seal (const struct gf_pkt_dir *d, uint8_t *pkt, size_t len)
{
  gcry_cipher_hd_t h;
  int r = gcm_open (d, &h, pkt);

  if (r != GF_OK)
    return r;
  if (gcry_cipher_encrypt (h, pkt + 4, len, NULL, 0)
      || gcry_cipher_gettag (h, pkt + 4 + len, GF_TAG_LEN))
    r = GF_ERR_CRYPTO;
  gcry_cipher_close (h);
  return r;
}

static int
gcm_open_packet (const struct gf_pkt_dir *d, uint8_t *pkt, size_t len)
{
  gcry_cipher_hd_t h;
  int r = gcm_open (d, &h, pkt);

  if (r != GF_OK)
    return r;
  if (gcry_cipher_decrypt (h, pkt + 4, len, NULL, 0)
      || gcry_cipher_checktag (h, pkt + 4 + len, GF_TAG_LEN))
    {
      r = GF_ERR_CRYPTO;
      gf_wipe (pkt + 4, len);	/* Never leave unauthenticated plaintext.  */
    }
  gcry_cipher_close (h);
  return r;
}

/* ------------------------------------------------------------------ */
/* Sending                                                            */
/* ------------------------------------------------------------------ */

static void
count_packet (struct gf_pkt_dir *d, size_t total)
{
  d->seq++;
  d->packets++;
  d->bytes += total;
  if (is_gcm (d->cipher))
    gcm_next_iv (d->iv);
}

/* Smallest padding of at least four bytes that aligns the packet.  */
static size_t
min_padding (const struct gf_pkt_dir *d, size_t payload)
{
  size_t bs = d->cipher == GF_CIPHER_NONE ? 8 : gf_cipher_block_len (d->cipher);
  /* The plaintext direction aligns the whole packet; the others align
     everything after the length field.  */
  size_t base = (d->cipher == GF_CIPHER_NONE ? 4 : 0) + 1 + payload;
  size_t pad = bs - base % bs;

  if (pad < 4)
    pad += bs;
  return pad;
}

int
gf_packet_send_padded (gf_packet *p, const uint8_t *payload, size_t len,
                       const uint8_t *padding, size_t padlen,
                       uint8_t *out, size_t cap, size_t *outlen)
{
  struct gf_pkt_dir *d;
  size_t pl, taglen, total, bs, base;
  int r = GF_OK;

  if (p == NULL || payload == NULL || padding == NULL || out == NULL
      || outlen == NULL || len == 0)
    return GF_ERR_INVAL;
  d = &p->write;
  taglen = d->cipher == GF_CIPHER_NONE ? 0 : GF_TAG_LEN;
  if (len > GF_MAX_PACKET)
    return GF_ERR_RANGE;
  bs = d->cipher == GF_CIPHER_NONE ? 8 : gf_cipher_block_len (d->cipher);
  base = (d->cipher == GF_CIPHER_NONE ? 4 : 0) + 1 + len;
  if (padlen < 4 || padlen > 255 || (base + padlen) % bs != 0)
    return GF_ERR_INVAL;
  pl = 1 + len + padlen;
  total = 4 + pl + taglen;
  if (total > GF_MAX_PACKET)
    return GF_ERR_RANGE;
  if (cap < total)
    return GF_ERR_BUFSIZE;
  if (d->seq == UINT32_MAX)
    return GF_ERR_RANGE;

  put_be32 (out, (uint32_t) pl);
  out[4] = (uint8_t) padlen;
  memcpy (out + 5, payload, len);
  memcpy (out + 5 + len, padding, padlen);
  switch (d->cipher)
    {
    case GF_CIPHER_NONE:
      break;
    case GF_CIPHER_CHACHA20_POLY1305:
      r = chacha_seal (d, out, pl);
      break;
    default:
      r = gcm_seal (d, out, pl);
      break;
    }
  if (r != GF_OK)
    {
      gf_wipe (out, total);
      return r;
    }
  count_packet (d, total);
  *outlen = total;
  return GF_OK;
}

int
gf_packet_send (gf_packet *p, const uint8_t *payload, size_t len,
                uint8_t *out, size_t cap, size_t *outlen)
{
  uint8_t pad[32];
  size_t padlen;
  int r;

  if (p == NULL || len == 0)
    return GF_ERR_INVAL;
  if (len > GF_MAX_PACKET)
    return GF_ERR_RANGE;
  padlen = min_padding (&p->write, len);
  r = gf_random (pad, padlen);
  if (r != GF_OK)
    return r;
  return gf_packet_send_padded (p, payload, len, pad, padlen, out, cap,
                                outlen);
}

/* ------------------------------------------------------------------ */
/* Receiving                                                          */
/* ------------------------------------------------------------------ */

/* Look at the start of the stream: the packet_length if four bytes are
   there (GF_OK), or GF_NEED_MORE.  Checks the length for every cipher.  */
static int
peek_length (const struct gf_pkt_dir *d, const uint8_t *buf, size_t avail,
             uint32_t *pl)
{
  uint8_t lenbuf[4];
  size_t bs;
  int r;

  if (avail < 4)
    return GF_NEED_MORE;
  switch (d->cipher)
    {
    case GF_CIPHER_CHACHA20_POLY1305:
      r = chacha_length (d, buf, lenbuf);
      if (r != GF_OK)
        return r;
      *pl = get_be32 (lenbuf);
      break;
    default:
      *pl = get_be32 (buf);
      break;
    }

  /* The shortest packet has a padding length byte, one payload byte and
     four bytes of padding.  Everything is bounded before we commit to
     waiting for that many bytes.  */
  if (*pl < 6 || *pl > GF_MAX_PACKET)
    return GF_ERR_ENCODING;
  bs = d->cipher == GF_CIPHER_NONE ? 8 : gf_cipher_block_len (d->cipher);
  if (((d->cipher == GF_CIPHER_NONE ? 4 : 0) + *pl) % bs != 0)
    return GF_ERR_ENCODING;
  return GF_OK;
}

int
gf_packet_receive (gf_packet *p, uint8_t **buf, size_t *len,
                   gf_packet_cb cb, void *user)
{
  if (p == NULL || buf == NULL || len == NULL || cb == NULL)
    return GF_ERR_INVAL;

  while (*len > 0)
    {
      struct gf_pkt_dir *d = &p->read;
      uint8_t *pkt = *buf;
      uint32_t pl;
      size_t taglen = d->cipher == GF_CIPHER_NONE ? 0 : GF_TAG_LEN, total;
      uint8_t padlen;
      int r = peek_length (d, pkt, *len, &pl);

      if (r != GF_OK)
        return r;
      total = 4 + (size_t) pl + taglen;
      if (total > GF_MAX_PACKET)
        return GF_ERR_ENCODING;
      if (*len < total)
        return GF_NEED_MORE;
      if (d->seq == UINT32_MAX)
        return GF_ERR_RANGE;

      switch (d->cipher)
        {
        case GF_CIPHER_NONE:
          r = GF_OK;
          break;
        case GF_CIPHER_CHACHA20_POLY1305:
          r = chacha_open_packet (d, pkt, pl);
          break;
        default:
          r = gcm_open_packet (d, pkt, pl);
          break;
        }
      if (r != GF_OK)
        return r;

      padlen = pkt[4];
      if (padlen < 4 || (size_t) padlen + 1 >= pl)
        return GF_ERR_ENCODING;

      count_packet (d, total);
      *buf += total;
      *len -= total;
      if (cb (user, pkt + 5, pl - padlen - 1) != 0)
        return GF_ERR_HANDLER;
    }
  return GF_OK;
}
