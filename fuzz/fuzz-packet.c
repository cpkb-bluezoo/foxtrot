#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/packet.h>

#include "fuzz-common.h"

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  return 0;
}

struct sink
{
  size_t n;
  uint8_t last[GF_MAX_PAYLOAD + 64];
  size_t lastlen;
};

static int
collect (void *user, const uint8_t *payload, size_t len)
{
  struct sink *s = user;

  s->n++;
  if (len > 0 && len <= sizeof s->last)
    {
      memcpy (s->last, payload, len);
      s->lastlen = len;
    }
  return 0;
}

static void
keys (gf_packet *p, enum gf_dir dir, enum gf_cipher c)
{
  uint8_t key[64], iv[12];
  size_t kl = gf_cipher_key_len (c), il = gf_cipher_iv_len (c);

  memset (key, 0x5a, sizeof key);
  memset (iv, 0xa5, sizeof iv);
  if (gf_packet_set_keys (p, dir, c, key, kl, iv, il, 0) != GF_OK)
    abort ();
}

/* Raw bytes into each reader (no cipher, then the three), cut into pieces;
   and a packet we seal, damaged in one place or not at all, which must
   either come out as it went in or not come out.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  static const enum gf_cipher ciphers[] = {
    GF_CIPHER_NONE, GF_CIPHER_CHACHA20_POLY1305, GF_CIPHER_AES256_GCM,
    GF_CIPHER_AES128_GCM
  };
  gf_packet p;
  struct sink sink;
  uint8_t *buf;
  size_t mode, chunk, pos = 0;
  enum gf_cipher c;

  if (size < 3)
    return 0;
  mode = data[0] % 8;
  chunk = 1 + data[1] % 200;
  c = ciphers[mode % 4];
  data += 2;
  size -= 2;
  memset (&sink, 0, sizeof sink);
  gf_packet_init (&p);
  if (c != GF_CIPHER_NONE)
    keys (&p, GF_DIR_READ, c);
  if (mode < 4)
    {
      size_t have = 0;

      buf = malloc (size + 1);
      if (buf == NULL)
        return 0;
      while (pos < size)
        {
          size_t n = size - pos < chunk ? size - pos : chunk, len;
          uint8_t *b;
          int rc;

          memcpy (buf + have, data + pos, n);
          have += n;
          pos += n;
          b = buf;
          len = have;
          rc = gf_packet_receive (&p, &b, &len, collect, &sink);
          if (rc == GF_OK)
            have = 0;
          else if (rc == GF_NEED_MORE)
            {
              memmove (buf, b, len);
              have = len;
            }
          else
            break;
        }
      free (buf);
    }
  else
    {
      gf_packet w, r;
      uint8_t out[GF_MAX_PAYLOAD + GF_PKT_OVERHEAD + 64];
      size_t outlen, plen = size > GF_MAX_PAYLOAD ? GF_MAX_PAYLOAD : size;
      uint8_t *b = out;
      size_t n;
      int damaged = 0, rc;

      if (plen == 0)
        return 0;
      gf_packet_init (&w);
      gf_packet_init (&r);
      if (c != GF_CIPHER_NONE)
        {
          keys (&w, GF_DIR_WRITE, c);
          keys (&r, GF_DIR_READ, c);
        }
      if (gf_packet_send (&w, data, plen, out, sizeof out, &outlen) != GF_OK)
        return 0;
      if (size > plen || chunk % 3 == 0)
        {
          /* One bit changed, where the input says.  */
          size_t at = (size_t) data[plen - 1] * 251 % outlen;

          out[at] ^= (uint8_t) (1u << (data[0] % 8));
          damaged = 1;
        }
      n = outlen;
      rc = gf_packet_receive (&r, &b, &n, collect, &sink);
      if (!damaged)
        {
          if (rc != GF_OK || sink.n != 1 || sink.lastlen != plen
              || memcmp (sink.last, data, plen) != 0)
            abort ();
        }
      else if (c != GF_CIPHER_NONE && sink.n != 0 && rc == GF_OK)
        {
          /* An authenticated packet that came out with a bit changed.  */
          if (sink.lastlen == plen && memcmp (sink.last, data, plen) == 0)
            abort ();
        }
      gf_packet_wipe (&w);
      gf_packet_wipe (&r);
    }
  gf_packet_wipe (&p);
  return 0;
}
