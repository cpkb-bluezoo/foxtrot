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

#include "gettext.h"

#define GF_MIN_GCRYPT "1.12.0"

void
gf_wipe (void *secret, size_t len)
{
  volatile uint8_t *p = secret;

  while (len--)
    *p++ = 0;
}

int
gf_ct_equal (const void *a, const void *b, size_t n)
{
  const uint8_t *x = a, *y = b;
  uint8_t diff = 0;
  size_t i;

  for (i = 0; i < n; i++)
    diff |= x[i] ^ y[i];
  return diff == 0;
}

int
gf_crypto_init (void)
{
  gfi_i18n_init ();
  if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    return GF_OK;
  if (!gcry_check_version (GF_MIN_GCRYPT))
    return GF_ERR_CRYPTO;
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  return GF_OK;
}

int
gf_random (void *buf, size_t len)
{
  int r = gf_crypto_init ();

  if (r != GF_OK)
    return r;
  gcry_randomize (buf, len, GCRY_STRONG_RANDOM);
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Hashes                                                             */
/* ------------------------------------------------------------------ */

size_t
gf_hash_size (enum gf_hash alg)
{
  switch (alg)
    {
    case GF_HASH_SHA256: return 32;
    case GF_HASH_SHA384: return 48;
    case GF_HASH_SHA512: return 64;
    default:             return 0;
    }
}

static int
hash_algo (enum gf_hash alg)
{
  switch (alg)
    {
    case GF_HASH_SHA256: return GCRY_MD_SHA256;
    case GF_HASH_SHA384: return GCRY_MD_SHA384;
    case GF_HASH_SHA512: return GCRY_MD_SHA512;
    default:             return 0;
    }
}

int
gf_hash_compute (enum gf_hash alg, const void *data, size_t len,
                 uint8_t *out, size_t outlen)
{
  int r = gf_crypto_init ();

  if (r != GF_OK)
    return r;
  if (gf_hash_size (alg) == 0)
    return GF_ERR_UNSUPPORTED;
  if (outlen != gf_hash_size (alg) || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  gcry_md_hash_buffer (hash_algo (alg), out, data, len);
  return GF_OK;
}

struct gf_hash_ctx
{
  gcry_md_hd_t md;
  enum gf_hash alg;
  int final;
};

int
gf_hash_new (gf_hash_ctx **out, enum gf_hash alg)
{
  gf_hash_ctx *h;
  int r = gf_crypto_init ();

  if (r != GF_OK)
    return r;
  if (out == NULL)
    return GF_ERR_INVAL;
  if (gf_hash_size (alg) == 0)
    return GF_ERR_UNSUPPORTED;
  h = calloc (1, sizeof *h);
  if (h == NULL)
    return GF_ERR_NOMEM;
  /* The hashed data includes the shared secret.  */
  if (gcry_md_open (&h->md, hash_algo (alg), GCRY_MD_FLAG_SECURE))
    {
      free (h);
      return GF_ERR_CRYPTO;
    }
  h->alg = alg;
  *out = h;
  return GF_OK;
}

void
gf_hash_free (gf_hash_ctx *h)
{
  if (h == NULL)
    return;
  gcry_md_close (h->md);
  free (h);
}

int
gf_hash_update (gf_hash_ctx *h, const void *data, size_t len)
{
  if (h == NULL || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  if (h->final)
    return GF_ERR_STATE;
  if (len > 0)
    gcry_md_write (h->md, data, len);
  return GF_OK;
}

int
gf_hash_update_u32 (gf_hash_ctx *h, uint32_t v)
{
  uint8_t b[4];

  b[0] = (uint8_t) (v >> 24);
  b[1] = (uint8_t) (v >> 16);
  b[2] = (uint8_t) (v >> 8);
  b[3] = (uint8_t) v;
  return gf_hash_update (h, b, 4);
}

int
gf_hash_update_string (gf_hash_ctx *h, const void *data, size_t len)
{
  int r;

  if (len > UINT32_MAX)
    return GF_ERR_RANGE;
  r = gf_hash_update_u32 (h, (uint32_t) len);
  if (r == GF_OK)
    r = gf_hash_update (h, data, len);
  return r;
}

int
gf_hash_update_mpint (gf_hash_ctx *h, const void *data, size_t len)
{
  const uint8_t *p = data;
  static const uint8_t zero = 0;
  int r;

  if (h == NULL || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  while (len > 0 && *p == 0)
    p++, len--;
  /* A magnitude with its top bit set needs a leading zero byte to stay
     positive (RFC 4251 section 5).  */
  if (len > 0 && (p[0] & 0x80))
    {
      if (len + 1 > UINT32_MAX)
        return GF_ERR_RANGE;
      r = gf_hash_update_u32 (h, (uint32_t) (len + 1));
      if (r == GF_OK)
        r = gf_hash_update (h, &zero, 1);
    }
  else
    r = gf_hash_update_u32 (h, (uint32_t) len);
  if (r == GF_OK)
    r = gf_hash_update (h, p, len);
  return r;
}

int
gf_hash_final (gf_hash_ctx *h, uint8_t *out, size_t outlen)
{
  if (h == NULL || out == NULL || outlen != gf_hash_size (h->alg))
    return GF_ERR_INVAL;
  if (!h->final)
    {
      gcry_md_final (h->md);
      h->final = 1;
    }
  memcpy (out, gcry_md_read (h->md, hash_algo (h->alg)), outlen);
  return GF_OK;
}
