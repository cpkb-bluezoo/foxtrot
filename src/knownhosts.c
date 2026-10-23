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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>
#include <foxtrot/knownhosts.h>

#include "internal.h"

#define MAX_LINE 65536
#define MAX_HOST 255
#define SALT_LEN 20		/* The size of a SHA-1 output, as OpenSSH.  */

enum marker
{
  M_NONE,
  M_CA,
  M_REVOKED
};

struct entry
{
  enum marker marker;
  int hashed;
  char *patterns;		/* Lower case, comma separated.  */
  size_t plen;
  uint8_t salt[SALT_LEN], hash[SALT_LEN];
  gf_key *key;			/* Never a certificate.  */
};

struct gf_knownhosts
{
  struct entry *e;
  size_t n, cap;
};

int
gf_knownhosts_new (gf_knownhosts **out)
{
  if (out == NULL)
    return GF_ERR_INVAL;
  *out = calloc (1, sizeof **out);
  return *out ? GF_OK : GF_ERR_NOMEM;
}

void
gf_knownhosts_free (gf_knownhosts *kh)
{
  size_t i;

  if (kh == NULL)
    return;
  for (i = 0; i < kh->n; i++)
    {
      free (kh->e[i].patterns);
      gf_key_free (kh->e[i].key);
    }
  free (kh->e);
  free (kh);
}

static char
lower (char c)
{
  return c >= 'A' && c <= 'Z' ? (char) (c - 'A' + 'a') : c;
}

/* The name as it is looked up: lower case, and "[name]:port" unless the port
   is 22.  Returns its length, or 0 if the host cannot be a host name.  */
static size_t
lookup_name (char *out, size_t cap, const char *host, unsigned port)
{
  size_t n, i, o = 0;

  if (host == NULL)
    return 0;
  n = strlen (host);
  if (n == 0 || n > MAX_HOST || cap < MAX_HOST + 16)
    return 0;
  /* What a line would read as something else: a comment, a marker or a
     negation at the start, a pattern or bracketed port anywhere.  A
     wildcard would make the key good for other hosts.  '@' is user@host,
     which is not a host: a pattern such as *.example.com must not match
     it.  */
  if (host[0] == '#' || host[0] == '@' || host[0] == '!')
    return 0;
  for (i = 0; i < n; i++)
    if ((unsigned char) host[i] <= ' ' || host[i] == ',' || host[i] == '|'
        || host[i] == '*' || host[i] == '?' || host[i] == '['
        || host[i] == ']' || host[i] == '@')
      return 0;
  if (port != 0 && port != 22)
    out[o++] = '[';
  for (i = 0; i < n; i++)
    out[o++] = lower (host[i]);
  if (port != 0 && port != 22)
    o += (size_t) snprintf (out + o, cap - o, "]:%u", port);
  out[o] = '\0';
  return o;
}

static int
entry_push (gf_knownhosts *kh, struct entry *e)
{
  if (kh->n == kh->cap)
    {
      size_t nc = kh->cap ? kh->cap * 2 : 16;
      struct entry *p = realloc (kh->e, nc * sizeof *p);

      if (p == NULL)
        return GF_ERR_NOMEM;
      kh->e = p;
      kh->cap = nc;
    }
  kh->e[kh->n++] = *e;
  return GF_OK;
}

static int
hmac_sha1 (const uint8_t *salt, const char *name, size_t n, uint8_t *out)
{
  gcry_mac_hd_t h;
  size_t len = SALT_LEN;
  int rc = GF_OK;

  if (gf_crypto_init () != GF_OK
      || gcry_mac_open (&h, GCRY_MAC_HMAC_SHA1, 0, NULL))
    return GF_ERR_CRYPTO;
  if (gcry_mac_setkey (h, salt, SALT_LEN) || gcry_mac_write (h, name, n)
      || gcry_mac_read (h, out, &len) || len != SALT_LEN)
    rc = GF_ERR_CRYPTO;
  gcry_mac_close (h);
  return rc;
}

/* PATTERNS (a comma separated list, lower case) against the name: some
   pattern matches and no excluded one does.  */
static int
match_list (const char *pat, size_t plen, const char *name, size_t nlen)
{
  size_t i = 0;
  int matched = 0;

  while (i <= plen)
    {
      size_t j = i;
      int neg;

      while (j < plen && pat[j] != ',')
        j++;
      neg = j > i && pat[i] == '!';
      if (gfi_wildmatch (pat + i + neg, j - i - neg, name, nlen))
        {
          if (neg)
            return 0;
          matched = 1;
        }
      i = j + 1;
    }
  return matched;
}

static int
entry_matches (const struct entry *e, const char *name, size_t nlen)
{
  uint8_t h[SALT_LEN];

  if (!e->hashed)
    return match_list (e->patterns, e->plen, name, nlen);
  return hmac_sha1 (e->salt, name, nlen, h) == GF_OK
    && gf_ct_equal (h, e->hash, SALT_LEN);
}

/* ---- loading ---- */

static int
is_blank (char c)
{
  return c == ' ' || c == '\t';
}

/* The next blank-separated token of [P, END); advances P.  */
static int
token (const char **p, const char *end, const char **t, size_t *tn)
{
  while (*p < end && is_blank (**p))
    (*p)++;
  if (*p >= end)
    return 0;
  *t = *p;
  while (*p < end && !is_blank (**p))
    (*p)++;
  *tn = (size_t) (*p - *t);
  return 1;
}

/* Parse "|1|salt|hash".  */
static int
parse_hashed (struct entry *e, const char *t, size_t n)
{
  const char *bar;
  uint8_t buf[SALT_LEN + 4];
  long r;

  if (n < 3 || memcmp (t, "|1|", 3) != 0)
    return 0;
  t += 3;
  n -= 3;
  bar = memchr (t, '|', n);
  if (bar == NULL)
    return 0;
  r = gfi_b64_decode (t, (size_t) (bar - t), buf, sizeof buf, 1);
  if (r != SALT_LEN)
    return 0;
  memcpy (e->salt, buf, SALT_LEN);
  r = gfi_b64_decode (bar + 1, n - (size_t) (bar + 1 - t), buf, sizeof buf, 1);
  if (r != SALT_LEN)
    return 0;
  memcpy (e->hash, buf, SALT_LEN);
  e->hashed = 1;
  return 1;
}

/* Comma separated names; empty items (and a lone '!') match nothing and are
   tolerated, as OpenSSH does, but there must be something else.  */
static int
valid_patterns (const char *t, size_t n)
{
  size_t i = 0;
  int real = 0;

  while (i <= n)
    {
      size_t j = i;

      while (j < n && t[j] != ',')
        j++;
      if (j > i && !(t[i] == '!' && j == i + 1))
        real = 1;
      i = j + 1;
    }
  return real;
}

/* One line; returns 1 if it became an entry, 0 if it was refused, -1 for
   an error, 2 for a line that is nothing (blank, comment).  */
static int
load_line (gf_knownhosts *kh, const char *l, size_t n)
{
  const char *p = l, *end = l + n, *t, *hosts;
  size_t tn, hn, i;
  struct entry e;
  gf_key *key = NULL;

  memset (&e, 0, sizeof e);
  while (end > p && (end[-1] == '\r' || is_blank (end[-1])))
    end--;
  if (!token (&p, end, &t, &tn) || t[0] == '#')
    return 2;
  if (t[0] == '@')
    {
      if (tn == 15 && memcmp (t, "@cert-authority", 15) == 0)
        e.marker = M_CA;
      else if (tn == 8 && memcmp (t, "@revoked", 8) == 0)
        e.marker = M_REVOKED;
      else
        return 0;
      if (!token (&p, end, &t, &tn))
        return 0;
    }
  hosts = t;
  hn = tn;
  /* The key: the rest of the line is "TYPE BASE64 [COMMENT]".  */
  while (p < end && is_blank (*p))
    p++;
  if (p >= end || gf_key_from_text (&key, p, (size_t) (end - p), NULL) != GF_OK)
    return 0;
  if (gf_key_is_certificate (key))
    {
      gf_key_free (key);
      return 0;
    }
  if (hn >= 1 && hosts[0] == '|')
    {
      if (!parse_hashed (&e, hosts, hn))
        {
          gf_key_free (key);
          return 0;
        }
    }
  else
    {
      if (!valid_patterns (hosts, hn))
        {
          gf_key_free (key);
          return 0;
        }
      e.patterns = malloc (hn + 1);
      if (e.patterns == NULL)
        {
          gf_key_free (key);
          return -1;
        }
      for (i = 0; i < hn; i++)
        e.patterns[i] = lower (hosts[i]);
      e.patterns[hn] = '\0';
      e.plen = hn;
    }
  e.key = key;
  if (entry_push (kh, &e) != GF_OK)
    {
      free (e.patterns);
      gf_key_free (key);
      return -1;
    }
  return 1;
}

int
gf_knownhosts_load (gf_knownhosts *kh, const char *text, size_t len,
                    size_t *bad)
{
  size_t i = 0, nbad = 0;

  if (kh == NULL || (text == NULL && len > 0))
    return GF_ERR_INVAL;
  while (i < len)
    {
      size_t j = i;
      int r;

      while (j < len && text[j] != '\n')
        j++;
      r = j - i > MAX_LINE ? 0 : load_line (kh, text + i, j - i);
      if (r < 0)
        return GF_ERR_NOMEM;
      if (r == 0)
        nbad++;
      i = j + 1;
    }
  if (bad)
    *bad = nbad;
  return GF_OK;
}

int
gf_knownhosts_add (gf_knownhosts *kh, const char *host, unsigned port,
                   const gf_key *key)
{
  char name[MAX_HOST + 16];
  size_t n;
  struct entry e;
  size_t bl;
  const uint8_t *b;
  int rc;

  if (kh == NULL || key == NULL || gf_key_is_certificate (key))
    return GF_ERR_INVAL;
  n = lookup_name (name, sizeof name, host, port);
  if (n == 0)
    return GF_ERR_INVAL;
  memset (&e, 0, sizeof e);
  e.patterns = malloc (n + 1);
  if (e.patterns == NULL)
    return GF_ERR_NOMEM;
  memcpy (e.patterns, name, n + 1);
  e.plen = n;
  b = gf_key_blob (key, &bl);
  rc = gf_key_from_blob (&e.key, b, bl);
  if (rc == GF_OK)
    rc = entry_push (kh, &e);
  if (rc != GF_OK)
    {
      free (e.patterns);
      gf_key_free (e.key);
    }
  return rc;
}

/* ---- checking ---- */

/* The same public key, whether or not either is a certificate.  */
static int
same_public (const gf_key *a, const gf_key *b)
{
  size_t al, bl;
  const uint8_t *ab = gf_key_plain_blob (a, &al), *bb = gf_key_plain_blob (b, &bl);

  return al == bl && memcmp (ab, bb, al) == 0;
}

enum gf_hostcheck
gf_knownhosts_check (const gf_knownhosts *kh, const char *host, unsigned port,
                     const gf_key *key, uint64_t now)
{
  char name[MAX_HOST + 16], plain[MAX_HOST + 16];
  size_t nn, pn, i;
  int known = 0;
  gf_cert_info ci;
  int cert;

  if (kh == NULL || key == NULL)
    return GF_HOST_UNKNOWN;
  nn = lookup_name (name, sizeof name, host, port);
  pn = lookup_name (plain, sizeof plain, host, 22);
  if (nn == 0)
    return GF_HOST_UNKNOWN;
  cert = gf_key_is_certificate (key);
  if (cert && gf_key_certificate_info (key, &ci) != GF_OK)
    return GF_HOST_UNKNOWN;

  /* Revocation outranks everything: the key, or the CA that signed it.  */
  for (i = 0; i < kh->n; i++)
    {
      const struct entry *e = &kh->e[i];

      if (e->marker == M_REVOKED && entry_matches (e, name, nn)
          && (same_public (e->key, key) || (cert && same_public (e->key, ci.ca))))
        return GF_HOST_REVOKED;
    }
  if (cert)
    for (i = 0; i < kh->n; i++)
      {
        const struct entry *e = &kh->e[i];

        /* A certificate is judged by the name it was dialled by, without
           the port.  */
        if (e->marker == M_CA && entry_matches (e, name, nn)
            && same_public (e->key, ci.ca)
            && gf_cert_check (key, GF_CERT_HOST, now, NULL) == GF_OK
            && gf_cert_has_principal (key, plain, pn, 1))
          return GF_HOST_MATCH;
      }
  for (i = 0; i < kh->n; i++)
    {
      const struct entry *e = &kh->e[i];

      if (e->marker == M_REVOKED || !entry_matches (e, name, nn))
        continue;
      known = 1;
      if (e->marker == M_NONE && same_public (e->key, key))
        return GF_HOST_MATCH;
    }
  return known ? GF_HOST_CHANGED : GF_HOST_UNKNOWN;
}

size_t
gf_knownhosts_sigalgs (const gf_knownhosts *kh, const char *host,
                       unsigned port, enum gf_sigalg *out, size_t cap)
{
  char name[MAX_HOST + 16];
  size_t nn, i, nd, k, j, n = 0;
  const enum gf_sigalg *def = gf_policy_default_sigalgs (&nd);
  int known = 0, ca = 0;

  nn = kh ? lookup_name (name, sizeof name, host, port) : 0;
  for (i = 0; nn && i < kh->n; i++)
    {
      const struct entry *e = &kh->e[i];

      if (e->marker != M_REVOKED && entry_matches (e, name, nn))
        {
          known = 1;
          if (e->marker == M_CA)
            ca = 1;
        }
    }
  for (k = 0; k < nd && n < cap; k++)
    {
      int ok = !known;

      if (known && gf_sigalg_is_cert (def[k]))
        ok = ca;
      else if (known)
        for (i = 0; i < kh->n && !ok; i++)
          {
            const struct entry *e = &kh->e[i];
            size_t na;
            const enum gf_sigalg *a;

            if (e->marker != M_NONE || !entry_matches (e, name, nn))
              continue;
            a = gf_key_sigalgs (e->key, &na);
            for (j = 0; j < na; j++)
              if (a[j] == def[k])
                ok = 1;
          }
      if (ok)
        out[n++] = def[k];
    }
  return n;
}

int
gf_knownhosts_format (char *out, size_t cap, size_t *len, const char *host,
                      unsigned port, const gf_key *key, int hash)
{
  char name[MAX_HOST + 16], text[16384];
  size_t nn, tl, o = 0;
  int rc;

  if (out == NULL || key == NULL || gf_key_is_certificate (key))
    return GF_ERR_INVAL;
  nn = lookup_name (name, sizeof name, host, port);
  if (nn == 0)
    return GF_ERR_INVAL;
  rc = gf_key_to_text (key, text, sizeof text, &tl);
  if (rc != GF_OK)
    return rc;
  if (hash)
    {
      uint8_t salt[SALT_LEN], h[SALT_LEN];

      rc = gf_random (salt, sizeof salt);
      if (rc == GF_OK)
        rc = hmac_sha1 (salt, name, nn, h);
      if (rc != GF_OK)
        return rc;
      if (cap < 3 + 28 + 1 + 28 + 1 + tl + 2)
        return GF_ERR_BUFSIZE;
      memcpy (out, "|1|", 3);
      o = 3;
      o += gfi_b64_encode (salt, sizeof salt, out + o, 1);
      out[o++] = '|';
      o += gfi_b64_encode (h, sizeof h, out + o, 1);
    }
  else
    {
      if (cap < nn + 1 + tl + 2)
        return GF_ERR_BUFSIZE;
      memcpy (out, name, nn);
      o = nn;
    }
  out[o++] = ' ';
  memcpy (out + o, text, tl);
  o += tl;
  out[o++] = '\n';
  out[o] = '\0';
  if (len)
    *len = o;
  return GF_OK;
}
