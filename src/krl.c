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
#include <foxtrot/wire.h>
#include <foxtrot/key.h>
#include <foxtrot/krl.h>

#define KRL_MAGIC "SSHKRL\n"	/* And a NUL: eight bytes.  */
#define KRL_FORMAT_VERSION 1

#define SECTION_CERTIFICATES 1
#define SECTION_EXPLICIT_KEY 2
#define SECTION_FINGERPRINT_SHA1 3
#define SECTION_SIGNATURE 4
#define SECTION_FINGERPRINT_SHA256 5
#define SECTION_EXTENSION 255

#define CERT_SERIAL_LIST 0x20
#define CERT_SERIAL_RANGE 0x21
#define CERT_SERIAL_BITMAP 0x22
#define CERT_KEY_ID 0x23
#define CERT_EXTENSION 0x39

struct item
{
  uint8_t *p;
  size_t n;
};

/* Byte strings, sorted by length and then content once loaded.  */
struct set
{
  struct item *v;
  size_t n, cap;
};

struct range
{
  uint64_t lo, hi;
};

/* What one certificates section revokes, for one CA or for all.  */
struct group
{
  uint8_t *ca;			/* The CA key blob; NULL for any CA.  */
  size_t calen;
  struct range *r;
  size_t nr, capr;
  struct set ids;
};

struct gf_krl
{
  struct set keys, sha1, sha256;
  struct group *g;
  size_t ng, capg;
  size_t entries;
  int loaded;			/* A list has been loaded.  */
  uint64_t version, generated;
  uint8_t *comment;
  size_t commentlen;
};

int
gf_krl_new (gf_krl **out)
{
  if (out == NULL)
    return GF_ERR_INVAL;
  *out = calloc (1, sizeof **out);
  return *out ? GF_OK : GF_ERR_NOMEM;
}

static void
set_free (struct set *s)
{
  size_t i;

  for (i = 0; i < s->n; i++)
    free (s->v[i].p);
  free (s->v);
  memset (s, 0, sizeof *s);
}

static void
group_free (struct group *g)
{
  free (g->ca);
  free (g->r);
  set_free (&g->ids);
}

static void
krl_clear (gf_krl *k)
{
  size_t i;

  set_free (&k->keys);
  set_free (&k->sha1);
  set_free (&k->sha256);
  for (i = 0; i < k->ng; i++)
    group_free (&k->g[i]);
  free (k->g);
  free (k->comment);
  memset (k, 0, sizeof *k);
}

void
gf_krl_free (gf_krl *k)
{
  if (k == NULL)
    return;
  krl_clear (k);
  free (k);
}

size_t
gf_krl_count (const gf_krl *k)
{
  return k ? k->entries : 0;
}

void
gf_krl_get_info (const gf_krl *k, gf_krl_info *info)
{
  if (info == NULL)
    return;
  memset (info, 0, sizeof *info);
  if (k == NULL)
    return;
  info->version = k->version;
  info->generated = k->generated;
  info->comment.data = k->comment;
  info->comment.len = k->commentlen;
}

/* ---- building ---- */

static int
set_add (struct set *s, const uint8_t *p, size_t n)
{
  uint8_t *c;

  if (s->n == s->cap)
    {
      size_t nc = s->cap ? s->cap * 2 : 16;
      struct item *nv = realloc (s->v, nc * sizeof *nv);

      if (nv == NULL)
        return GF_ERR_NOMEM;
      s->v = nv;
      s->cap = nc;
    }
  c = malloc (n ? n : 1);
  if (c == NULL)
    return GF_ERR_NOMEM;
  memcpy (c, p, n);
  s->v[s->n].p = c;
  s->v[s->n].n = n;
  s->n++;
  return GF_OK;
}

static int
item_cmp (const void *a, const void *b)
{
  const struct item *x = a, *y = b;

  if (x->n != y->n)
    return x->n < y->n ? -1 : 1;
  return x->n ? memcmp (x->p, y->p, x->n) : 0;
}

static void
set_sort (struct set *s)
{
  if (s->n > 1)
    qsort (s->v, s->n, sizeof *s->v, item_cmp);
}

struct lookup
{
  const uint8_t *p;
  size_t n;
};

static int
lookup_cmp (const void *a, const void *b)
{
  const struct lookup *x = a;
  const struct item *y = b;

  if (x->n != y->n)
    return x->n < y->n ? -1 : 1;
  return x->n ? memcmp (x->p, y->p, x->n) : 0;
}

static int
set_has (const struct set *s, const uint8_t *p, size_t n)
{
  struct lookup key;

  key.p = p;
  key.n = n;
  return s->n > 0 && bsearch (&key, s->v, s->n, sizeof *s->v, lookup_cmp) != NULL;
}

static int
range_cmp (const void *a, const void *b)
{
  const struct range *x = a, *y = b;

  if (x->lo != y->lo)
    return x->lo < y->lo ? -1 : 1;
  return x->hi < y->hi ? -1 : x->hi > y->hi;
}

/* Sort and merge overlapping and adjacent ranges.  */
static void
ranges_normalize (struct group *g)
{
  size_t i, o = 0;

  if (g->nr < 2)
    return;
  qsort (g->r, g->nr, sizeof *g->r, range_cmp);
  for (i = 1; i < g->nr; i++)
    {
      if (g->r[i].lo <= g->r[o].hi
          || (g->r[o].hi != UINT64_MAX && g->r[i].lo == g->r[o].hi + 1))
        {
          if (g->r[i].hi > g->r[o].hi)
            g->r[o].hi = g->r[i].hi;
        }
      else
        g->r[++o] = g->r[i];
    }
  g->nr = o + 1;
}

static int
range_add (struct group *g, uint64_t lo, uint64_t hi)
{
  if (g->nr == g->capr)
    {
      size_t nc = g->capr ? g->capr * 2 : 16;
      struct range *nr = realloc (g->r, nc * sizeof *nr);

      if (nr == NULL)
        return GF_ERR_NOMEM;
      g->r = nr;
      g->capr = nc;
    }
  g->r[g->nr].lo = lo;
  g->r[g->nr].hi = hi;
  g->nr++;
  return GF_OK;
}

static int
range_has (const struct group *g, uint64_t serial)
{
  size_t lo = 0, hi = g->nr;

  while (lo < hi)
    {
      size_t mid = lo + (hi - lo) / 2;

      if (serial < g->r[mid].lo)
        hi = mid;
      else if (serial > g->r[mid].hi)
        lo = mid + 1;
      else
        return 1;
    }
  return 0;
}

/* ---- parsing ---- */

/* Counts entries against the limit, over everything loaded.  */
struct ctx
{
  gf_krl *t;			/* What this list adds.  */
  size_t base;			/* The entries already in the list.  */
  size_t groups;		/* The certificates sections already in it.  */
};

static int
count_entry (struct ctx *c)
{
  if (c->base + c->t->entries >= GF_KRL_MAX_ENTRIES)
    return GF_ERR_RANGE;
  c->t->entries++;
  return GF_OK;
}

/* Sections 2, 3 and 5: strings, each of length WANT unless that is 0.  */
static int
blob_section (struct ctx *c, struct set *s, gf_slice data, size_t want)
{
  gf_reader r;

  gf_reader_init (&r, data.data, data.len);
  while (gf_rd_remaining (&r) > 0)
    {
      gf_slice b;
      int rc;

      if (gf_rd_string (&r, &b) != GF_OK || (want != 0 && b.len != want))
        return GF_ERR_ENCODING;
      if (b.len == 0)
        continue;		/* Matches nothing.  */
      rc = count_entry (c);
      if (rc == GF_OK)
        rc = set_add (s, b.data, b.len);
      if (rc != GF_OK)
        return rc;
    }
  return GF_OK;
}

/* An extension: name, critical flag, contents.  One we must understand
   would fail the list; we understand none.  */
static int
extension (gf_slice data)
{
  gf_reader r;
  gf_slice name, contents;
  int critical;

  gf_reader_init (&r, data.data, data.len);
  if (gf_rd_string (&r, &name) != GF_OK || gf_rd_bool (&r, &critical) != GF_OK
      || gf_rd_string (&r, &contents) != GF_OK || gf_rd_finish (&r) != GF_OK)
    return GF_ERR_ENCODING;
  return critical ? GF_ERR_UNSUPPORTED : GF_OK;
}

/* The bits of the mpint MAG, least significant first, are serials from
   OFFSET on: add them as ranges.  */
static int
bitmap (struct ctx *c, struct group *g, uint64_t offset, gf_slice mag)
{
  size_t nbits = mag.len * 8, i;
  int run = 0;
  uint64_t lo = 0, hi = 0;

  for (i = 0; i < nbits; i++)
    {
      size_t byte = mag.len - 1 - i / 8;
      int set = (mag.data[byte] >> (i % 8)) & 1;

      if (!set && (i % 8) == 0 && mag.data[byte] == 0)
        {
          /* A run of zero bytes: skip it whole.  */
          if (run)
            {
              int rc = count_entry (c);

              if (rc == GF_OK)
                rc = range_add (g, lo, hi);
              if (rc != GF_OK)
                return rc;
              run = 0;
            }
          i += 7;
          continue;
        }
      if (set)
        {
          uint64_t s = offset + i;

          if (s < offset || (uint64_t) i > UINT64_MAX - offset)
            return GF_ERR_ENCODING;	/* Wraps.  */
          if (s == 0)
            return GF_ERR_ENCODING;
          if (run)
            hi = s;
          else
            {
              run = 1;
              lo = hi = s;
            }
        }
      else if (run)
        {
          int rc = count_entry (c);

          if (rc == GF_OK)
            rc = range_add (g, lo, hi);
          if (rc != GF_OK)
            return rc;
          run = 0;
        }
    }
  if (run)
    {
      int rc = count_entry (c);

      if (rc == GF_OK)
        rc = range_add (g, lo, hi);
      return rc;
    }
  return GF_OK;
}

static int
cert_subsection (struct ctx *c, struct group *g, uint8_t type, gf_slice data)
{
  gf_reader r;
  int rc;

  gf_reader_init (&r, data.data, data.len);
  switch (type)
    {
    case CERT_SERIAL_LIST:
      while (gf_rd_remaining (&r) > 0)
        {
          uint64_t s;

          if (gf_rd_u64 (&r, &s) != GF_OK || s == 0)
            return GF_ERR_ENCODING;
          rc = count_entry (c);
          if (rc == GF_OK)
            rc = range_add (g, s, s);
          if (rc != GF_OK)
            return rc;
        }
      return GF_OK;
    case CERT_SERIAL_RANGE:
      {
        uint64_t lo, hi;

        if (gf_rd_u64 (&r, &lo) != GF_OK || gf_rd_u64 (&r, &hi) != GF_OK
            || gf_rd_finish (&r) != GF_OK || lo == 0 || lo > hi)
          return GF_ERR_ENCODING;
        rc = count_entry (c);
        return rc == GF_OK ? range_add (g, lo, hi) : rc;
      }
    case CERT_SERIAL_BITMAP:
      {
        uint64_t off;
        gf_slice mag;

        if (gf_rd_u64 (&r, &off) != GF_OK || gf_rd_mpint (&r, &mag) != GF_OK
            || gf_rd_finish (&r) != GF_OK)
          return GF_ERR_ENCODING;
        return bitmap (c, g, off, mag);
      }
    case CERT_KEY_ID:
      while (gf_rd_remaining (&r) > 0)
        {
          gf_slice id;

          if (gf_rd_string (&r, &id) != GF_OK)
            return GF_ERR_ENCODING;
          rc = count_entry (c);
          if (rc == GF_OK)
            rc = set_add (&g->ids, id.data, id.len);
          if (rc != GF_OK)
            return rc;
        }
      return GF_OK;
    case CERT_EXTENSION:
      return extension (data);
    default:
      return GF_ERR_UNSUPPORTED;
    }
}

static int
certificates_section (struct ctx *c, gf_slice data)
{
  gf_reader r;
  gf_slice ca, reserved;
  gf_krl *t = c->t;
  struct group *g;

  gf_reader_init (&r, data.data, data.len);
  if (gf_rd_string (&r, &ca) != GF_OK || gf_rd_string (&r, &reserved) != GF_OK)
    return GF_ERR_ENCODING;
  /* A section is kept, and walked by every check of a certificate, whether
     or not it holds anything, so sections are counted against the limit
     with the entries (though not as entries, for gf_krl_count).  */
  if (c->base + c->t->entries + c->groups + t->ng >= GF_KRL_MAX_ENTRIES)
    return GF_ERR_RANGE;
  if (t->ng == t->capg)
    {
      size_t nc = t->capg ? t->capg * 2 : 8;
      struct group *ng = realloc (t->g, nc * sizeof *ng);

      if (ng == NULL)
        return GF_ERR_NOMEM;
      t->g = ng;
      t->capg = nc;
    }
  g = &t->g[t->ng];
  memset (g, 0, sizeof *g);
  t->ng++;
  if (ca.len > 0)
    {
      g->ca = malloc (ca.len);
      if (g->ca == NULL)
        return GF_ERR_NOMEM;
      memcpy (g->ca, ca.data, ca.len);
      g->calen = ca.len;
    }
  while (gf_rd_remaining (&r) > 0)
    {
      uint8_t type;
      gf_slice sub;
      int rc;

      if (gf_rd_u8 (&r, &type) != GF_OK || gf_rd_string (&r, &sub) != GF_OK)
        return GF_ERR_ENCODING;
      rc = cert_subsection (c, g, type, sub);
      if (rc != GF_OK)
        return rc;
    }
  return GF_OK;
}

static int
parse (struct ctx *c, const uint8_t *data, size_t len)
{
  gf_reader r;
  gf_slice magic, reserved, comment;
  uint32_t format;
  uint64_t flags;
  gf_krl *t = c->t;

  gf_reader_init (&r, data, len);
  if (gf_rd_bytes (&r, 8, &magic) != GF_OK
      || memcmp (magic.data, KRL_MAGIC, 8) != 0)
    return GF_ERR_ENCODING;
  if (gf_rd_u32 (&r, &format) != GF_OK || format != KRL_FORMAT_VERSION
      || gf_rd_u64 (&r, &t->version) != GF_OK
      || gf_rd_u64 (&r, &t->generated) != GF_OK
      || gf_rd_u64 (&r, &flags) != GF_OK
      || gf_rd_string (&r, &reserved) != GF_OK
      || gf_rd_string (&r, &comment) != GF_OK)
    return GF_ERR_ENCODING;
  if (comment.len > 0)
    {
      t->comment = malloc (comment.len + 1);
      if (t->comment == NULL)
        return GF_ERR_NOMEM;
      memcpy (t->comment, comment.data, comment.len);
      t->comment[comment.len] = '\0';
      t->commentlen = comment.len;
    }
  while (gf_rd_remaining (&r) > 0)
    {
      uint8_t type;
      gf_slice sect;
      int rc;

      if (gf_rd_u8 (&r, &type) != GF_OK)
        return GF_ERR_ENCODING;
      /* The signature section has no length of its own: it is not read
         past, because it is not accepted.  */
      if (type == SECTION_SIGNATURE)
        return GF_ERR_UNSUPPORTED;
      if (gf_rd_string (&r, &sect) != GF_OK)
        return GF_ERR_ENCODING;
      switch (type)
        {
        case SECTION_CERTIFICATES:
          rc = certificates_section (c, sect);
          break;
        case SECTION_EXPLICIT_KEY:
          rc = blob_section (c, &t->keys, sect, 0);
          break;
        case SECTION_FINGERPRINT_SHA1:
          rc = blob_section (c, &t->sha1, sect, 20);
          break;
        case SECTION_FINGERPRINT_SHA256:
          rc = blob_section (c, &t->sha256, sect, 32);
          break;
        case SECTION_EXTENSION:
          rc = extension (sect);
          break;
        default:
          rc = GF_ERR_UNSUPPORTED;
        }
      if (rc != GF_OK)
        return rc;
    }
  return GF_OK;
}

/* Move what T holds into K and make it ready for lookups.  */
static int
merge (gf_krl *k, gf_krl *t)
{
  struct item *ni;
  struct group *ng;
  size_t i;
  struct set *dst[3] = { &k->keys, &k->sha1, &k->sha256 };
  struct set *src[3] = { &t->keys, &t->sha1, &t->sha256 };

  /* Everything that can fail first, so that a failure changes nothing.  */
  for (i = 0; i < 3; i++)
    {
      if (src[i]->n == 0)
        continue;
      ni = realloc (dst[i]->v, (dst[i]->n + src[i]->n) * sizeof *ni);
      if (ni == NULL)
        return GF_ERR_NOMEM;
      dst[i]->v = ni;
      dst[i]->cap = dst[i]->n + src[i]->n;
    }
  if (t->ng > 0)
    {
      ng = realloc (k->g, (k->ng + t->ng) * sizeof *ng);
      if (ng == NULL)
        return GF_ERR_NOMEM;
      k->g = ng;
      k->capg = k->ng + t->ng;
    }
  for (i = 0; i < 3; i++)
    {
      if (src[i]->n == 0)
        continue;
      memcpy (dst[i]->v + dst[i]->n, src[i]->v, src[i]->n * sizeof *ni);
      dst[i]->n += src[i]->n;
      set_sort (dst[i]);
    }
  for (i = 0; i < t->ng; i++)
    {
      ranges_normalize (&t->g[i]);
      set_sort (&t->g[i].ids);
      k->g[k->ng++] = t->g[i];
    }
  k->entries += t->entries;
  if (!k->loaded || t->version >= k->version)
    {
      free (k->comment);
      k->comment = t->comment;
      k->commentlen = t->commentlen;
      k->version = t->version;
      k->generated = t->generated;
      t->comment = NULL;
    }
  k->loaded = 1;
  /* What was moved is no longer T's.  */
  for (i = 0; i < 3; i++)
    {
      free (src[i]->v);
      memset (src[i], 0, sizeof *src[i]);
    }
  free (t->g);
  t->g = NULL;
  t->ng = 0;
  return GF_OK;
}

int
gf_krl_load (gf_krl *k, const uint8_t *data, size_t len)
{
  gf_krl t;
  struct ctx c;
  int rc;

  if (k == NULL || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  if (len > GF_KRL_MAX_SIZE)
    return GF_ERR_RANGE;
  memset (&t, 0, sizeof t);
  c.t = &t;
  c.base = k->entries;
  c.groups = k->ng;
  rc = parse (&c, data, len);
  if (rc == GF_OK)
    rc = merge (k, &t);
  krl_clear (&t);
  return rc;
}

/* ---- checking ---- */

/* Is the key whose blob is B (N bytes) revoked by hash or in full?  */
static int
blob_revoked (const gf_krl *k, const uint8_t *b, size_t n, int *err)
{
  uint8_t h1[20], h2[32];

  if (gf_crypto_init () != GF_OK)
    {
      *err = GF_ERR_CRYPTO;
      return 0;
    }
  gcry_md_hash_buffer (GCRY_MD_SHA1, h1, b, n);
  gcry_md_hash_buffer (GCRY_MD_SHA256, h2, b, n);
  return set_has (&k->sha1, h1, sizeof h1) || set_has (&k->sha256, h2, sizeof h2)
    || set_has (&k->keys, b, n);
}

int
gf_krl_check (const gf_krl *k, const gf_key *key)
{
  const uint8_t *pb, *cb;
  size_t pn, cn, i;
  int err = 0;

  if (k == NULL || key == NULL)
    return GF_ERR_INVAL;
  pb = gf_key_plain_blob (key, &pn);
  if (pb == NULL)
    return GF_ERR_INVAL;
  if (blob_revoked (k, pb, pn, &err))
    return 1;
  if (err)
    return err;
  if (gf_key_is_certificate (key))
    {
      gf_cert_info ci;

      if (gf_key_certificate_info (key, &ci) != GF_OK)
        return GF_ERR_INVAL;
      cb = gf_key_blob (ci.ca, &cn);
      if (blob_revoked (k, cb, cn, &err))
        return 1;
      if (err)
        return err;
      for (i = 0; i < k->ng; i++)
        {
          const struct group *g = &k->g[i];

          if (g->ca != NULL && (g->calen != cn || memcmp (g->ca, cb, cn) != 0))
            continue;
          if (set_has (&g->ids, ci.key_id.data, ci.key_id.len))
            return 1;
          /* A certificate with no serial has none to revoke by.  */
          if (ci.serial != 0 && range_has (g, ci.serial))
            return 1;
        }
    }
  return 0;
}
