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

/* Key revocation lists: what ssh-keygen -k writes, read and asked the way
   ssh-keygen -Q asks, and the lists that must be refused.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>
#include <foxtrot/krl.h>

#include "tst-util.h"
#include "vectors-krl.h"

static uint8_t *
unhex (const char *hex, size_t *n)
{
  size_t cap = strlen (hex) / 2 + 1;
  uint8_t *b = malloc (cap);

  CHECK (b != NULL);
  *n = tst_unhex (hex, b, cap);
  return b;
}

static gf_key *
key_of (const char *hex)
{
  size_t n;
  uint8_t *b = unhex (hex, &n);
  gf_key *k = NULL;

  CHECK_EQ (gf_key_from_blob (&k, b, n), GF_OK);
  free (b);
  return k;
}

static gf_krl *
load_hex (const char *hex, gf_krl *into)
{
  size_t n;
  uint8_t *b = unhex (hex, &n);
  gf_krl *k = into;

  if (k == NULL)
    CHECK_EQ (gf_krl_new (&k), GF_OK);
  CHECK_EQ (gf_krl_load (k, b, n), GF_OK);
  free (b);
  return k;
}

/* Every key and certificate ssh-keygen -Q was asked about.  */
static void
test_against_openssh (void)
{
  gf_krl *main_ = load_hex (vec_krl_main, NULL), *wild = load_hex (vec_krl_wild, NULL);
  gf_krl *both = load_hex (vec_krl_main, NULL);
  size_t i, revoked = 0;

  load_hex (vec_krl_wild, both);
  for (i = 0; i < sizeof vec_krl_queries / sizeof vec_krl_queries[0]; i++)
    {
      const struct vec_krl_query *q = &vec_krl_queries[i];
      gf_key *k = key_of (q->blob);
      int m = gf_krl_check (main_, k), w = gf_krl_check (wild, k),
        b = gf_krl_check (both, k);

      if (m != q->main || w != q->wild || b != (q->main || q->wild))
        {
          fprintf (stderr, "%s: main %d (ssh-keygen %d), wild %d (%d), both %d\n",
                   q->name, m, q->main, w, q->wild, b);
          CHECK (0);
        }
      revoked += (size_t) m;
      gf_key_free (k);
    }
  CHECK (revoked > 20);
  CHECK (gf_krl_count (main_) > 10);
  gf_krl_free (main_);
  gf_krl_free (wild);
  gf_krl_free (both);
}

static void
test_info (void)
{
  gf_krl *k;
  gf_krl_info info;

  CHECK_EQ (gf_krl_new (&k), GF_OK);
  gf_krl_get_info (k, &info);
  CHECK_EQ (info.version, 0);
  CHECK_EQ (info.comment.len, 0);
  load_hex (vec_krl_wild, k);
  gf_krl_get_info (k, &info);
  CHECK_EQ (info.version, 3);
  CHECK_EQ (info.generated, 1700000000);
  CHECK (gf_slice_equals (info.comment, "any ca"));
  /* The description is the one of the highest version, whichever came
     last: the main list is 7 and has no comment.  */
  load_hex (vec_krl_main, k);
  gf_krl_get_info (k, &info);
  CHECK_EQ (info.version, 7);
  CHECK_EQ (info.comment.len, 0);
  load_hex (vec_krl_wild, k);
  gf_krl_get_info (k, &info);
  CHECK_EQ (info.version, 7);
  CHECK_EQ (info.comment.len, 0);
  gf_krl_free (k);
  gf_krl_get_info (NULL, &info);
  CHECK_EQ (info.version, 0);
  gf_krl_get_info (NULL, NULL);
}

/* Builders for lists that ssh-keygen would not write.  */
static uint8_t buf[1 << 16];

static gf_writer
header (uint64_t version)
{
  gf_writer w;

  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_bytes (&w, "SSHKRL\n", 8);
  gf_wr_u32 (&w, 1);
  gf_wr_u64 (&w, version);
  gf_wr_u64 (&w, 1700000000);
  gf_wr_u64 (&w, 0);
  gf_wr_string (&w, "", 0);
  gf_wr_string (&w, "", 0);
  return w;
}

/* A certificates section for any CA with one subsection.  */
static void
cert_section (gf_writer *w, uint8_t type, const uint8_t *data, size_t n)
{
  size_t i;
  uint8_t sub[1 << 12];
  size_t sn = 0;

  sub[sn++] = 0;
  sub[sn++] = 0;
  sub[sn++] = 0;
  sub[sn++] = 0;		/* The CA: empty.  */
  sub[sn++] = 0;
  sub[sn++] = 0;
  sub[sn++] = 0;
  sub[sn++] = 0;		/* Reserved: empty.  */
  sub[sn++] = type;
  sub[sn++] = (uint8_t) (n >> 24);
  sub[sn++] = (uint8_t) (n >> 16);
  sub[sn++] = (uint8_t) (n >> 8);
  sub[sn++] = (uint8_t) n;
  for (i = 0; i < n; i++)
    sub[sn++] = data[i];
  gf_wr_u8 (w, 1);
  gf_wr_string (w, sub, sn);
}

static uint8_t *
u64s (uint8_t *p, uint64_t a)
{
  int i;

  for (i = 0; i < 8; i++)
    *p++ = (uint8_t) (a >> (56 - 8 * i));
  return p;
}

static int
load_buf (gf_krl *k, gf_writer *w)
{
  CHECK_EQ (gf_wr_status (w), GF_OK);
  return gf_krl_load (k, buf, w->len);
}

static void
test_refused (void)
{
  gf_krl *k;
  gf_writer w;
  uint8_t d[64], *p;
  size_t before;

  CHECK_EQ (gf_krl_new (&k), GF_OK);
  load_hex (vec_krl_main, k);
  before = gf_krl_count (k);

  /* A list with nothing in it is fine.  */
  w = header (1);
  CHECK_EQ (load_buf (k, &w), GF_OK);
  CHECK_EQ (gf_krl_count (k), before);

  /* Magic and version.  */
  w = header (1);
  buf[0] = 'X';
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  buf[11] = 2;
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  CHECK_EQ (gf_krl_load (k, buf, 0), GF_ERR_ENCODING);
  CHECK_EQ (gf_krl_load (k, buf, 7), GF_ERR_ENCODING);
  CHECK_EQ (gf_krl_load (NULL, buf, 7), GF_ERR_INVAL);
  CHECK_EQ (gf_krl_load (k, NULL, 7), GF_ERR_INVAL);

  /* A serial of 0 anywhere, a range that runs backwards, or from 0.  */
  w = header (1);
  u64s (d, 0);
  cert_section (&w, 0x20, d, 8);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  p = u64s (d, 5);
  u64s (p, 0);
  cert_section (&w, 0x20, d, 16);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  p = u64s (d, 0);
  u64s (p, 5);
  cert_section (&w, 0x21, d, 16);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  p = u64s (d, 9);
  u64s (p, 8);
  cert_section (&w, 0x21, d, 16);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  /* ... but 1 to the end is a range.  */
  w = header (1);
  p = u64s (d, 1);
  u64s (p, UINT64_MAX);
  cert_section (&w, 0x21, d, 16);
  CHECK_EQ (load_buf (k, &w), GF_OK);
  /* Trailing bytes in a range, a half serial.  */
  w = header (1);
  p = u64s (d, 5);
  u64s (p, 6);
  d[16] = 0;
  cert_section (&w, 0x21, d, 17);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  u64s (d, 5);
  cert_section (&w, 0x20, d, 7);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);

  /* Bitmaps: a bit for serial 0, one that runs past 2^64, a negative or
     over-long mpint.  */
  w = header (1);
  p = u64s (d, 0);
  p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 1; p[4] = 1;	/* mpint 1: bit 0. */
  cert_section (&w, 0x22, d, 13);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  p = u64s (d, UINT64_MAX - 1);
  p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 1; p[4] = 4;	/* Bit 2: wraps. */
  cert_section (&w, 0x22, d, 13);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  p = u64s (d, UINT64_MAX);
  p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 1; p[4] = 2;	/* Bit 1: serial 1. */
  cert_section (&w, 0x22, d, 13);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  p = u64s (d, UINT64_MAX - 1);
  p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 1; p[4] = 2;	/* Bit 1: the last. */
  cert_section (&w, 0x22, d, 13);
  CHECK_EQ (load_buf (k, &w), GF_OK);
  w = header (1);
  p = u64s (d, 5);
  p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 1; p[4] = 0x80;	/* Negative. */
  cert_section (&w, 0x22, d, 13);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  p = u64s (d, 5);
  p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 2; p[4] = 0; p[5] = 1;	/* Padded. */
  cert_section (&w, 0x22, d, 14);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);

  /* Unknown sections and subsections, and the signature section.  */
  w = header (1);
  gf_wr_u8 (&w, 9);
  gf_wr_string (&w, "", 0);
  CHECK_EQ (load_buf (k, &w), GF_ERR_UNSUPPORTED);
  w = header (1);
  cert_section (&w, 0x30, d, 0);
  CHECK_EQ (load_buf (k, &w), GF_ERR_UNSUPPORTED);
  w = header (1);
  gf_wr_u8 (&w, 4);
  gf_wr_string (&w, "ssh-ed25519", 11);
  gf_wr_string (&w, "sig", 3);
  CHECK_EQ (load_buf (k, &w), GF_ERR_UNSUPPORTED);
  /* Even with a good list before it.  */
  w = header (1);
  p = u64s (d, 5);
  cert_section (&w, 0x20, d, 8);
  gf_wr_u8 (&w, 4);
  gf_wr_string (&w, "x", 1);
  gf_wr_string (&w, "y", 1);
  CHECK_EQ (load_buf (k, &w), GF_ERR_UNSUPPORTED);

  /* Extensions: critical ones fail the list, others are ignored.  */
  {
    uint8_t e[64];
    gf_writer ew;

    gf_writer_init (&ew, e, sizeof e);
    gf_wr_cstring (&ew, "a@b");
    gf_wr_u8 (&ew, 0);
    gf_wr_string (&ew, "z", 1);
    w = header (1);
    gf_wr_u8 (&w, 255);
    gf_wr_string (&w, e, ew.len);
    CHECK_EQ (load_buf (k, &w), GF_OK);
    gf_writer_init (&ew, e, sizeof e);
    gf_wr_cstring (&ew, "a@b");
    gf_wr_u8 (&ew, 1);
    gf_wr_string (&ew, "z", 1);
    w = header (1);
    gf_wr_u8 (&w, 255);
    gf_wr_string (&w, e, ew.len);
    CHECK_EQ (load_buf (k, &w), GF_ERR_UNSUPPORTED);
    /* A certificate extension, the same.  */
    gf_writer_init (&ew, e, sizeof e);
    gf_wr_cstring (&ew, "a@b");
    gf_wr_u8 (&ew, 0);
    gf_wr_string (&ew, "z", 1);
    w = header (1);
    cert_section (&w, 0x39, e, ew.len);
    CHECK_EQ (load_buf (k, &w), GF_OK);
    gf_writer_init (&ew, e, sizeof e);
    gf_wr_cstring (&ew, "a@b");
    gf_wr_u8 (&ew, 1);
    gf_wr_string (&ew, "z", 1);
    w = header (1);
    cert_section (&w, 0x39, e, ew.len);
    CHECK_EQ (load_buf (k, &w), GF_ERR_UNSUPPORTED);
  }

  /* Hashes of the wrong length; an empty hash section is fine.  */
  w = header (1);
  gf_wr_u8 (&w, 3);
  {
    size_t m = gf_wr_string_begin (&w);

    gf_wr_string (&w, d, 19);
    gf_wr_string_end (&w, m);
  }
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  gf_wr_u8 (&w, 5);
  {
    size_t m = gf_wr_string_begin (&w);

    gf_wr_string (&w, d, 20);
    gf_wr_string_end (&w, m);
  }
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);
  w = header (1);
  gf_wr_u8 (&w, 5);
  gf_wr_string (&w, "", 0);
  CHECK_EQ (load_buf (k, &w), GF_OK);
  /* A string that runs past its section.  */
  w = header (1);
  gf_wr_u8 (&w, 2);
  gf_wr_string (&w, "\0\0\0\x09" "abc", 7);
  CHECK_EQ (load_buf (k, &w), GF_ERR_ENCODING);

  /* The two good ones above added their entries, and no refused list added
     any: the count is before, a range, and a bit.  */
  CHECK_EQ (gf_krl_count (k), before + 2);
  gf_krl_free (k);
}

/* A list that fails halfway adds nothing, and a prefix of a good list never
   crashes.  */
static void
test_atomic_and_prefixes (void)
{
  size_t n, i, ok = 0;
  uint8_t *b = unhex (vec_krl_main, &n);
  gf_krl *k, *base;
  gf_key *revoked = key_of (vec_krl_queries[1].blob);	/* plain-key. */

  CHECK_EQ (gf_krl_new (&base), GF_OK);
  CHECK_EQ (gf_krl_check (base, revoked), 0);
  for (i = 0; i <= n; i++)
    {
      int rc;
      size_t c;

      CHECK_EQ (gf_krl_new (&k), GF_OK);
      rc = gf_krl_load (k, b, i);
      c = gf_krl_count (k);
      if (rc == GF_OK)
        ok++;
      else
        {
          CHECK_EQ (c, 0);
          CHECK_EQ (gf_krl_check (k, revoked), 0);
        }
      gf_krl_free (k);
    }
  CHECK (ok >= 2);		/* The header alone, and the whole.  */
  CHECK (ok < n);
  /* Flipping any one byte of a good list is read or refused, never worse.  */
  for (i = 0; i < n; i++)
    {
      uint8_t save = b[i];

      b[i] ^= 0xff;
      CHECK_EQ (gf_krl_new (&k), GF_OK);
      (void) gf_krl_load (k, b, n);
      (void) gf_krl_check (k, revoked);
      gf_krl_free (k);
      b[i] = save;
    }
  free (b);
  gf_key_free (revoked);
  gf_krl_free (base);
}

/* More entries than the limit are refused rather than allocated.  */
static void
test_limits (void)
{
  gf_krl *k;
  size_t n = (size_t) GF_KRL_MAX_ENTRIES + 1, i;
  gf_writer w;
  uint8_t *big = malloc (n * 8 + 64), *p;

  CHECK (big != NULL);
  CHECK_EQ (gf_krl_new (&k), GF_OK);
  w = header (1);
  /* A list of serials: the section by hand.  */
  p = big;
  *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
  *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
  *p++ = 0x20;
  {
    uint32_t len = (uint32_t) (n * 8);

    *p++ = (uint8_t) (len >> 24);
    *p++ = (uint8_t) (len >> 16);
    *p++ = (uint8_t) (len >> 8);
    *p++ = (uint8_t) len;
  }
  for (i = 0; i < n; i++)
    p = u64s (p, 2 * i + 1);	/* Not adjacent: one range each.  */
  {
    uint8_t *file;
    size_t sect = (size_t) (p - big), hl = w.len;

    file = malloc (hl + 1 + 4 + sect);
    CHECK (file != NULL);
    memcpy (file, buf, hl);
    file[hl] = 1;
    file[hl + 1] = (uint8_t) (sect >> 24);
    file[hl + 2] = (uint8_t) (sect >> 16);
    file[hl + 3] = (uint8_t) (sect >> 8);
    file[hl + 4] = (uint8_t) sect;
    memcpy (file + hl + 5, big, sect);
    CHECK_EQ (gf_krl_load (k, file, hl + 5 + sect), GF_ERR_RANGE);
    CHECK_EQ (gf_krl_count (k), 0);
    free (file);
    file = calloc ((size_t) GF_KRL_MAX_SIZE + 1, 1);
    CHECK (file != NULL);
    CHECK_EQ (gf_krl_load (k, file, GF_KRL_MAX_SIZE), GF_ERR_ENCODING);
    CHECK_EQ (gf_krl_load (k, file, (size_t) GF_KRL_MAX_SIZE + 1), GF_ERR_RANGE);
    free (file);
  }
  free (big);
  gf_krl_free (k);
}

static void
test_arguments (void)
{
  gf_krl *k;
  gf_key *key = key_of (vec_krl_queries[0].blob);

  CHECK_EQ (gf_krl_new (NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_krl_new (&k), GF_OK);
  CHECK_EQ (gf_krl_check (k, key), 0);
  CHECK_EQ (gf_krl_check (NULL, key), GF_ERR_INVAL);
  CHECK_EQ (gf_krl_check (k, NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_krl_count (NULL), 0);
  gf_krl_free (NULL);
  gf_krl_free (k);
  gf_key_free (key);
}

int
main (void)
{
  CHECK_EQ (gf_crypto_init (), GF_OK);
  test_against_openssh ();
  test_info ();
  test_refused ();
  test_atomic_and_prefixes ();
  test_limits ();
  test_arguments ();
  TST_DONE ();
}
