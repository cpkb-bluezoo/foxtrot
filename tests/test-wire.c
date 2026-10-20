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
#include <foxtrot/wire.h>

#include "tst-util.h"

/* The examples of RFC 4251 section 5.  */
static void
test_mpint (void)
{
  uint8_t buf[64], wire[64];
  gf_reader r;
  gf_slice m;
  gf_writer w;
  size_t n;

  /* 0 */
  n = tst_unhex ("00000000", wire, sizeof wire);
  gf_reader_init (&r, wire, n);
  CHECK_EQ (gf_rd_mpint (&r, &m), GF_OK);
  CHECK_EQ (m.len, 0);
  CHECK_EQ (gf_rd_finish (&r), GF_OK);

  /* 0x9a378f9b2e332a7 */
  n = tst_unhex ("0000000809a378f9b2e332a7", wire, sizeof wire);
  gf_reader_init (&r, wire, n);
  CHECK_EQ (gf_rd_mpint (&r, &m), GF_OK);
  CHECK (tst_eq_hex (m.data, m.len, "09a378f9b2e332a7"));

  /* 0x80 needs a leading zero.  */
  n = tst_unhex ("000000020080", wire, sizeof wire);
  gf_reader_init (&r, wire, n);
  CHECK_EQ (gf_rd_mpint (&r, &m), GF_OK);
  CHECK (tst_eq_hex (m.data, m.len, "80"));

  /* -deadbeef and -1234 (RFC examples) and any other negative number:
     refused.  */
  n = tst_unhex ("00000005ff21524111", wire, sizeof wire);
  gf_reader_init (&r, wire, n);
  CHECK_EQ (gf_rd_mpint (&r, &m), GF_ERR_ENCODING);
  n = tst_unhex ("00000002edcc", wire, sizeof wire);
  gf_reader_init (&r, wire, n);
  CHECK_EQ (gf_rd_mpint (&r, &m), GF_ERR_ENCODING);
  CHECK_EQ (gf_rd_remaining (&r), n);	/* Reader did not move.  */

  /* Redundant leading zero, and a lone zero byte.  */
  n = tst_unhex ("00000002007f", wire, sizeof wire);
  gf_reader_init (&r, wire, n);
  CHECK_EQ (gf_rd_mpint (&r, &m), GF_ERR_ENCODING);
  n = tst_unhex ("0000000100", wire, sizeof wire);
  gf_reader_init (&r, wire, n);
  CHECK_EQ (gf_rd_mpint (&r, &m), GF_ERR_ENCODING);

  /* Writing normalizes: leading zeros dropped, sign byte added.  */
  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_mpint (&w, (const uint8_t[]) { 0, 0, 0x80, 1 }, 4);
  gf_wr_mpint (&w, (const uint8_t[]) { 0, 0 }, 2);
  gf_wr_mpint (&w, (const uint8_t[]) { 0x7f }, 1);
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  CHECK (tst_eq_hex (buf, w.len, "00000003008001" "00000000" "000000017f"));
}

static void
test_scalars (void)
{
  uint8_t buf[64];
  gf_writer w;
  gf_reader r;
  uint8_t b;
  uint32_t u;
  uint64_t q;
  int t;
  gf_slice s;

  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u8 (&w, 0x42);
  gf_wr_u32 (&w, 0xdeadbeef);
  gf_wr_u64 (&w, UINT64_C (0x0123456789abcdef));
  gf_wr_bool (&w, 1);
  gf_wr_bool (&w, 0);
  gf_wr_cstring (&w, "testing");
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  CHECK (tst_eq_hex (buf, w.len, "42" "deadbeef" "0123456789abcdef" "01" "00"
                     "00000007" "74657374696e67"));

  gf_reader_init (&r, buf, w.len);
  CHECK_EQ (gf_rd_u8 (&r, &b), GF_OK);
  CHECK_EQ (b, 0x42);
  CHECK_EQ (gf_rd_u32 (&r, &u), GF_OK);
  CHECK (u == 0xdeadbeef);
  CHECK_EQ (gf_rd_u64 (&r, &q), GF_OK);
  CHECK (q == UINT64_C (0x0123456789abcdef));
  CHECK_EQ (gf_rd_bool (&r, &t), GF_OK);
  CHECK_EQ (t, 1);
  CHECK_EQ (gf_rd_bool (&r, &t), GF_OK);
  CHECK_EQ (t, 0);
  CHECK_EQ (gf_rd_finish (&r), GF_ERR_ENCODING);
  CHECK_EQ (gf_rd_string (&r, &s), GF_OK);
  CHECK (gf_slice_equals (s, "testing"));
  CHECK_EQ (gf_rd_finish (&r), GF_OK);
  CHECK_EQ (gf_rd_u8 (&r, &b), GF_ERR_ENCODING);
}

/* A short read leaves the reader where it was, so a caller can retry.  */
static void
test_short (void)
{
  const uint8_t wire[] = { 0, 0, 0, 5, 'a', 'b', 'c' };
  gf_reader r;
  gf_slice s;
  uint64_t q;

  gf_reader_init (&r, wire, sizeof wire);
  CHECK_EQ (gf_rd_string (&r, &s), GF_ERR_ENCODING);
  CHECK_EQ (gf_rd_remaining (&r), sizeof wire);
  CHECK_EQ (gf_rd_u64 (&r, &q), GF_ERR_ENCODING);

  /* A length that claims more than 2^31 bytes must not overflow.  */
  {
    const uint8_t big[] = { 0xff, 0xff, 0xff, 0xff, 1, 2 };

    gf_reader_init (&r, big, sizeof big);
    CHECK_EQ (gf_rd_string (&r, &s), GF_ERR_ENCODING);
  }
}

static void
test_namelist (void)
{
  gf_slice list, n;
  uint8_t wire[128];
  gf_reader r;
  gf_writer w;

  gf_writer_init (&w, wire, sizeof wire);
  gf_wr_namelist (&w, "zlib,none");
  gf_wr_namelist (&w, "");
  gf_wr_namelist (&w, "a,,b");
  gf_wr_namelist (&w, "a,");
  gf_wr_namelist (&w, ",a");
  gf_wr_namelist (&w, "a b");
  gf_wr_namelist (&w, "caf\xc3\xa9");
  CHECK_EQ (gf_wr_status (&w), GF_OK);

  gf_reader_init (&r, wire, w.len);
  CHECK_EQ (gf_rd_namelist (&r, &list), GF_OK);
  CHECK (gf_namelist_contains (list, "none"));
  CHECK (gf_namelist_contains (list, "zlib"));
  CHECK (!gf_namelist_contains (list, "zli"));
  CHECK (!gf_namelist_contains (list, "nonex"));
  CHECK (gf_namelist_next (&list, &n));
  CHECK (gf_slice_equals (n, "zlib"));
  CHECK (gf_namelist_next (&list, &n));
  CHECK (gf_slice_equals (n, "none"));
  CHECK (!gf_namelist_next (&list, &n));
  CHECK_EQ (gf_rd_namelist (&r, &list), GF_OK);
  CHECK_EQ (list.len, 0);
  CHECK (!gf_namelist_contains (list, "none"));
  /* Each malformed list is refused and does not advance the reader.  */
  while (gf_rd_remaining (&r) > 0)
    {
      size_t before = gf_rd_remaining (&r);

      CHECK_EQ (gf_rd_namelist (&r, &list), GF_ERR_ENCODING);
      CHECK_EQ (gf_rd_remaining (&r), before);
      /* Skip the string to try the next one.  */
      gf_rd_string (&r, &list);
    }

  /* Names longer than 64 characters are refused.  */
  {
    char name[80];
    uint8_t buf[100];

    memset (name, 'x', 64);
    name[64] = 0;
    gf_writer_init (&w, buf, sizeof buf);
    gf_wr_cstring (&w, name);
    gf_reader_init (&r, buf, w.len);
    CHECK_EQ (gf_rd_namelist (&r, &list), GF_OK);
    name[64] = 'x';
    name[65] = 0;
    gf_writer_init (&w, buf, sizeof buf);
    gf_wr_cstring (&w, name);
    gf_reader_init (&r, buf, w.len);
    CHECK_EQ (gf_rd_namelist (&r, &list), GF_ERR_ENCODING);
  }
}

static void
test_text_and_overflow (void)
{
  uint8_t buf[8], wire[] = { 0, 0, 0, 3, 'a', 0, 'b' };
  gf_writer w;
  gf_reader r;
  gf_slice s;
  size_t mark;

  gf_reader_init (&r, wire, sizeof wire);
  CHECK_EQ (gf_rd_text (&r, &s), GF_ERR_ENCODING);
  CHECK_EQ (gf_rd_string (&r, &s), GF_OK);

  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u32 (&w, 1);
  gf_wr_u32 (&w, 2);
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  gf_wr_u8 (&w, 3);			/* Does not fit.  */
  CHECK_EQ (gf_wr_status (&w), GF_ERR_BUFSIZE);
  CHECK_EQ (w.len, 8);			/* Nothing was written.  */

  gf_writer_init (&w, buf, sizeof buf);
  mark = gf_wr_string_begin (&w);
  gf_wr_u8 (&w, 7);
  gf_wr_u8 (&w, 8);
  gf_wr_string_end (&w, mark);
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  CHECK (tst_eq_hex (buf, w.len, "000000020708"));
}

static void
test_utf8 (void)
{
  static const struct
  {
    const char *hex;
    int ok;
  } v[] = {
    { "", 1 }, { "41", 1 }, { "c3a9", 1 }, { "e282ac", 1 }, { "f09f9880", 1 },
    { "f48fbfbf", 1 },			/* U+10FFFF */
    { "80", 0 }, { "c0af", 0 }, { "c1bf", 0 },	/* Continuation, overlong.  */
    { "e08080", 0 }, { "f0808080", 0 },		/* Overlong.  */
    { "eda080", 0 }, { "edbfbf", 0 },		/* Surrogates.  */
    { "f4908080", 0 }, { "f5808080", 0 },	/* Above U+10FFFF.  */
    { "c3", 0 }, { "e282", 0 }, { "f09f98", 0 },	/* Truncated.  */
    { "c328", 0 }, { "ff", 0 }
  };
  size_t i;

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      uint8_t b[16];
      size_t n = tst_unhex (v[i].hex, b, sizeof b);

      CHECK_EQ (gf_utf8_valid (b, n), v[i].ok);
    }
}

int
main (void)
{
  test_utf8 ();
  test_scalars ();
  test_mpint ();
  test_short ();
  test_namelist ();
  test_text_and_overflow ();
  TST_DONE ();
}
