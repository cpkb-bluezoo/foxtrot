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

/* SSH data types (RFC 4251 section 5): byte, boolean, uint32, uint64,
   string, mpint and name-list.

   A gf_reader walks a buffer that is already complete.  That is the right
   shape for SSH: the binary packet layer (packet.h) delivers whole
   authenticated payloads, so a message is never parsed from a partial
   buffer.  Reads are all-or-nothing: a read that fails leaves the reader
   where it was and returns GF_ERR_ENCODING.  Variable-length values are
   slices into the caller's buffer; nothing is copied or allocated.

   A gf_writer fills a caller-supplied buffer.  It records the first
   overflow and ignores every write after it, so a message can be built
   with no check after each field and one at the end (gf_wr_status).  */

#ifndef FOXTROT_WIRE_H
#define FOXTROT_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gf_slice
{
  const uint8_t *data;
  size_t len;
} gf_slice;

/* ---- Reading ---- */

typedef struct gf_reader
{
  const uint8_t *p;
  size_t len;			/* Bytes left.  */
} gf_reader;

void gf_reader_init (gf_reader *r, const void *data, size_t len);
size_t gf_rd_remaining (const gf_reader *r);

/* Succeeds only if every byte has been consumed.  A message with
   trailing bytes after its last field is malformed here.  */
int gf_rd_finish (const gf_reader *r);

int gf_rd_u8 (gf_reader *r, uint8_t *v);
int gf_rd_u32 (gf_reader *r, uint32_t *v);
int gf_rd_u64 (gf_reader *r, uint64_t *v);
/* Any nonzero byte is true (RFC 4251 section 5).  */
int gf_rd_bool (gf_reader *r, int *v);
/* N raw bytes.  */
int gf_rd_bytes (gf_reader *r, size_t n, gf_slice *s);
/* uint32 length, then that many bytes.  */
int gf_rd_string (gf_reader *r, gf_slice *s);
/* A string that must not contain NUL, for text fields.  */
int gf_rd_text (gf_reader *r, gf_slice *s);
/* A text field that must also be valid UTF-8 (RFC 3629): no overlong
   forms, surrogates or code points above U+10FFFF.  */
int gf_rd_utf8 (gf_reader *r, gf_slice *s);
/* 1 if the LEN bytes at DATA are valid UTF-8.  */
int gf_utf8_valid (const uint8_t *data, size_t len);
/* A non-negative mpint in its only valid encoding: no redundant leading
   zero bytes.  *MAG is the magnitude without the sign byte, empty for
   zero.  A negative number is rejected, as nothing in SSH sends one.  */
int gf_rd_mpint (gf_reader *r, gf_slice *mag);
/* A name-list: a string whose names are 1 to 64 printable US-ASCII
   characters without a comma or space, separated by single commas, with
   no empty name.  An empty list is valid.  */
int gf_rd_namelist (gf_reader *r, gf_slice *list);

/* Name-list iteration.  gf_namelist_next sets *NAME to the first name of
   *LIST and advances *LIST past it and its comma; returns 1, or 0 at
   the end.  */
int gf_namelist_next (gf_slice *list, gf_slice *name);
int gf_namelist_valid (gf_slice list);
/* 1 if LIST has the name NAME (a C string, or a slice).  */
int gf_namelist_contains (gf_slice list, const char *name);
int gf_namelist_has (gf_slice list, gf_slice name);
/* Compare a slice with a C string.  */
int gf_slice_equals (gf_slice s, const char *str);

/* ---- Writing ---- */

typedef struct gf_writer
{
  uint8_t *buf;
  size_t cap;
  size_t len;
  int err;
} gf_writer;

void gf_writer_init (gf_writer *w, uint8_t *buf, size_t cap);
/* GF_OK, or GF_ERR_BUFSIZE if anything did not fit.  */
int gf_wr_status (const gf_writer *w);

void gf_wr_u8 (gf_writer *w, uint8_t v);
void gf_wr_u32 (gf_writer *w, uint32_t v);
void gf_wr_u64 (gf_writer *w, uint64_t v);
void gf_wr_bool (gf_writer *w, int v);
void gf_wr_bytes (gf_writer *w, const void *data, size_t len);
void gf_wr_string (gf_writer *w, const void *data, size_t len);
void gf_wr_cstring (gf_writer *w, const char *s);
/* An unsigned big-endian magnitude, which need not be minimal.  */
void gf_wr_mpint (gf_writer *w, const void *mag, size_t len);
/* A name-list from a C string that already holds the comma-separated
   names.  */
void gf_wr_namelist (gf_writer *w, const char *names);

/* A string whose content is built in place: gf_wr_string_begin returns a
   mark, the caller writes the content, and gf_wr_string_end fills in
   the length.  */
size_t gf_wr_string_begin (gf_writer *w);
void gf_wr_string_end (gf_writer *w, size_t mark);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_WIRE_H */
