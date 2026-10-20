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

#include <foxtrot/status.h>
#include <foxtrot/wire.h>

/* ------------------------------------------------------------------ */
/* Reading                                                            */
/* ------------------------------------------------------------------ */

void
gf_reader_init (gf_reader *r, const void *data, size_t len)
{
  r->p = data;
  r->len = len;
}

size_t
gf_rd_remaining (const gf_reader *r)
{
  return r->len;
}

int
gf_rd_finish (const gf_reader *r)
{
  return r->len == 0 ? GF_OK : GF_ERR_ENCODING;
}

int
gf_rd_u8 (gf_reader *r, uint8_t *v)
{
  if (r->len < 1)
    return GF_ERR_ENCODING;
  *v = r->p[0];
  r->p++;
  r->len--;
  return GF_OK;
}

int
gf_rd_u32 (gf_reader *r, uint32_t *v)
{
  if (r->len < 4)
    return GF_ERR_ENCODING;
  *v = (uint32_t) r->p[0] << 24 | (uint32_t) r->p[1] << 16
    | (uint32_t) r->p[2] << 8 | r->p[3];
  r->p += 4;
  r->len -= 4;
  return GF_OK;
}

int
gf_rd_u64 (gf_reader *r, uint64_t *v)
{
  uint32_t hi, lo;
  gf_reader save = *r;

  if (gf_rd_u32 (r, &hi) != GF_OK || gf_rd_u32 (r, &lo) != GF_OK)
    {
      *r = save;
      return GF_ERR_ENCODING;
    }
  *v = (uint64_t) hi << 32 | lo;
  return GF_OK;
}

int
gf_rd_bool (gf_reader *r, int *v)
{
  uint8_t b;

  if (gf_rd_u8 (r, &b) != GF_OK)
    return GF_ERR_ENCODING;
  *v = b != 0;
  return GF_OK;
}

int
gf_rd_bytes (gf_reader *r, size_t n, gf_slice *s)
{
  if (r->len < n)
    return GF_ERR_ENCODING;
  s->data = r->p;
  s->len = n;
  r->p += n;
  r->len -= n;
  return GF_OK;
}

int
gf_rd_string (gf_reader *r, gf_slice *s)
{
  gf_reader save = *r;
  uint32_t n;

  if (gf_rd_u32 (r, &n) != GF_OK || gf_rd_bytes (r, n, s) != GF_OK)
    {
      *r = save;
      return GF_ERR_ENCODING;
    }
  return GF_OK;
}

int
gf_rd_text (gf_reader *r, gf_slice *s)
{
  gf_reader save = *r;

  if (gf_rd_string (r, s) != GF_OK)
    return GF_ERR_ENCODING;
  if (s->len > 0 && memchr (s->data, 0, s->len) != NULL)
    {
      *r = save;
      return GF_ERR_ENCODING;
    }
  return GF_OK;
}

int
gf_utf8_valid (const uint8_t *p, size_t n)
{
  size_t i = 0;

  while (i < n)
    {
      uint8_t c = p[i];
      size_t extra;
      uint32_t cp;

      if (c < 0x80)
        {
          i++;
          continue;
        }
      if (c >= 0xc2 && c <= 0xdf)
        {
          extra = 1;
          cp = c & 0x1f;
        }
      else if (c >= 0xe0 && c <= 0xef)
        {
          extra = 2;
          cp = c & 0x0f;
        }
      else if (c >= 0xf0 && c <= 0xf4)
        {
          extra = 3;
          cp = c & 0x07;
        }
      else
        return 0;
      if (i + extra >= n)
        return 0;
      {
        size_t k;

        for (k = 1; k <= extra; k++)
          {
            if ((p[i + k] & 0xc0) != 0x80)
              return 0;
            cp = cp << 6 | (p[i + k] & 0x3f);
          }
      }
      if ((extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000)
          || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
        return 0;
      i += extra + 1;
    }
  return 1;
}

int
gf_rd_utf8 (gf_reader *r, gf_slice *s)
{
  gf_reader save = *r;

  if (gf_rd_text (r, s) != GF_OK)
    return GF_ERR_ENCODING;
  if (!gf_utf8_valid (s->data, s->len))
    {
      *r = save;
      return GF_ERR_ENCODING;
    }
  return GF_OK;
}

int
gf_rd_mpint (gf_reader *r, gf_slice *mag)
{
  gf_reader save = *r;
  gf_slice s;

  if (gf_rd_string (r, &s) != GF_OK)
    return GF_ERR_ENCODING;
  if (s.len > 0)
    {
      /* Negative, or a redundant leading zero (RFC 4251 section 5: the
         encoding has no unnecessary leading bytes).  */
      if ((s.data[0] & 0x80)
          || (s.data[0] == 0 && (s.len == 1 || !(s.data[1] & 0x80))))
        {
          *r = save;
          return GF_ERR_ENCODING;
        }
      if (s.data[0] == 0)
        {
          s.data++;
          s.len--;
        }
    }
  *mag = s;
  return GF_OK;
}

int
gf_namelist_valid (gf_slice list)
{
  size_t i, run = 0;

  for (i = 0; i < list.len; i++)
    {
      uint8_t c = list.data[i];

      if (c == ',')
        {
          if (run == 0)
            return 0;
          run = 0;
        }
      else if (c <= 0x20 || c >= 0x7f || ++run > 64)
        return 0;
    }
  return list.len == 0 || run > 0;
}

int
gf_rd_namelist (gf_reader *r, gf_slice *list)
{
  gf_reader save = *r;

  if (gf_rd_string (r, list) != GF_OK)
    return GF_ERR_ENCODING;
  if (!gf_namelist_valid (*list))
    {
      *r = save;
      return GF_ERR_ENCODING;
    }
  return GF_OK;
}

int
gf_namelist_next (gf_slice *list, gf_slice *name)
{
  const uint8_t *comma;

  if (list->len == 0)
    return 0;
  comma = memchr (list->data, ',', list->len);
  name->data = list->data;
  if (comma == NULL)
    {
      name->len = list->len;
      list->data += list->len;
      list->len = 0;
    }
  else
    {
      name->len = (size_t) (comma - list->data);
      list->len -= name->len + 1;
      list->data = comma + 1;
    }
  return 1;
}

int
gf_slice_equals (gf_slice s, const char *str)
{
  size_t n = strlen (str);

  return s.len == n && (n == 0 || memcmp (s.data, str, n) == 0);
}

int
gf_namelist_has (gf_slice list, gf_slice name)
{
  gf_slice n;

  while (gf_namelist_next (&list, &n))
    if (n.len == name.len && memcmp (n.data, name.data, n.len) == 0)
      return 1;
  return 0;
}

int
gf_namelist_contains (gf_slice list, const char *name)
{
  gf_slice n;

  while (gf_namelist_next (&list, &n))
    if (gf_slice_equals (n, name))
      return 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Writing                                                            */
/* ------------------------------------------------------------------ */

void
gf_writer_init (gf_writer *w, uint8_t *buf, size_t cap)
{
  w->buf = buf;
  w->cap = cap;
  w->len = 0;
  w->err = 0;
}

int
gf_wr_status (const gf_writer *w)
{
  return w->err ? GF_ERR_BUFSIZE : GF_OK;
}

void
gf_wr_bytes (gf_writer *w, const void *data, size_t len)
{
  if (w->err)
    return;
  if (len > w->cap - w->len)
    {
      w->err = 1;
      return;
    }
  if (len > 0)
    memcpy (w->buf + w->len, data, len);
  w->len += len;
}

void
gf_wr_u8 (gf_writer *w, uint8_t v)
{
  gf_wr_bytes (w, &v, 1);
}

void
gf_wr_u32 (gf_writer *w, uint32_t v)
{
  uint8_t b[4];

  b[0] = (uint8_t) (v >> 24);
  b[1] = (uint8_t) (v >> 16);
  b[2] = (uint8_t) (v >> 8);
  b[3] = (uint8_t) v;
  gf_wr_bytes (w, b, 4);
}

void
gf_wr_u64 (gf_writer *w, uint64_t v)
{
  gf_wr_u32 (w, (uint32_t) (v >> 32));
  gf_wr_u32 (w, (uint32_t) v);
}

void
gf_wr_bool (gf_writer *w, int v)
{
  gf_wr_u8 (w, v ? 1 : 0);
}

void
gf_wr_string (gf_writer *w, const void *data, size_t len)
{
  if (len > UINT32_MAX)
    {
      w->err = 1;
      return;
    }
  gf_wr_u32 (w, (uint32_t) len);
  gf_wr_bytes (w, data, len);
}

void
gf_wr_cstring (gf_writer *w, const char *s)
{
  gf_wr_string (w, s, strlen (s));
}

void
gf_wr_namelist (gf_writer *w, const char *names)
{
  gf_wr_cstring (w, names);
}

void
gf_wr_mpint (gf_writer *w, const void *mag, size_t len)
{
  const uint8_t *p = mag;

  while (len > 0 && *p == 0)
    p++, len--;
  if (len > 0 && (p[0] & 0x80))
    {
      if (len + 1 > UINT32_MAX)
        {
          w->err = 1;
          return;
        }
      gf_wr_u32 (w, (uint32_t) (len + 1));
      gf_wr_u8 (w, 0);
    }
  else
    gf_wr_u32 (w, (uint32_t) len);
  gf_wr_bytes (w, p, len);
}

size_t
gf_wr_string_begin (gf_writer *w)
{
  size_t mark = w->len;

  gf_wr_u32 (w, 0);
  return mark;
}

void
gf_wr_string_end (gf_writer *w, size_t mark)
{
  size_t n;

  if (w->err)
    return;
  n = w->len - mark - 4;
  w->buf[mark] = (uint8_t) (n >> 24);
  w->buf[mark + 1] = (uint8_t) (n >> 16);
  w->buf[mark + 2] = (uint8_t) (n >> 8);
  w->buf[mark + 3] = (uint8_t) n;
}
