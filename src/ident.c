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
#include <foxtrot/policy.h>
#include <foxtrot/ident.h>

#define PREFIX "SSH-"

enum
{
  ST_START,			/* At the start of a line.  */
  ST_IDENT,			/* In a line that began with "SSH-".  */
  ST_SKIP,			/* In some other line.  */
  ST_DONE,
  ST_FAILED
};

void
gf_ident_init (gf_ident *id, int allow_prefix)
{
  memset (id, 0, sizeof *id);
  id->allow_prefix = allow_prefix;
  id->state = ST_START;
}

/* LINE holds the identification line without CR LF.  Check the grammar
   and the version.  */
static int
validate (gf_ident *id)
{
  const uint8_t *l = id->line;
  size_t n = id->end, i;
  const char *ver = GF_PROTOCOL_VERSION;
  size_t vl = strlen (ver);

  for (i = 0; i < n; i++)
    if (l[i] < 0x20 || l[i] > 0x7e)
      return GF_ERR_ENCODING;
  /* "SSH-" protoversion "-" softwareversion.  */
  if (n < 4 + 1 + 1 + 1 || memcmp (l, PREFIX, 4) != 0)
    return GF_ERR_ENCODING;
  for (i = 4; i < n && l[i] != '-'; i++)
    continue;
  if (i == n || i == 4)
    return GF_ERR_ENCODING;
  if (i - 4 != vl || memcmp (l + 4, ver, vl) != 0)
    return GF_ERR_UNSUPPORTED;
  id->software = i + 1;
  if (id->software >= n || l[id->software] == ' ')
    return GF_ERR_ENCODING;
  return GF_OK;
}

int
gf_ident_parse (gf_ident *id, const uint8_t **buf, size_t *len)
{
  if (id->state == ST_DONE)
    return GF_OK;
  if (id->state == ST_FAILED)
    return GF_ERR_ENCODING;

  while (*len > 0)
    {
      uint8_t c = **buf;

      (*buf)++;
      (*len)--;

      if (id->state == ST_SKIP)
        {
          if (++id->skipped > GF_IDENT_MAX_PREFIX)
            goto fail;
          if (c == '\n')
            {
              id->state = ST_START;
              id->len = 0;
            }
          continue;
        }

      /* ST_START or ST_IDENT: collect the line.  */
      if (id->len >= GF_IDENT_MAX)
        goto fail;
      id->line[id->len++] = c;

      if (id->state == ST_START && id->len == sizeof PREFIX - 1)
        {
          if (memcmp (id->line, PREFIX, id->len) == 0)
            id->state = ST_IDENT;
          else if (id->allow_prefix)
            {
              id->skipped += id->len;
              id->state = ST_SKIP;
              if (id->skipped > GF_IDENT_MAX_PREFIX)
                goto fail;
              if (c == '\n')
                {
                  id->state = ST_START;
                  id->len = 0;
                }
              continue;
            }
          else
            goto fail;
        }
      if (c == '\n')
        {
          int r;

          if (id->state == ST_START)
            {
              /* A line shorter than "SSH-": text before the
                 identification, or an error from a client.  */
              if (!id->allow_prefix)
                goto fail;
              id->skipped += id->len;
              id->len = 0;
              if (id->skipped > GF_IDENT_MAX_PREFIX)
                goto fail;
              continue;
            }
          if (id->len < 2 || id->line[id->len - 2] != '\r')
            goto fail;
          id->end = id->len - 2;
          r = validate (id);
          if (r != GF_OK)
            {
              id->state = ST_FAILED;
              return r;
            }
          id->state = ST_DONE;
          return GF_OK;
        }
    }
  return GF_NEED_MORE;

fail:
  id->state = ST_FAILED;
  return GF_ERR_ENCODING;
}

gf_slice
gf_ident_string (const gf_ident *id)
{
  gf_slice s;

  s.data = id->line;
  s.len = id->end;
  return s;
}

gf_slice
gf_ident_software (const gf_ident *id)
{
  gf_slice s;

  s.data = id->line + id->software;
  s.len = id->end - id->software;
  return s;
}

int
gf_ident_format (const char *software, const char *comments, uint8_t *out,
                 size_t cap, size_t *outlen)
{
  size_t i, n, sl, cl = 0;

  if (software == NULL || out == NULL || outlen == NULL)
    return GF_ERR_INVAL;
  sl = strlen (software);
  if (sl == 0)
    return GF_ERR_INVAL;
  for (i = 0; i < sl; i++)
    if (software[i] < 0x21 || software[i] > 0x7e || software[i] == '-')
      return GF_ERR_INVAL;
  if (comments != NULL)
    {
      cl = strlen (comments);
      for (i = 0; i < cl; i++)
        if (comments[i] < 0x20 || comments[i] > 0x7e)
          return GF_ERR_INVAL;
    }
  n = sizeof PREFIX - 1 + strlen (GF_PROTOCOL_VERSION) + 1 + sl
    + (cl ? 1 + cl : 0);
  if (n + 2 > GF_IDENT_MAX)
    return GF_ERR_RANGE;
  if (cap < n + 2)
    return GF_ERR_BUFSIZE;
  memcpy (out, PREFIX GF_PROTOCOL_VERSION "-", n - sl - (cl ? 1 + cl : 0));
  i = n - sl - (cl ? 1 + cl : 0);
  memcpy (out + i, software, sl);
  i += sl;
  if (cl)
    {
      out[i++] = ' ';
      memcpy (out + i, comments, cl);
      i += cl;
    }
  out[i++] = '\r';
  out[i++] = '\n';
  *outlen = i;
  return GF_OK;
}
