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

#include "internal.h"

static const char b64chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t
gfi_b64_encode (const uint8_t *in, size_t n, char *out, int pad)
{
  size_t i, o = 0;

  for (i = 0; i + 2 < n; i += 3)
    {
      uint32_t v = (uint32_t) in[i] << 16 | in[i + 1] << 8 | in[i + 2];

      out[o++] = b64chars[v >> 18];
      out[o++] = b64chars[(v >> 12) & 63];
      out[o++] = b64chars[(v >> 6) & 63];
      out[o++] = b64chars[v & 63];
    }
  if (i < n)
    {
      uint32_t v = (uint32_t) in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0);

      out[o++] = b64chars[v >> 18];
      out[o++] = b64chars[(v >> 12) & 63];
      if (i + 1 < n)
        out[o++] = b64chars[(v >> 6) & 63];
      if (pad)
        {
          if (i + 1 >= n)
            out[o++] = '=';
          out[o++] = '=';
        }
    }
  return o;
}

long
gfi_b64_decode (const char *in, size_t n, uint8_t *out, size_t cap, int strict)
{
  uint32_t acc = 0;
  int bits = 0;
  size_t o = 0, i, pads = 0, chars = 0;

  for (i = 0; i < n; i++)
    {
      const char *p;
      char c = in[i];

      if (!strict && (c == '\n' || c == '\r' || c == ' ' || c == '\t'))
        continue;
      if (c == '=')
        {
          pads++;
          continue;
        }
      p = c ? strchr (b64chars, c) : NULL;
      if (p == NULL || pads)
        return -1;
      acc = acc << 6 | (uint32_t) (p - b64chars);
      bits += 6;
      chars++;
      if (bits >= 8)
        {
          bits -= 8;
          if (o >= cap)
            return -1;
          out[o++] = (uint8_t) (acc >> bits);
        }
    }
  if (strict)
    {
      /* Whole quads, padded exactly as much as the last one needs, and no
         stray bits after the data: one text for each byte string.  */
      if (chars % 4 == 1 || pads != (4 - chars % 4) % 4
          || (bits > 0 && (acc & ((1u << bits) - 1)) != 0))
        return -1;
    }
  return (long) o;
}
