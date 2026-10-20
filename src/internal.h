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

/* Declarations shared between the library's source files.  Nothing here is
   exported: the library exports only gf_ symbols, and these are gfi_.  */

#ifndef GF_INTERNAL_H
#define GF_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/* 1 if Q (QLEN bytes) is an uncompressed point 0x04 x y on the NIST curve
   CURVE (a libgcrypt curve name such as "NIST P-256") with both
   coordinates reduced, else 0.  libgcrypt's ECDH does not check this
   itself, and an unchecked peer value is an invalid-curve attack.  */
int gfi_ec_point_ok (const char *curve, const uint8_t *q, size_t qlen);

/* Match S (SN bytes) against the pattern PAT (PN bytes), in which '*' stands
   for any run of characters and '?' for any one.  Case sensitive.  */
int gfi_wildmatch (const char *pat, size_t pn, const char *s, size_t sn);

/* Base64 (RFC 4648).  Encode IN (N bytes) into OUT, which must hold 4*ceil(N/3)
   characters; PAD nonzero for '=' padding.  No terminating NUL.  Returns the
   length written.  */
size_t gfi_b64_encode (const uint8_t *in, size_t n, char *out, int pad);

/* Decode N characters into OUT (CAP bytes).  Returns the number of bytes, or
   -1 for text that is not base64 or does not fit.  Not STRICT: white space is
   ignored and the padding is not checked, as in PEM bodies.  STRICT: only the
   alphabet, padded to a whole quad, nothing after the padding, and zero
   bits after the data, so that each byte string has exactly one text.  */
long gfi_b64_decode (const char *in, size_t n, uint8_t *out, size_t cap,
                     int strict);

#endif /* GF_INTERNAL_H */
