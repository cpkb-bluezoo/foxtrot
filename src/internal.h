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

#endif /* GF_INTERNAL_H */
