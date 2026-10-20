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

/* Status codes shared by every foxtrot module.

   The library never aborts and never writes to stderr; every failure is
   reported to the caller as a negative gf_status value.  */

#ifndef FOXTROT_STATUS_H
#define FOXTROT_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

enum gf_status
{
  GF_OK = 0,

  /* Push parsers: the input ended in the middle of a syntactic unit.
     The caller must keep the unconsumed tail and present it again,
     followed by more data.  Not a protocol error by itself.  */
  GF_NEED_MORE = 1,

  GF_ERR_INVAL = -1,		/* Bad argument (programmer error).  */
  GF_ERR_NOMEM = -2,		/* Allocation failed.  */
  GF_ERR_ENCODING = -3,		/* Malformed wire data.  */
  GF_ERR_RANGE = -4,		/* Value outside the permitted range.  */
  GF_ERR_BUFSIZE = -5,		/* Output buffer too small.  */
  GF_ERR_CRYPTO = -6,		/* Primitive failed (bad tag, bad key...).  */
  GF_ERR_UNSUPPORTED = -7,	/* Algorithm not permitted by policy.  */
  GF_ERR_HANDLER = -8,		/* A handler callback asked to abort.  */
  GF_ERR_HOSTKEY = -9,		/* Host key rejected or signature invalid.  */
  GF_ERR_UNAVAILABLE = -10,	/* Feature not compiled in.  */
  GF_ERR_PROTOCOL = -11,	/* Well-formed but illegal for this state.  */
  GF_ERR_TIMEOUT = -12,		/* A deadline passed.  */
  GF_ERR_STATE = -13,		/* Call not allowed in the current state.  */
  GF_ERR_CLOSED = -14,		/* The connection is closed.  */
  GF_ERR_AUTH = -15,		/* Authentication failed.  */
  GF_ERR_AGAIN = -16,		/* Out of room for now; retry after events.  */
  GF_ERR_PASSPHRASE = -17	/* The passphrase is wrong for the key file.  */
};

/* Return a description of STATUS, translated into the current locale.  */
const char *gf_strerror (int status);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_STATUS_H */
