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

/* The protocol version exchange (RFC 4253 section 4.2).

   Each side sends one line, "SSH-2.0-softwareversion SP comments CR LF",
   before anything else.  foxtrot speaks SSH 2.0 only: a peer that
   announces protocol version 1.99 (compatible with SSH-1) or 1.x is
   refused, and so is a line that does not end in CR LF.

   A server may send other lines of text before its identification line (a
   client must be ready for that, a server must not be); the parser skips
   them, up to a fixed limit.  Parsing is incremental in the usual way:
   the bytes after the identification line belong to the next layer and
   are left in the buffer.  */

#ifndef FOXTROT_IDENT_H
#define FOXTROT_IDENT_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/wire.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Longest identification line, counting CR LF (RFC 4253 section 4.2).  */
#define GF_IDENT_MAX 255
/* Most bytes of text a client skips before the server's line.  */
#define GF_IDENT_MAX_PREFIX 16384

typedef struct gf_ident
{
  uint8_t line[GF_IDENT_MAX + 1];
  size_t len;			/* Bytes of LINE in use.  */
  size_t skipped;		/* Bytes of other lines skipped so far.  */
  int state;
  int allow_prefix;
  size_t software;		/* Offset of the software version.  */
  size_t end;			/* Length of the line without CR LF.  */
} gf_ident;

/* ALLOW_PREFIX is nonzero in a client (the server may send text first).  */
void gf_ident_init (gf_ident *id, int allow_prefix);

/* Consume bytes from *BUF.  Returns GF_OK when the line is complete (*BUF
   is then just past its LF), GF_NEED_MORE when it is not, GF_ERR_ENCODING
   for a malformed line and GF_ERR_UNSUPPORTED for a protocol version
   other than 2.0.  Fails permanently after an error.  */
int gf_ident_parse (gf_ident *id, const uint8_t **buf, size_t *len);

/* The line without its CR LF: "SSH-2.0-OpenSSH_9.6 comments".  This is
   what the key exchange hashes as V_C or V_S.  Valid once parsing is done.  */
gf_slice gf_ident_string (const gf_ident *id);
/* Just the software version and, if any, comments.  */
gf_slice gf_ident_software (const gf_ident *id);

/* Write our line, "SSH-2.0-" SOFTWARE [SP COMMENTS] CR LF, into OUT.  The
   software version must be printable US-ASCII without spaces or hyphens,
   COMMENTS (may be NULL) printable US-ASCII.  *OUTLEN includes CR LF.  */
int gf_ident_format (const char *software, const char *comments,
                     uint8_t *out, size_t cap, size_t *outlen);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_IDENT_H */
