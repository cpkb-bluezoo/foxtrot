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

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/wire.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>
#include <foxtrot/agent.h>

#define SESSION_BIND "session-bind@openssh.com"

/* ------------------------------------------------------------------ */
/* Framing                                                            */
/* ------------------------------------------------------------------ */

struct gf_agent_reader
{
  uint8_t hdr[4];		/* The length field, as far as it has come.  */
  size_t nhdr;
  size_t want;			/* The length of the frame being read; 0 while
				   the length is.  */
  uint8_t *buf;			/* The frame so far, if it did not arrive in
				   one piece.  */
  size_t have, cap;
  int failed;
};

int
gf_agent_reader_new (gf_agent_reader **out)
{
  if (out == NULL)
    return GF_ERR_INVAL;
  *out = calloc (1, sizeof **out);
  return *out ? GF_OK : GF_ERR_NOMEM;
}

void
gf_agent_reader_free (gf_agent_reader *r)
{
  if (r == NULL)
    return;
  free (r->buf);
  free (r);
}

int
gf_agent_reader_idle (const gf_agent_reader *r)
{
  return r != NULL && r->nhdr == 0 && r->want == 0;
}

/* The length field, checked.  Zero or too large is the end of the stream.  */
static int
frame_length (const uint8_t *p, size_t *want)
{
  uint32_t l = (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16
    | (uint32_t) p[2] << 8 | p[3];

  if (l == 0)
    return GF_ERR_ENCODING;
  if (l > GF_AGENT_MAX_FRAME)
    return GF_ERR_RANGE;
  *want = l;
  return GF_OK;
}

/* Room for N more bytes of the partial frame.  The buffer grows with what
   has arrived, never with what a length announced, and never past it.  */
static int
make_room (gf_agent_reader *r, size_t n)
{
  size_t need = r->have + n, cap;
  uint8_t *b;

  if (need <= r->cap)
    return GF_OK;
  cap = r->cap ? r->cap : 512;
  while (cap < need)
    cap *= 2;
  if (cap > r->want)
    cap = r->want;
  b = realloc (r->buf, cap);
  if (b == NULL)
    return GF_ERR_NOMEM;
  r->buf = b;
  r->cap = cap;
  return GF_OK;
}

static int
fail (gf_agent_reader *r, int status)
{
  r->failed = 1;
  return status;
}

int
gf_agent_reader_feed (gf_agent_reader *r, const uint8_t *data, size_t len,
                      gf_agent_frame_cb frame_cb, void *user)
{
  int rc;

  if (r == NULL || (data == NULL && len > 0) || frame_cb == NULL)
    return GF_ERR_INVAL;
  if (r->failed)
    return GF_ERR_STATE;

  while (len > 0)
    {
      size_t take;

      if (r->want == 0)
        {
          /* The length: from DATA if all four bytes are there, else a byte
             at a time.  */
          if (r->nhdr == 0 && len >= 4)
            {
              rc = frame_length (data, &r->want);
              data += 4;
              len -= 4;
            }
          else
            {
              while (len > 0 && r->nhdr < 4)
                {
                  r->hdr[r->nhdr++] = *data++;
                  len--;
                }
              if (r->nhdr < 4)
                break;
              rc = frame_length (r->hdr, &r->want);
              r->nhdr = 0;
            }
          if (rc != GF_OK)
            return fail (r, rc);
          r->have = 0;
          continue;
        }

      if (r->have == 0 && len >= r->want)
        {
          /* The whole frame is here: no copy.  */
          size_t n = r->want;

          r->want = 0;
          if (frame_cb (user, data, n) != 0)
            return fail (r, GF_ERR_HANDLER);
          data += n;
          len -= n;
          continue;
        }

      take = r->want - r->have;
      if (take > len)
        take = len;
      rc = make_room (r, take);
      if (rc != GF_OK)
        return fail (r, rc);
      memcpy (r->buf + r->have, data, take);
      r->have += take;
      data += take;
      len -= take;
      if (r->have == r->want)
        {
          size_t n = r->want;

          r->want = 0;
          r->have = 0;
          if (frame_cb (user, r->buf, n) != 0)
            return fail (r, GF_ERR_HANDLER);
        }
    }
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Requests                                                           */
/* ------------------------------------------------------------------ */

int
gf_agent_request_identities (uint8_t *out, size_t cap, size_t *len)
{
  gf_writer w;

  if (out == NULL || len == NULL)
    return GF_ERR_INVAL;
  gf_writer_init (&w, out, cap);
  gf_wr_u32 (&w, 1);
  gf_wr_u8 (&w, GF_AGENT_REQUEST_IDENTITIES);
  *len = w.len;
  return gf_wr_status (&w);
}

/* The flags for ALG, or -1 if an agent is not asked to sign under it.  */
static int
sign_flags (enum gf_sigalg alg)
{
  switch (alg)
    {
    case GF_SIG_RSA_SHA2_256:
    case GF_SIG_RSA_SHA2_256_CERT:
      return GF_AGENT_RSA_SHA2_256;
    case GF_SIG_RSA_SHA2_512:
    case GF_SIG_RSA_SHA2_512_CERT:
      return GF_AGENT_RSA_SHA2_512;
    case GF_SIG_ED25519:
    case GF_SIG_ECDSA_NISTP256:
    case GF_SIG_ECDSA_NISTP384:
    case GF_SIG_ED25519_CERT:
    case GF_SIG_ECDSA_NISTP256_CERT:
    case GF_SIG_ECDSA_NISTP384_CERT:
    case GF_SIG_SK_ED25519:
    case GF_SIG_SK_ECDSA_NISTP256:
    case GF_SIG_SK_ED25519_CERT:
    case GF_SIG_SK_ECDSA_NISTP256_CERT:
      return 0;
    default:
      /* Nothing else: not 0, not an unknown value, not X.509.  Above all,
         not RSA with SHA-1, which an agent signs when the flags are 0.  The
         key type check in gf_agent_sign_request refuses these as well today;
         this is what keeps it so should an algorithm be added to policy.h
         that an RSA key makes and that is not a SHA-2 one.  */
      return -1;
    }
}

int
gf_agent_sign_request (const gf_key *key, enum gf_sigalg alg,
                       const uint8_t *data, size_t datalen, uint8_t *out,
                       size_t cap, size_t *len)
{
  gf_writer w;
  const uint8_t *blob;
  size_t bloblen;
  const char *kt;
  int flags;

  if (key == NULL || (data == NULL && datalen > 0) || out == NULL
      || len == NULL)
    return GF_ERR_INVAL;
  flags = sign_flags (alg);
  kt = gf_key_type_name (key);
  if (flags < 0 || !gf_sigalg_matches_key_type (alg, kt, strlen (kt)))
    return GF_ERR_UNSUPPORTED;
  blob = gf_key_blob (key, &bloblen);
  if (datalen > GF_AGENT_MAX_FRAME
      || 1 + 4 + bloblen + 4 + datalen + 4 > GF_AGENT_MAX_FRAME)
    return GF_ERR_RANGE;

  gf_writer_init (&w, out, cap);
  gf_wr_u32 (&w, (uint32_t) (1 + 4 + bloblen + 4 + datalen + 4));
  gf_wr_u8 (&w, GF_AGENT_SIGN_REQUEST);
  gf_wr_string (&w, blob, bloblen);
  gf_wr_string (&w, data, datalen);
  gf_wr_u32 (&w, (uint32_t) flags);
  *len = w.len;
  return gf_wr_status (&w);
}

int
gf_agent_session_bind (const gf_key *hostkey, gf_slice session_id,
                       gf_slice signature, uint8_t *out, size_t cap,
                       size_t *len)
{
  gf_writer w;
  const uint8_t *blob;
  size_t bloblen, total;

  if (hostkey == NULL || out == NULL || len == NULL || session_id.len == 0
      || session_id.data == NULL || signature.len == 0
      || signature.data == NULL)
    return GF_ERR_INVAL;
  blob = gf_key_blob (hostkey, &bloblen);
  /* Each is a part of a frame that must be under GF_AGENT_MAX_FRAME, so
     the sum of the three below cannot wrap.  */
  if (bloblen > GF_AGENT_MAX_FRAME || session_id.len > GF_AGENT_MAX_FRAME
      || signature.len > GF_AGENT_MAX_FRAME)
    return GF_ERR_RANGE;
  total = 1 + 4 + (sizeof SESSION_BIND - 1) + 4 + bloblen + 4 + session_id.len
    + 4 + signature.len + 1;
  if (total > GF_AGENT_MAX_FRAME)
    return GF_ERR_RANGE;

  gf_writer_init (&w, out, cap);
  gf_wr_u32 (&w, (uint32_t) total);
  gf_wr_u8 (&w, GF_AGENT_EXTENSION);
  gf_wr_cstring (&w, SESSION_BIND);
  gf_wr_string (&w, blob, bloblen);
  gf_wr_string (&w, session_id.data, session_id.len);
  gf_wr_string (&w, signature.data, signature.len);
  gf_wr_bool (&w, 0);		/* is_forwarding: never.  */
  *len = w.len;
  return gf_wr_status (&w);
}

/* ------------------------------------------------------------------ */
/* Replies                                                            */
/* ------------------------------------------------------------------ */

enum gf_agent_type
gf_agent_type (const uint8_t *payload, size_t len)
{
  if (payload == NULL || len == 0)
    return GF_AGENT_UNKNOWN;
  switch (payload[0])
    {
    case GF_AGENT_FAILURE:
    case GF_AGENT_SUCCESS:
    case GF_AGENT_REQUEST_IDENTITIES:
    case GF_AGENT_EXTENSION_FAILURE:
      /* They carry nothing.  */
      return len == 1 ? (enum gf_agent_type) payload[0] : GF_AGENT_UNKNOWN;
    case GF_AGENT_IDENTITIES_ANSWER:
    case GF_AGENT_SIGN_REQUEST:
    case GF_AGENT_SIGN_RESPONSE:
    case GF_AGENT_EXTENSION:
      return (enum gf_agent_type) payload[0];
    default:
      return GF_AGENT_UNKNOWN;
    }
}

/* Start reading a message that must be of TYPE; R is left after the type
   byte.  */
static int
open_message (gf_reader *r, const uint8_t *payload, size_t len,
              enum gf_agent_type type)
{
  uint8_t t;

  if (payload == NULL)
    return GF_ERR_INVAL;
  gf_reader_init (r, payload, len);
  if (gf_rd_u8 (r, &t) != GF_OK)
    return GF_ERR_ENCODING;
  return t == (uint8_t) type ? GF_OK : GF_ERR_PROTOCOL;
}

int
gf_agent_identities (const uint8_t *payload, size_t len,
                     gf_agent_identity_cb identity_cb, void *user,
                     size_t *skipped)
{
  gf_reader r, again;
  gf_slice blob, comment;
  uint32_t n, i;
  size_t nskipped = 0;
  int rc;

  if (identity_cb == NULL)
    return GF_ERR_INVAL;
  if (skipped != NULL)
    *skipped = 0;
  rc = open_message (&r, payload, len, GF_AGENT_IDENTITIES_ANSWER);
  if (rc != GF_OK)
    return rc;
  if (gf_rd_u32 (&r, &n) != GF_OK)
    return GF_ERR_ENCODING;

  /* The whole message is checked before anything is called.  What the
     count says does not matter: every identity takes at least eight bytes
     (two strings, even if empty) or this fails, so it is not read more
     often than the bytes could hold, whatever the count.  */
  again = r;
  for (i = 0; i < n; i++)
    if (gf_rd_string (&again, &blob) != GF_OK
        || gf_rd_string (&again, &comment) != GF_OK)
      return GF_ERR_ENCODING;
  if (gf_rd_finish (&again) != GF_OK)
    return GF_ERR_ENCODING;

  for (i = 0; i < n; i++)
    {
      gf_key *key = NULL;

      if (gf_rd_string (&r, &blob) != GF_OK
          || gf_rd_string (&r, &comment) != GF_OK)
        return GF_ERR_ENCODING;	/* Not reached.  */
      rc = gf_key_from_blob (&key, blob.data, blob.len);
      if (rc == GF_ERR_NOMEM)
        return rc;
      if (rc != GF_OK)
        {
          nskipped++;
          continue;
        }
      rc = identity_cb (user, key, comment);
      gf_key_free (key);
      if (rc != 0)
        {
          if (skipped != NULL)
            *skipped = nskipped;
          return GF_ERR_HANDLER;
        }
    }
  if (skipped != NULL)
    *skipped = nskipped;
  return GF_OK;
}

int
gf_agent_sign_response (const uint8_t *payload, size_t len, gf_slice *sig)
{
  gf_reader r;
  gf_slice s;
  int rc;

  if (sig == NULL)
    return GF_ERR_INVAL;
  rc = open_message (&r, payload, len, GF_AGENT_SIGN_RESPONSE);
  if (rc != GF_OK)
    return rc;
  if (gf_rd_string (&r, &s) != GF_OK || gf_rd_finish (&r) != GF_OK)
    return GF_ERR_ENCODING;
  *sig = s;
  return GF_OK;
}
