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

/* The ssh-agent codec.  The first byte says what the rest is:

     0  an agent's byte stream, fed whole, in chunks (the second byte sets
        their size) and a byte at a time: the same frames and the same
        status each time; every frame that comes out goes to the parsers;
     1  the payload of an IDENTITIES_ANSWER;
     2  the payload of a SIGN_RESPONSE;
     3  data for a SIGN_REQUEST and a session-bind (the second byte picks
        the key and the algorithm), read back field by field.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>
#include <foxtrot/agent.h>

#include "fuzz-common.h"
#include "vectors-agent.h"

#define NKEYS (sizeof vec_agent_signs / sizeof vec_agent_signs[0])
/* Every algorithm of policy.h, and two values that are not.  */
#define NALGS (GF_SIG_X509_RSA2048_SHA256 + 2)

static gf_key *keys[NKEYS];

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  static uint8_t b[4096];
  size_t i, n;

  (void) argc;
  (void) argv;
  gf_crypto_init ();
  for (i = 0; i < NKEYS; i++)
    {
      n = fuzz_unhex (vec_agent_signs[i].blob, b, sizeof b);
      if (gf_key_from_blob (&keys[i], b, n) != GF_OK)
        abort ();
    }
  return 0;
}

static void
die (const char *why)
{
  fprintf (stderr, "%s\n", why);
  abort ();
}

/* ---- Replies ---- */

struct idsink
{
  const uint8_t *payload;
  size_t len, calls;
};

static int
on_identity (void *user, const gf_key *key, gf_slice comment)
{
  struct idsink *s = user;
  gf_key *again = NULL;
  const uint8_t *b;
  size_t bl;

  s->calls++;
  if (key == NULL)
    die ("an identity with no key");
  if (comment.len > 0
      && (comment.data < s->payload
          || comment.data + comment.len > s->payload + s->len))
    die ("a comment outside the payload");
  /* The key is what its blob says it is.  */
  b = gf_key_blob (key, &bl);
  if (gf_key_from_blob (&again, b, bl) != GF_OK || !gf_key_equal (key, again))
    die ("an identity that is not its blob");
  gf_key_free (again);
  return 0;
}

static void
check_identities (const uint8_t *p, size_t len)
{
  struct idsink s = { p, len, 0 };
  size_t skipped = 99;
  int rc = gf_agent_identities (p, len, on_identity, &s, &skipped);

  if (rc == GF_OK)
    {
      uint8_t *more;
      uint32_t n = (uint32_t) p[1] << 24 | (uint32_t) p[2] << 16
        | (uint32_t) p[3] << 8 | p[4];
      struct idsink t = { NULL, 0, 0 };

      if (len < 5 || p[0] != GF_AGENT_IDENTITIES_ANSWER)
        die ("an identities answer that is not one");
      if (s.calls + skipped != n)
        die ("identities lost or made");
      /* A message is exactly its fields: a byte more or less is not one.  */
      more = malloc (len + 1);
      if (more == NULL)
        return;
      memcpy (more, p, len);
      more[len] = 0;
      if (gf_agent_identities (more, len + 1, on_identity, &t, NULL)
          != GF_ERR_ENCODING || t.calls != 0)
        die ("trailing bytes after identities");
      free (more);
      if (gf_agent_identities (p, len - 1, on_identity, &t, NULL)
          != GF_ERR_ENCODING || t.calls != 0)
        die ("a cut identities answer");
    }
  else if (s.calls != 0)
    die ("identities called for a message that is refused");
}

static void
check_sign_response (const uint8_t *p, size_t len)
{
  gf_slice sig;
  int rc = gf_agent_sign_response (p, len, &sig);

  if (rc == GF_OK)
    {
      uint8_t *again = malloc (len + 1);
      gf_slice s2;

      if (again == NULL)
        return;
      if (sig.len > 0 && (sig.data < p || sig.data + sig.len > p + len))
        die ("a signature outside the payload");
      if (len != 1 + 4 + sig.len || p[0] != GF_AGENT_SIGN_RESPONSE
          || sig.data != p + 5)
        die ("a signature response that is not one");
      memcpy (again, p, len);
      again[len] = 0;
      if (gf_agent_sign_response (again, len + 1, &s2) != GF_ERR_ENCODING)
        die ("trailing bytes after a signature");
      free (again);
    }
}

static void
check_frame (const uint8_t *p, size_t len)
{
  enum gf_agent_type t = gf_agent_type (p, len);

  if (t == GF_AGENT_IDENTITIES_ANSWER)
    check_identities (p, len);
  else if (t == GF_AGENT_SIGN_RESPONSE)
    check_sign_response (p, len);
  else
    {
      /* Neither parser takes what it is not.  */
      gf_slice sig;
      struct idsink s = { p, len, 0 };

      if (gf_agent_sign_response (p, len, &sig) == GF_OK)
        die ("a signature response from another type");
      if (gf_agent_identities (p, len, on_identity, &s, NULL) == GF_OK)
        die ("identities from another type");
    }
}

/* ---- The reader ---- */

struct sink
{
  size_t n, bytes;
  uint64_t hash;
};

static int
collect (void *user, const uint8_t *p, size_t len)
{
  struct sink *s = user;
  size_t i;

  if (len == 0 || len > GF_AGENT_MAX_FRAME)
    die ("a frame of an impossible size");
  s->n++;
  s->bytes += 4 + len;
  s->hash = (s->hash ^ len) * 1099511628211ull;
  for (i = 0; i < len; i++)
    s->hash = (s->hash ^ p[i]) * 1099511628211ull;
  check_frame (p, len);
  return 0;
}

static int
feed_in (const uint8_t *data, size_t size, size_t chunk, struct sink *s,
         int *idle)
{
  gf_agent_reader *r = NULL;
  size_t pos;
  int rc = GF_OK;

  memset (s, 0, sizeof *s);
  s->hash = 14695981039346656037ull;
  if (gf_agent_reader_new (&r) != GF_OK)
    return GF_ERR_NOMEM;
  for (pos = 0; pos < size && rc == GF_OK; pos += chunk)
    rc = gf_agent_reader_feed (r, data + pos,
                               size - pos < chunk ? size - pos : chunk,
                               collect, s);
  *idle = gf_agent_reader_idle (r);
  /* A reader that failed stays failed.  */
  if (rc != GF_OK && gf_agent_reader_feed (r, data, 1, collect, s) != GF_ERR_STATE)
    die ("a failed reader that carries on");
  gf_agent_reader_free (r);
  return rc;
}

static void
fuzz_reader (const uint8_t *data, size_t size, size_t chunk)
{
  struct sink whole, piece, bytes;
  int idle_w, idle_p, idle_b, rw, rp, rb;

  if (size == 0)
    return;
  rw = feed_in (data, size, size, &whole, &idle_w);
  rp = feed_in (data, size, chunk, &piece, &idle_p);
  rb = feed_in (data, size, 1, &bytes, &idle_b);
  if (rw == GF_ERR_NOMEM || rp == GF_ERR_NOMEM || rb == GF_ERR_NOMEM)
    return;
  if (rw != rp || rw != rb || whole.n != piece.n || whole.n != bytes.n
      || whole.hash != piece.hash || whole.hash != bytes.hash
      || idle_w != idle_p || idle_w != idle_b)
    die ("the reader's answer depends on how the bytes were cut");
  if (whole.bytes > size)
    die ("frames from more bytes than there were");
  if (rw == GF_OK && idle_w != (whole.bytes == size))
    die ("idle and the bytes left disagree");
}

/* ---- Requests ---- */

static size_t
be32 (const uint8_t *p)
{
  return (size_t) p[0] << 24 | (size_t) p[1] << 16 | (size_t) p[2] << 8 | p[3];
}

static void
fuzz_requests (const uint8_t *data, size_t size, unsigned sel)
{
  const gf_key *key = keys[sel % NKEYS];
  enum gf_sigalg alg = (enum gf_sigalg) ((sel / NKEYS) % NALGS);
  const char *name = gf_sigalg_name (alg);
  const char *kt = gf_key_type_name (key);
  size_t cap = size + 4096, len = 0, bl;
  uint8_t *out = malloc (cap);
  const uint8_t *blob = gf_key_blob (key, &bl);
  gf_reader r;
  gf_slice a, b;
  uint32_t flags;
  uint8_t t;
  int rc, forwarding;

  if (out == NULL)
    return;
  rc = gf_agent_sign_request (key, alg, data, size, out, cap, &len);
  if (rc == GF_OK)
    {
      unsigned want = 0;

      if (name == NULL || gf_sigalg_is_x509 (alg)
          || !gf_sigalg_matches_key_type (alg, kt, strlen (kt)))
        die ("a request for an algorithm that is not the key's");
      if (strstr (name, "rsa-sha2-256") != NULL)
        want = GF_AGENT_RSA_SHA2_256;
      else if (strstr (name, "rsa-sha2-512") != NULL)
        want = GF_AGENT_RSA_SHA2_512;
      if (len < 4 || be32 (out) != len - 4)
        die ("a request whose length is wrong");
      gf_reader_init (&r, out + 4, len - 4);
      if (gf_rd_u8 (&r, &t) != GF_OK || t != GF_AGENT_SIGN_REQUEST
          || gf_rd_string (&r, &a) != GF_OK || a.len != bl
          || memcmp (a.data, blob, bl) != 0
          || gf_rd_string (&r, &b) != GF_OK || b.len != size
          || (size > 0 && memcmp (b.data, data, size) != 0)
          || gf_rd_u32 (&r, &flags) != GF_OK || flags != want
          || gf_rd_finish (&r) != GF_OK)
        die ("a sign request that is not what was asked");
      /* One byte less room is too little.  */
      if (gf_agent_sign_request (key, alg, data, size, out, len - 1, &bl)
          != GF_ERR_BUFSIZE)
        die ("a request that fitted in too little");
    }
  else if (rc != GF_ERR_UNSUPPORTED)
    die ("a sign request failed for another reason");
  else if (name != NULL && !gf_sigalg_is_x509 (alg)
           && gf_sigalg_matches_key_type (alg, kt, strlen (kt))
           && alg != 0)
    die ("a sign request refused that policy allows");

  /* session-bind: the first bytes are the session identifier, the rest the
     signature.  */
  if (size >= 2)
    {
      gf_slice sid, sig;
      size_t cut = 1 + data[0] % (size - 1);

      sid.data = data + 1;
      sid.len = cut;
      sig.data = data + 1 + cut;
      sig.len = size - 1 - cut;
      if (sig.len == 0)
        sig = sid;
      rc = gf_agent_session_bind (keys[0], sid, sig, out, cap, &len);
      if (rc == GF_OK)
        {
          gf_reader_init (&r, out + 4, len - 4);
          blob = gf_key_blob (keys[0], &bl);
          if (be32 (out) != len - 4 || gf_rd_u8 (&r, &t) != GF_OK
              || t != GF_AGENT_EXTENSION
              || gf_rd_string (&r, &a) != GF_OK
              || !gf_slice_equals (a, "session-bind@openssh.com")
              || gf_rd_string (&r, &a) != GF_OK || a.len != bl
              || memcmp (a.data, blob, bl) != 0
              || gf_rd_string (&r, &a) != GF_OK || a.len != sid.len
              || memcmp (a.data, sid.data, sid.len) != 0
              || gf_rd_string (&r, &b) != GF_OK || b.len != sig.len
              || memcmp (b.data, sig.data, sig.len) != 0
              || gf_rd_bool (&r, &forwarding) != GF_OK || forwarding != 0
              || gf_rd_finish (&r) != GF_OK)
            die ("a session-bind that is not what was asked");
        }
      else if (rc != GF_ERR_BUFSIZE)
        die ("a session-bind failed for another reason");
    }
  free (out);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  unsigned mode;

  if (size < 2)
    return 0;
  mode = data[0] % 4;
  switch (mode)
    {
    case 0:
      fuzz_reader (data + 2, size - 2, 1 + data[1] % 97);
      break;
    case 1:
      check_identities (data + 1, size - 1);
      break;
    case 2:
      check_sign_response (data + 1, size - 1);
      break;
    default:
      fuzz_requests (data + 2, size - 2, data[1]);
      break;
    }
  return 0;
}
