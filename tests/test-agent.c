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

/* The ssh-agent protocol: the messages of a real OpenSSH ssh-agent (see
   gen-agent-vectors.py), the reader fed in every chunk size, and the
   messages that must be refused.  */

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

#include "tst-util.h"
#include "vectors-agent.h"

#define NIDS (sizeof vec_agent_ids / sizeof vec_agent_ids[0])
#define NSIGNS (sizeof vec_agent_signs / sizeof vec_agent_signs[0])

static uint8_t *
unhex (const char *hex, size_t *n)
{
  size_t cap = strlen (hex) / 2 + 1;
  uint8_t *b = malloc (cap);

  CHECK (b != NULL);
  *n = tst_unhex (hex, b, cap);
  return b;
}

/* Hex given in pieces (a string over 4095 characters is not portable C).  */
static uint8_t *
unhex_parts (const char *const *parts, size_t *n)
{
  size_t i, total = 0, off = 0;
  uint8_t *b;

  for (i = 0; parts[i] != NULL; i++)
    total += strlen (parts[i]) / 2;
  b = malloc (total + 1);
  CHECK (b != NULL);
  for (i = 0; parts[i] != NULL; i++)
    off += tst_unhex (parts[i], b + off, total - off);
  *n = off;
  return b;
}

static gf_key *
key_of (const char *hex)
{
  size_t n;
  uint8_t *b = unhex (hex, &n);
  gf_key *k = NULL;

  CHECK_EQ (gf_key_from_blob (&k, b, n), GF_OK);
  free (b);
  return k;
}

/* A frame around PAYLOAD (N bytes), in a new buffer of N + 4 bytes.  */
static uint8_t *
framed (const uint8_t *payload, size_t n)
{
  uint8_t *f = malloc (n + 4);

  CHECK (f != NULL);
  f[0] = (uint8_t) (n >> 24);
  f[1] = (uint8_t) (n >> 16);
  f[2] = (uint8_t) (n >> 8);
  f[3] = (uint8_t) n;
  memcpy (f + 4, payload, n);
  return f;
}

/* ---- The identities answer ---- */

struct idlist
{
  size_t n;
  uint8_t blob[16][4096];
  size_t bloblen[16];
  uint8_t comment[16][64];
  size_t commentlen[16];
  size_t stop_at;		/* Return nonzero at this call; 0: never.  */
};

static int
on_identity (void *user, const gf_key *key, gf_slice comment)
{
  struct idlist *l = user;
  size_t bl;
  const uint8_t *b = gf_key_blob (key, &bl);

  if (l->n < 16 && bl <= sizeof l->blob[0] && comment.len <= sizeof l->comment[0])
    {
      memcpy (l->blob[l->n], b, bl);
      l->bloblen[l->n] = bl;
      memcpy (l->comment[l->n], comment.data, comment.len);
      l->commentlen[l->n] = comment.len;
    }
  l->n++;
  return l->stop_at != 0 && l->n == l->stop_at;
}

/* The real agent's answer: the keys foxtrot takes, in order, with their
   comments, and a count of the three it does not (P-521, a 1024-bit RSA key
   and DSA).  */
static void
test_identities_real (void)
{
  size_t n, i, j = 0, skipped = 99, expect_skipped = 0;
  uint8_t *p = unhex_parts (vec_agent_identities, &n);
  struct idlist *l = calloc (1, sizeof *l);

  CHECK (l != NULL);
  CHECK_EQ (gf_agent_type (p, n), GF_AGENT_IDENTITIES_ANSWER);
  CHECK_EQ (gf_agent_identities (p, n, on_identity, l, &skipped), GF_OK);
  for (i = 0; i < NIDS; i++)
    {
      size_t bn;
      uint8_t *b;

      if (!vec_agent_ids[i].accepted)
        {
          expect_skipped++;
          continue;
        }
      b = unhex (vec_agent_ids[i].blob, &bn);
      CHECK (j < l->n);
      if (j < l->n)
        {
          CHECK (l->bloblen[j] == bn && memcmp (l->blob[j], b, bn) == 0);
          CHECK (l->commentlen[j] == strlen (vec_agent_ids[i].comment)
                 && memcmp (l->comment[j], vec_agent_ids[i].comment,
                            l->commentlen[j]) == 0);
        }
      free (b);
      j++;
    }
  CHECK_EQ (l->n, j);
  CHECK_EQ (skipped, expect_skipped);
  CHECK_EQ (expect_skipped, 3);
  CHECK_EQ (NIDS - expect_skipped, 6);

  /* SKIPPED is optional.  */
  l->n = 0;
  CHECK_EQ (gf_agent_identities (p, n, on_identity, l, NULL), GF_OK);
  CHECK_EQ (l->n, j);

  /* A callback that stops the walk.  */
  l->n = 0;
  l->stop_at = 2;
  CHECK_EQ (gf_agent_identities (p, n, on_identity, l, &skipped),
            GF_ERR_HANDLER);
  CHECK_EQ (l->n, 2);
  free (p);
  free (l);
}

static void
test_identities_empty (void)
{
  size_t n, skipped = 99;
  uint8_t *p = unhex (vec_agent_empty_answer, &n);
  struct idlist *l = calloc (1, sizeof *l);

  CHECK_EQ (gf_agent_type (p, n), GF_AGENT_IDENTITIES_ANSWER);
  CHECK_EQ (gf_agent_identities (p, n, on_identity, l, &skipped), GF_OK);
  CHECK_EQ (l->n, 0);
  CHECK_EQ (skipped, 0);
  free (p);
  free (l);
}

/* Every prefix of the answer is malformed, and nothing is called: the whole
   message is checked first.  Anything after it is malformed too.  */
static void
test_identities_malformed (void)
{
  size_t n, i, skipped;
  uint8_t *p = unhex_parts (vec_agent_identities, &n);
  uint8_t *q = malloc (n + 1);
  struct idlist *l = calloc (1, sizeof *l);

  CHECK (q != NULL && l != NULL);
  for (i = 0; i < n; i++)
    {
      l->n = 0;
      skipped = 99;
      CHECK_EQ (gf_agent_identities (p, i, on_identity, l, &skipped),
                GF_ERR_ENCODING);
      CHECK_EQ (l->n, 0);
    }
  memcpy (q, p, n);
  q[n] = 0;
  l->n = 0;
  CHECK_EQ (gf_agent_identities (q, n + 1, on_identity, l, NULL),
            GF_ERR_ENCODING);
  CHECK_EQ (l->n, 0);

  /* The last identity's comment cut short by a byte, with the lengths of
     everything before it good: no callback for the ones before.  */
  l->n = 0;
  CHECK_EQ (gf_agent_identities (p, n - 1, on_identity, l, NULL),
            GF_ERR_ENCODING);
  CHECK_EQ (l->n, 0);

  /* Another type, or nothing.  */
  CHECK_EQ (gf_agent_identities (p, 0, on_identity, l, NULL), GF_ERR_ENCODING);
  q[0] = GF_AGENT_SIGN_RESPONSE;
  CHECK_EQ (gf_agent_identities (q, n, on_identity, l, NULL), GF_ERR_PROTOCOL);
  q[0] = GF_AGENT_FAILURE;
  CHECK_EQ (gf_agent_identities (q, 1, on_identity, l, NULL), GF_ERR_PROTOCOL);
  CHECK_EQ (l->n, 0);
  free (p);
  free (q);
  free (l);
}

/* A count the bytes cannot hold, whatever the count says.  */
static void
test_identities_count (void)
{
  static const uint32_t counts[] = { 1, 2, 0x7fffffff, 0x80000000u, 0xffffffffu,
                                     0x20000000, 0x40000000 };
  uint8_t m[5 + 8];
  size_t i;
  struct idlist *l = calloc (1, sizeof *l);

  CHECK (l != NULL);
  /* One identity's worth of bytes (two empty strings).  */
  memset (m, 0, sizeof m);
  m[0] = GF_AGENT_IDENTITIES_ANSWER;
  for (i = 0; i < sizeof counts / sizeof counts[0]; i++)
    {
      m[1] = (uint8_t) (counts[i] >> 24);
      m[2] = (uint8_t) (counts[i] >> 16);
      m[3] = (uint8_t) (counts[i] >> 8);
      m[4] = (uint8_t) counts[i];
      CHECK_EQ (gf_agent_identities (m, sizeof m, on_identity, l, NULL),
                counts[i] == 1 ? GF_OK : GF_ERR_ENCODING);
    }
  /* Count 1, an empty blob that gf_key_from_blob refuses: skipped.  */
  {
    size_t skipped = 0;

    m[1] = m[2] = m[3] = 0;
    m[4] = 1;
    CHECK_EQ (gf_agent_identities (m, sizeof m, on_identity, l, &skipped),
              GF_OK);
    CHECK_EQ (skipped, 1);
    CHECK_EQ (l->n, 0);
  }
  /* Count 0 with bytes after it.  */
  m[4] = 0;
  CHECK_EQ (gf_agent_identities (m, sizeof m, on_identity, l, NULL),
            GF_ERR_ENCODING);
  /* A string that runs past the end.  */
  m[4] = 1;
  m[8] = 0xff;
  CHECK_EQ (gf_agent_identities (m, sizeof m, on_identity, l, NULL),
            GF_ERR_ENCODING);
  m[5] = 0xff;
  m[8] = 0;
  CHECK_EQ (gf_agent_identities (m, sizeof m, on_identity, l, NULL),
            GF_ERR_ENCODING);
  CHECK_EQ (gf_agent_identities (NULL, 0, NULL, l, NULL), GF_ERR_INVAL);
  free (l);
}

/* Append a string to the message M, which is N bytes long.  */
static void
put_string (uint8_t *m, size_t *n, const void *data, size_t len)
{
  m[(*n)++] = (uint8_t) (len >> 24);
  m[(*n)++] = (uint8_t) (len >> 16);
  m[(*n)++] = (uint8_t) (len >> 8);
  m[(*n)++] = (uint8_t) len;
  memcpy (m + *n, data, len);
  *n += len;
}

static size_t
be32 (const uint8_t *p)
{
  return (size_t) p[0] << 24 | (size_t) p[1] << 16 | (size_t) p[2] << 8 | p[3];
}

/* An identity that is a DSA key by name, one that is junk, and a good one
   among them; the comment is bytes that mean something to a terminal.  */
static void
test_identities_skipped (void)
{
  static const uint8_t comment[] = { 'a', 0, 'b', 0x1b, '[', '2', 'J', 0xff };
  size_t bn, n = 0, skipped = 0, i;
  uint8_t *good = unhex (vec_agent_ids[0].blob, &bn);
  uint8_t *m = malloc (1024);
  struct idlist *l = calloc (1, sizeof *l);
  /* ssh-dss and four mpints: a blob that is a DSA key's in form.  */
  static const uint8_t dss[] = {
    0, 0, 0, 7, 's', 's', 'h', '-', 'd', 's', 's',
    0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1
  };

  CHECK (m != NULL && l != NULL);
  m[n++] = GF_AGENT_IDENTITIES_ANSWER;
  memcpy (m + n, "\0\0\0\3", 4);
  n += 4;
  put_string (m, &n, dss, sizeof dss);
  put_string (m, &n, "", 0);
  put_string (m, &n, good, bn);
  put_string (m, &n, comment, sizeof comment);
  put_string (m, &n, "xyz", 3);	/* Junk.  */
  put_string (m, &n, "", 0);

  CHECK_EQ (gf_agent_identities (m, n, on_identity, l, &skipped), GF_OK);
  CHECK_EQ (skipped, 2);
  CHECK_EQ (l->n, 1);
  CHECK (l->bloblen[0] == bn && memcmp (l->blob[0], good, bn) == 0);
  CHECK (l->commentlen[0] == sizeof comment
         && memcmp (l->comment[0], comment, sizeof comment) == 0);
  for (i = 0; i < n; i++)
    CHECK (gf_agent_identities (m, i, on_identity, l, NULL) == GF_ERR_ENCODING);
  free (good);
  free (m);
  free (l);
}

/* ---- Signing ---- */

static void
test_sign_real (void)
{
  size_t i, msglen;
  uint8_t *msg = unhex (vec_agent_msg, &msglen);

  for (i = 0; i < NSIGNS; i++)
    {
      const struct vec_agent_sign *v = &vec_agent_signs[i];
      size_t bn, rn, qn, len = 0, rl;
      uint8_t *blob = unhex (v->blob, &bn);
      uint8_t *want = unhex (v->request, &qn);
      uint8_t *resp = unhex (v->response, &rn);
      uint8_t out[4096];
      gf_key *k = key_of (v->blob);
      enum gf_sigalg alg = gf_sigalg_from_name (v->alg, strlen (v->alg));
      gf_slice sig;

      if (k == NULL || alg == 0)
        {
          fprintf (stderr, "%s: no key or algorithm\n", v->name);
          tst_failures++;
          free (blob);
          free (want);
          free (resp);
          gf_key_free (k);
          continue;
        }
      /* The request is the one the agent signed for, byte for byte.  */
      CHECK_EQ (gf_agent_sign_request (k, alg, msg, msglen, out, sizeof out,
                                       &len), GF_OK);
      CHECK_EQ (len, qn + 4);
      CHECK (len == qn + 4 && memcmp (out + 4, want, qn) == 0);
      rl = be32 (out);
      CHECK_EQ (rl, qn);
      CHECK_EQ (want[0], GF_AGENT_SIGN_REQUEST);
      /* The flags, which are the last four bytes.  */
      CHECK_EQ (want[qn - 1], v->flags);
      CHECK_EQ (out[len - 1], v->flags);

      /* The reply is a signature the library verifies.  */
      CHECK_EQ (gf_agent_type (resp, rn), GF_AGENT_SIGN_RESPONSE);
      CHECK_EQ (gf_agent_sign_response (resp, rn, &sig), GF_OK);
      CHECK_EQ (gf_key_verify (k, alg, msg, msglen, sig.data, sig.len), GF_OK);
      /* Not for other data.  */
      CHECK (gf_key_verify (k, alg, msg, msglen - 1, sig.data, sig.len)
             != GF_OK);
      free (blob);
      free (want);
      free (resp);
      gf_key_free (k);
    }
  free (msg);
}

static void
test_failure_and_unknown (void)
{
  size_t n;
  uint8_t *f = unhex (vec_agent_failure, &n);
  gf_slice sig;
  uint8_t *u = unhex (vec_agent_unknown_extension_answer, &n);
  uint8_t m[8];

  CHECK_EQ (gf_agent_type (f, 1), GF_AGENT_FAILURE);
  CHECK_EQ (gf_agent_sign_response (f, 1, &sig), GF_ERR_PROTOCOL);
  CHECK_EQ (gf_agent_type (u, n), GF_AGENT_FAILURE);
  free (f);
  free (u);

  /* The types, and what is not one.  */
  memset (m, 0, sizeof m);
  m[0] = 5;
  CHECK_EQ (gf_agent_type (m, 1), GF_AGENT_FAILURE);
  m[0] = 6;
  CHECK_EQ (gf_agent_type (m, 1), GF_AGENT_SUCCESS);
  m[0] = 11;
  CHECK_EQ (gf_agent_type (m, 1), GF_AGENT_REQUEST_IDENTITIES);
  m[0] = 12;
  CHECK_EQ (gf_agent_type (m, 5), GF_AGENT_IDENTITIES_ANSWER);
  m[0] = 13;
  CHECK_EQ (gf_agent_type (m, 8), GF_AGENT_SIGN_REQUEST);
  m[0] = 14;
  CHECK_EQ (gf_agent_type (m, 8), GF_AGENT_SIGN_RESPONSE);
  m[0] = 27;
  CHECK_EQ (gf_agent_type (m, 8), GF_AGENT_EXTENSION);
  m[0] = 28;
  CHECK_EQ (gf_agent_type (m, 1), GF_AGENT_EXTENSION_FAILURE);
  /* Nothing, anything else, and bytes after a message with no contents.  */
  CHECK_EQ (gf_agent_type (m, 0), GF_AGENT_UNKNOWN);
  CHECK_EQ (gf_agent_type (NULL, 0), GF_AGENT_UNKNOWN);
  {
    unsigned t;

    for (t = 0; t < 256; t++)
      {
        m[0] = (uint8_t) t;
        if (t != 5 && t != 6 && t != 11 && t != 12 && t != 13 && t != 14
            && t != 27 && t != 28)
          CHECK_EQ (gf_agent_type (m, 8), GF_AGENT_UNKNOWN);
      }
  }
  m[0] = 5;
  CHECK_EQ (gf_agent_type (m, 2), GF_AGENT_UNKNOWN);
  m[0] = 6;
  CHECK_EQ (gf_agent_type (m, 2), GF_AGENT_UNKNOWN);
  m[0] = 28;
  CHECK_EQ (gf_agent_type (m, 2), GF_AGENT_UNKNOWN);
  m[0] = 11;
  CHECK_EQ (gf_agent_type (m, 2), GF_AGENT_UNKNOWN);
}

static void
test_sign_response_malformed (void)
{
  size_t n, i;
  uint8_t *p = unhex (vec_agent_signs[0].response, &n);
  uint8_t *q = malloc (n + 1);
  gf_slice sig;

  CHECK (q != NULL);
  CHECK_EQ (gf_agent_sign_response (p, n, &sig), GF_OK);
  CHECK (sig.data == p + 5 && sig.len == n - 5);	/* A slice of the payload.  */
  for (i = 0; i < n; i++)
    CHECK_EQ (gf_agent_sign_response (p, i, &sig), GF_ERR_ENCODING);
  memcpy (q, p, n);
  q[n] = 0;
  CHECK_EQ (gf_agent_sign_response (q, n + 1, &sig), GF_ERR_ENCODING);
  /* A length that runs past the end by one.  */
  memcpy (q, p, n);
  q[4]++;
  CHECK_EQ (gf_agent_sign_response (q, n, &sig), GF_ERR_ENCODING);
  /* A huge one.  */
  q[1] = 0xff;
  q[4]--;
  CHECK_EQ (gf_agent_sign_response (q, n, &sig), GF_ERR_ENCODING);
  /* Another type.  */
  memcpy (q, p, n);
  q[0] = GF_AGENT_IDENTITIES_ANSWER;
  CHECK_EQ (gf_agent_sign_response (q, n, &sig), GF_ERR_PROTOCOL);
  CHECK_EQ (gf_agent_sign_response (p, n, NULL), GF_ERR_INVAL);
  free (p);
  free (q);
}

/* Which algorithm gives which flag, and which are refused.  */
static void
test_sign_flags (void)
{
  static const struct
  {
    const char *vector;		/* A key to ask about, by vec_agent_signs name.  */
    enum gf_sigalg alg;
    int flags;			/* -1: GF_ERR_UNSUPPORTED.  */
  } t[] = {
    { "ed25519", GF_SIG_ED25519, 0 },
    { "p256", GF_SIG_ECDSA_NISTP256, 0 },
    { "p384", GF_SIG_ECDSA_NISTP384, 0 },
    { "rsa256", GF_SIG_RSA_SHA2_256, 2 },
    { "rsa256", GF_SIG_RSA_SHA2_512, 4 },
    { "ed25519_cert", GF_SIG_ED25519_CERT, 0 },
    { "rsa256_cert", GF_SIG_RSA_SHA2_256_CERT, 2 },
    { "rsa512_cert", GF_SIG_RSA_SHA2_512_CERT, 4 },
    /* The wrong algorithm for the key: a type, a certificate for a plain
       key and a plain algorithm for a certificate.  */
    { "ed25519", GF_SIG_RSA_SHA2_256, -1 },
    { "rsa256", GF_SIG_ED25519, -1 },
    { "p256", GF_SIG_ECDSA_NISTP384, -1 },
    { "p384", GF_SIG_ECDSA_NISTP256, -1 },
    { "ed25519", GF_SIG_ED25519_CERT, -1 },
    { "ed25519_cert", GF_SIG_ED25519, -1 },
    { "rsa256", GF_SIG_RSA_SHA2_256_CERT, -1 },
    { "rsa256_cert", GF_SIG_RSA_SHA2_256, -1 },
    /* Not an algorithm: 0 is what a name the policy refuses ("ssh-rsa",
       SHA-1) comes out as.  */
    { "rsa256", (enum gf_sigalg) 0, -1 },
    { "rsa256", (enum gf_sigalg) 99, -1 },
    { "rsa256", (enum gf_sigalg) -1, -1 },
    /* An agent holds no X.509 chain.  */
    { "p256", GF_SIG_X509_ECDSA_NISTP256, -1 },
    { "rsa256", GF_SIG_X509_RSA2048_SHA256, -1 },
  };
  uint8_t data[8] = "datadata", out[4096];
  size_t i, j;

  CHECK_EQ (gf_sigalg_from_name ("ssh-rsa", 7), 0);
  for (i = 0; i < sizeof t / sizeof t[0]; i++)
    {
      gf_key *k = NULL;
      size_t len = 0;
      int rc;

      for (j = 0; j < NSIGNS; j++)
        if (strcmp (vec_agent_signs[j].name, t[i].vector) == 0)
          k = key_of (vec_agent_signs[j].blob);
      CHECK (k != NULL);
      if (k == NULL)
        continue;
      rc = gf_agent_sign_request (k, t[i].alg, data, sizeof data, out,
                                  sizeof out, &len);
      if (t[i].flags < 0)
        CHECK_EQ (rc, GF_ERR_UNSUPPORTED);
      else
        {
          CHECK_EQ (rc, GF_OK);
          CHECK_EQ (out[len - 1], t[i].flags);
          CHECK (out[len - 2] == 0 && out[len - 3] == 0 && out[len - 4] == 0);
        }
      gf_key_free (k);
    }
}

/* A security key is named in a request like any other, with no flags.  */
static void
test_sign_sk (void)
{
  gf_key *k = key_of (vec_agent_sk_blob);
  uint8_t out[512];
  size_t len = 0, bn;
  uint8_t *blob = unhex (vec_agent_sk_blob, &bn);

  CHECK (k != NULL);
  CHECK_EQ (gf_agent_sign_request (k, GF_SIG_SK_ED25519, (const uint8_t *) "x",
                                   1, out, sizeof out, &len), GF_OK);
  CHECK_EQ (len, 4 + 1 + 4 + bn + 4 + 1 + 4);
  CHECK (memcmp (out + 9, blob, bn) == 0);
  CHECK_EQ (out[len - 1], 0);
  /* A plain Ed25519 algorithm is not the security key's.  */
  CHECK_EQ (gf_agent_sign_request (k, GF_SIG_ED25519, (const uint8_t *) "x", 1,
                                   out, sizeof out, &len), GF_ERR_UNSUPPORTED);
  free (blob);
  gf_key_free (k);
}

static void
test_sign_limits (void)
{
  gf_key *k = key_of (vec_agent_signs[0].blob);
  size_t bn, len, fixed, i;
  uint8_t *blob = unhex (vec_agent_signs[0].blob, &bn);
  uint8_t *data = calloc (GF_AGENT_MAX_FRAME + 2, 1);
  uint8_t *out = malloc (GF_AGENT_MAX_FRAME + 64);
  uint8_t small[16], tiny[GF_AGENT_SIGN_OVERHEAD + 128];
  size_t need;

  CHECK (data != NULL && out != NULL && k != NULL);
  /* The frame of exactly the limit, and one byte more.  */
  fixed = 1 + 4 + bn + 4 + 4;
  CHECK_EQ (gf_agent_sign_request (k, GF_SIG_ED25519, data,
                                   GF_AGENT_MAX_FRAME - fixed, out,
                                   GF_AGENT_MAX_FRAME + 64, &len), GF_OK);
  CHECK_EQ (len, GF_AGENT_MAX_FRAME + 4);
  CHECK_EQ (gf_agent_sign_request (k, GF_SIG_ED25519, data,
                                   GF_AGENT_MAX_FRAME - fixed + 1, out,
                                   GF_AGENT_MAX_FRAME + 64, &len),
            GF_ERR_RANGE);
  CHECK_EQ (gf_agent_sign_request (k, GF_SIG_ED25519, data,
                                   GF_AGENT_MAX_FRAME + 1, out,
                                   GF_AGENT_MAX_FRAME + 64, &len),
            GF_ERR_RANGE);
  /* The documented overhead.  */
  need = GF_AGENT_SIGN_OVERHEAD + bn + 3;
  CHECK_EQ (gf_agent_sign_request (k, GF_SIG_ED25519, data, 3, tiny,
                                   need, &len), GF_OK);
  CHECK_EQ (len, need);
  /* Every smaller buffer is too small.  */
  for (i = 0; i < need; i++)
    CHECK_EQ (gf_agent_sign_request (k, GF_SIG_ED25519, data, 3, tiny, i, &len),
              GF_ERR_BUFSIZE);
  /* Empty data is a string of length 0.  */
  CHECK_EQ (gf_agent_sign_request (k, GF_SIG_ED25519, NULL, 0, tiny, sizeof tiny,
                                   &len), GF_OK);
  CHECK_EQ (len, GF_AGENT_SIGN_OVERHEAD + bn);
  CHECK_EQ (gf_agent_sign_request (k, GF_SIG_ED25519, NULL, 1, tiny,
                                   sizeof tiny, &len), GF_ERR_INVAL);
  CHECK_EQ (gf_agent_sign_request (NULL, GF_SIG_ED25519, data, 1, small,
                                   sizeof small, &len), GF_ERR_INVAL);
  free (blob);
  free (data);
  free (out);
  gf_key_free (k);
}

static void
test_request_identities (void)
{
  static const uint8_t want[] = { 0, 0, 0, 1, 11 };
  uint8_t out[8];
  size_t len = 0, i;

  CHECK_EQ (gf_agent_request_identities (out, sizeof out, &len), GF_OK);
  CHECK (len == sizeof want && memcmp (out, want, len) == 0);
  CHECK_EQ (gf_agent_request_identities (out, sizeof want, &len), GF_OK);
  for (i = 0; i < sizeof want; i++)
    CHECK_EQ (gf_agent_request_identities (out, i, &len), GF_ERR_BUFSIZE);
  CHECK_EQ (gf_agent_request_identities (NULL, 8, &len), GF_ERR_INVAL);
}

/* ---- session-bind ---- */

static void
test_session_bind (void)
{
  size_t hn, sn, gn, bn, qn, qbn, len = 0, i;
  uint8_t *hk = unhex (vec_agent_bind_hostkey, &hn);
  uint8_t *sid = unhex (vec_agent_session_id, &sn);
  uint8_t *sig = unhex (vec_agent_bind_sig, &gn);
  uint8_t *bad = unhex (vec_agent_bind_bad_sig, &bn);
  uint8_t *want = unhex (vec_agent_bind_request, &qn);
  uint8_t *wantbad = unhex (vec_agent_bind_bad_request, &qbn);
  gf_key *k = key_of (vec_agent_bind_hostkey);
  uint8_t *out = malloc (4096);
  gf_slice s = { sid, sn }, g = { sig, gn }, b = { bad, bn };

  CHECK (out != NULL && k != NULL);
  /* What the agent accepted and what it refused, as they were sent.  */
  CHECK_EQ (gf_agent_session_bind (k, s, g, out, 4096, &len), GF_OK);
  CHECK_EQ (len, qn + 4);
  CHECK (len == qn + 4 && memcmp (out + 4, want, qn) == 0);
  CHECK_EQ (be32 (out), qn);
  CHECK_EQ (gf_agent_type (out + 4, qn), GF_AGENT_EXTENSION);
  CHECK_EQ (len, GF_AGENT_BIND_OVERHEAD + hn + sn + gn);
  CHECK_EQ (gf_agent_session_bind (k, s, b, out, 4096, &len), GF_OK);
  CHECK (len == qbn + 4 && memcmp (out + 4, wantbad, qbn) == 0);
  /* The forwarding flag is clear.  */
  CHECK_EQ (out[len - 1], 0);

  CHECK_EQ (gf_agent_session_bind (k, s, g, out, 4096, &len), GF_OK);
  for (i = 0; i < len; i++)
    CHECK_EQ (gf_agent_session_bind (k, s, g, out, i, &len), GF_ERR_BUFSIZE);

  /* Nothing to bind to.  */
  {
    gf_slice none = { sid, 0 }, nul = { NULL, 4 };

    CHECK_EQ (gf_agent_session_bind (k, none, g, out, 4096, &len), GF_ERR_INVAL);
    CHECK_EQ (gf_agent_session_bind (k, s, none, out, 4096, &len), GF_ERR_INVAL);
    CHECK_EQ (gf_agent_session_bind (k, nul, g, out, 4096, &len), GF_ERR_INVAL);
    CHECK_EQ (gf_agent_session_bind (k, s, nul, out, 4096, &len), GF_ERR_INVAL);
    CHECK_EQ (gf_agent_session_bind (NULL, s, g, out, 4096, &len), GF_ERR_INVAL);
  }
  /* A signature too large for a frame.  */
  {
    gf_slice huge = { sig, GF_AGENT_MAX_FRAME };

    CHECK_EQ (gf_agent_session_bind (k, s, huge, out, 4096, &len),
              GF_ERR_RANGE);
  }
  free (hk);
  free (sid);
  free (sig);
  free (bad);
  free (want);
  free (wantbad);
  free (out);
  gf_key_free (k);
}

/* ---- The reader ---- */

struct frames
{
  size_t n;
  size_t len[8];
  uint8_t *data[8];
  const uint8_t *seen;		/* Where the first frame was delivered from.  */
  size_t stop_at;
};

static int
on_frame (void *user, const uint8_t *p, size_t len)
{
  struct frames *f = user;

  if (f->n < 8)
    {
      f->len[f->n] = len;
      f->data[f->n] = malloc (len);
      CHECK (f->data[f->n] != NULL);
      memcpy (f->data[f->n], p, len);
      if (f->n == 0)
        f->seen = p;
    }
  f->n++;
  return f->stop_at != 0 && f->n == f->stop_at;
}

static void
frames_free (struct frames *f)
{
  size_t i;

  for (i = 0; i < f->n && i < 8; i++)
    free (f->data[i]);
  memset (f, 0, sizeof *f);
}

/* The stream of the real agent's replies, fed whole and in every chunk size
   from 1 to its length, gives the same frames.  */
static void
test_reader_chunks (void)
{
  size_t sn, in, en, fn = 1, total, c, i;
  uint8_t *ident = unhex_parts (vec_agent_identities, &in);
  uint8_t *sign = unhex (vec_agent_signs[3].response, &sn);
  uint8_t *empty = unhex (vec_agent_empty_answer, &en);
  uint8_t fail = GF_AGENT_FAILURE;
  const uint8_t *payloads[4];
  size_t lens[4];
  uint8_t *stream, *f;
  size_t off = 0, k;

  payloads[0] = ident;
  lens[0] = in;
  payloads[1] = sign;
  lens[1] = sn;
  payloads[2] = empty;
  lens[2] = en;
  payloads[3] = &fail;
  lens[3] = fn;
  total = 4 * 4 + in + sn + en + fn;
  stream = malloc (total);
  CHECK (stream != NULL);
  for (k = 0; k < 4; k++)
    {
      f = framed (payloads[k], lens[k]);
      memcpy (stream + off, f, lens[k] + 4);
      off += lens[k] + 4;
      free (f);
    }
  CHECK_EQ (off, total);

  for (c = 1; c <= total + 1; c++)
    {
      gf_agent_reader *r = NULL;
      struct frames fr;
      int rc = GF_OK;

      memset (&fr, 0, sizeof fr);
      CHECK_EQ (gf_agent_reader_new (&r), GF_OK);
      CHECK (gf_agent_reader_idle (r));
      for (i = 0; i < total && rc == GF_OK; i += c)
        rc = gf_agent_reader_feed (r, stream + i, total - i < c ? total - i : c,
                                   on_frame, &fr);
      CHECK_EQ (rc, GF_OK);
      CHECK_EQ (fr.n, 4);
      for (k = 0; k < 4 && k < fr.n; k++)
        CHECK (fr.len[k] == lens[k] && memcmp (fr.data[k], payloads[k], lens[k]) == 0);
      CHECK (gf_agent_reader_idle (r));
      frames_free (&fr);
      gf_agent_reader_free (r);
    }
  free (stream);
  free (ident);
  free (sign);
  free (empty);
}

/* A frame that arrives whole is not copied; one that does not is held until
   it is complete, and the reader says it is in the middle of one.  */
static void
test_reader_idle_and_zero_copy (void)
{
  uint8_t payload[10] = { 14, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  uint8_t *f = framed (payload, sizeof payload);
  gf_agent_reader *r = NULL;
  struct frames fr;
  size_t i;

  memset (&fr, 0, sizeof fr);
  CHECK_EQ (gf_agent_reader_new (&r), GF_OK);
  CHECK_EQ (gf_agent_reader_feed (r, f, 14, on_frame, &fr), GF_OK);
  CHECK_EQ (fr.n, 1);
  CHECK (fr.seen == f + 4);
  CHECK (gf_agent_reader_idle (r));
  frames_free (&fr);

  /* Every proper prefix leaves it between frames only if it is empty.  */
  for (i = 1; i < 14; i++)
    {
      CHECK_EQ (gf_agent_reader_feed (r, f, i, on_frame, &fr), GF_OK);
      CHECK_EQ (fr.n, 0);
      CHECK (!gf_agent_reader_idle (r));
      CHECK_EQ (gf_agent_reader_feed (r, f + i, 14 - i, on_frame, &fr), GF_OK);
      CHECK_EQ (fr.n, 1);
      CHECK (gf_agent_reader_idle (r));
      CHECK (fr.len[0] == sizeof payload
             && memcmp (fr.data[0], payload, sizeof payload) == 0);
      frames_free (&fr);
    }
  /* Nothing is not input.  */
  CHECK_EQ (gf_agent_reader_feed (r, NULL, 0, on_frame, &fr), GF_OK);
  CHECK_EQ (gf_agent_reader_feed (r, f, 0, on_frame, &fr), GF_OK);
  CHECK (gf_agent_reader_idle (r));
  CHECK_EQ (gf_agent_reader_feed (r, f, 1, NULL, &fr), GF_ERR_INVAL);
  CHECK_EQ (gf_agent_reader_feed (NULL, f, 1, on_frame, &fr), GF_ERR_INVAL);
  gf_agent_reader_free (r);
  gf_agent_reader_free (NULL);
  free (f);
}

/* A length of zero and a length over the limit end the stream, as soon as
   the four bytes of it are in and whatever follows, in every split; the
   reader then refuses everything.  */
static void
test_reader_bad_length (void)
{
  static const struct
  {
    uint8_t len[4];
    int status;
  } t[] = {
    { { 0, 0, 0, 0 }, GF_ERR_ENCODING },
    { { 0, 4, 0, 1 }, GF_ERR_RANGE },	/* The limit and one more.  */
    { { 0, 4, 0, 0 }, GF_OK },		/* The limit itself.  */
    { { 0, 5, 0, 0 }, GF_ERR_RANGE },
    { { 0, 0xff, 0xff, 0xff }, GF_ERR_RANGE },
    { { 0x7f, 0xff, 0xff, 0xff }, GF_ERR_RANGE },
    { { 0x80, 0, 0, 0 }, GF_ERR_RANGE },
    { { 0xff, 0xff, 0xff, 0xff }, GF_ERR_RANGE },
  };
  size_t i, split;

  for (i = 0; i < sizeof t / sizeof t[0]; i++)
    for (split = 1; split <= 4; split++)
      {
        gf_agent_reader *r = NULL;
        struct frames fr;
        int rc;
        const uint8_t junk[3] = { 14, 14, 14 };

        memset (&fr, 0, sizeof fr);
        CHECK_EQ (gf_agent_reader_new (&r), GF_OK);
        /* Nothing but the length arrives: it is judged by itself.  */
        rc = gf_agent_reader_feed (r, t[i].len, split, on_frame, &fr);
        if (split < 4)
          {
            CHECK_EQ (rc, GF_OK);
            rc = gf_agent_reader_feed (r, t[i].len + split, 4 - split, on_frame,
                                       &fr);
          }
        CHECK_EQ (rc, t[i].status);
        CHECK_EQ (fr.n, 0);
        if (t[i].status != GF_OK)
          {
            CHECK_EQ (gf_agent_reader_feed (r, junk, sizeof junk, on_frame, &fr),
                      GF_ERR_STATE);
            CHECK_EQ (fr.n, 0);
          }
        gf_agent_reader_free (r);
      }

  /* And in the middle of a stream, behind a good frame.  */
  {
    uint8_t s[5 + 4] = { 0, 0, 0, 1, 6, 0, 4, 0, 1 };
    gf_agent_reader *r = NULL;
    struct frames fr;

    memset (&fr, 0, sizeof fr);
    CHECK_EQ (gf_agent_reader_new (&r), GF_OK);
    CHECK_EQ (gf_agent_reader_feed (r, s, sizeof s, on_frame, &fr), GF_ERR_RANGE);
    CHECK_EQ (fr.n, 1);		/* The good frame was delivered first.  */
    frames_free (&fr);
    gf_agent_reader_free (r);
  }
}

/* The frame of exactly the limit is read, whole and in pieces.  */
static void
test_reader_max_frame (void)
{
  uint8_t *p = calloc (GF_AGENT_MAX_FRAME, 1);
  uint8_t *f;
  static const size_t chunks[] = { 1, 7, 4096, 65536, GF_AGENT_MAX_FRAME + 4 };
  size_t c, i;

  CHECK (p != NULL);
  p[0] = GF_AGENT_SIGN_RESPONSE;
  p[GF_AGENT_MAX_FRAME - 1] = 0x5a;
  f = framed (p, GF_AGENT_MAX_FRAME);
  for (c = 0; c < sizeof chunks / sizeof chunks[0]; c++)
    {
      gf_agent_reader *r = NULL;
      struct frames fr;
      int rc = GF_OK;

      memset (&fr, 0, sizeof fr);
      CHECK_EQ (gf_agent_reader_new (&r), GF_OK);
      for (i = 0; i < GF_AGENT_MAX_FRAME + 4 && rc == GF_OK; i += chunks[c])
        {
          size_t n = GF_AGENT_MAX_FRAME + 4 - i;

          rc = gf_agent_reader_feed (r, f + i, n < chunks[c] ? n : chunks[c],
                                     on_frame, &fr);
        }
      CHECK_EQ (rc, GF_OK);
      CHECK_EQ (fr.n, 1);
      CHECK (fr.len[0] == GF_AGENT_MAX_FRAME
             && memcmp (fr.data[0], p, GF_AGENT_MAX_FRAME) == 0);
      CHECK (gf_agent_reader_idle (r));
      frames_free (&fr);
      gf_agent_reader_free (r);
    }
  free (f);
  free (p);
}

/* The callback stopping the walk fails the reader, with frames behind it
   in the same chunk undelivered.  */
static void
test_reader_handler_stop (void)
{
  uint8_t s[] = { 0, 0, 0, 1, 6, 0, 0, 0, 1, 5, 0, 0, 0, 1, 6 };
  static const uint8_t held[] = { 0, 0, 0, 2, 6, 7 };
  gf_agent_reader *r = NULL;
  struct frames fr;

  memset (&fr, 0, sizeof fr);
  fr.stop_at = 2;
  CHECK_EQ (gf_agent_reader_new (&r), GF_OK);
  CHECK_EQ (gf_agent_reader_feed (r, s, sizeof s, on_frame, &fr),
            GF_ERR_HANDLER);
  CHECK_EQ (fr.n, 2);
  CHECK_EQ (gf_agent_reader_feed (r, s, 5, on_frame, &fr), GF_ERR_STATE);
  CHECK_EQ (fr.n, 2);
  frames_free (&fr);
  gf_agent_reader_free (r);

  /* The same from a frame that was held until it was complete.  */
  memset (&fr, 0, sizeof fr);
  fr.stop_at = 1;
  CHECK_EQ (gf_agent_reader_new (&r), GF_OK);
  CHECK_EQ (gf_agent_reader_feed (r, held, 5, on_frame, &fr), GF_OK);
  CHECK_EQ (fr.n, 0);
  CHECK_EQ (gf_agent_reader_feed (r, held + 5, 1, on_frame, &fr),
            GF_ERR_HANDLER);
  CHECK_EQ (fr.n, 1);
  CHECK_EQ (gf_agent_reader_feed (r, held, 1, on_frame, &fr), GF_ERR_STATE);
  frames_free (&fr);
  gf_agent_reader_free (r);
}

/* A request made here is read back by the reader as the payload.  */
static void
test_roundtrip (void)
{
  uint8_t out[128];
  size_t len;
  gf_agent_reader *r = NULL;
  struct frames fr;

  memset (&fr, 0, sizeof fr);
  CHECK_EQ (gf_agent_request_identities (out, sizeof out, &len), GF_OK);
  CHECK_EQ (gf_agent_reader_new (&r), GF_OK);
  CHECK_EQ (gf_agent_reader_feed (r, out, len, on_frame, &fr), GF_OK);
  CHECK_EQ (fr.n, 1);
  CHECK (fr.len[0] == 1 && fr.data[0][0] == GF_AGENT_REQUEST_IDENTITIES);
  CHECK_EQ (gf_agent_type (fr.data[0], fr.len[0]), GF_AGENT_REQUEST_IDENTITIES);
  frames_free (&fr);
  gf_agent_reader_free (r);
}

int
main (void)
{
  CHECK_EQ (gf_crypto_init (), GF_OK);
  test_identities_real ();
  test_identities_empty ();
  test_identities_malformed ();
  test_identities_count ();
  test_identities_skipped ();
  test_sign_real ();
  test_failure_and_unknown ();
  test_sign_response_malformed ();
  test_sign_flags ();
  test_sign_sk ();
  test_sign_limits ();
  test_request_identities ();
  test_session_bind ();
  test_reader_chunks ();
  test_reader_idle_and_zero_copy ();
  test_reader_bad_length ();
  test_reader_max_frame ();
  test_reader_handler_stop ();
  test_roundtrip ();
  TST_DONE ();
}
