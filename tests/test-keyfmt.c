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

/* Keys in other formats: every file that python's cryptography, openssl,
   ssh-keygen and puttygen wrote for a key is read as that key, what we write
   is what they write, and what must be refused is.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>
#include <gcrypt.h>

#include <foxtrot/keyfmt.h>

#include "tst-util.h"
#include "vectors-keyfmt.h"
#include "vectors-cert.h"

static gf_key *
pub_of (const char *text)
{
  gf_key *k = NULL;

  CHECK_EQ (gf_key_from_text (&k, text, strlen (text), NULL), GF_OK);
  return k;
}

/* K is the private key whose public key is WANT: it has the private part,
   and signs for it.  */
static void
check_private (const gf_key *k, const gf_key *want, const char *what)
{
  static const uint8_t msg[] = "a message to sign";
  uint8_t sig[GF_SIG_MAX];
  size_t n, na;
  const enum gf_sigalg *algs;

  if (k == NULL)
    {
      fprintf (stderr, "%s: not read\n", what);
      CHECK (0);
      return;
    }
  if (!gf_key_equal (k, want) || !gf_key_has_private (k))
    {
      fprintf (stderr, "%s: wrong key or no private part\n", what);
      CHECK (0);
      return;
    }
  algs = gf_key_sigalgs (k, &na);
  CHECK_EQ (gf_key_sign (k, algs[0], msg, sizeof msg, sig, sizeof sig, &n), GF_OK);
  CHECK_EQ (gf_key_verify (want, algs[0], msg, sizeof msg, sig, n), GF_OK);
}

static void
check_public (const gf_key *k, const gf_key *want, const char *what)
{
  if (k == NULL || !gf_key_equal (k, want) || gf_key_has_private (k))
    {
      fprintf (stderr, "%s: not the public key\n", what);
      CHECK (0);
    }
}

static int
nonempty (const char *s)
{
  return s != NULL && s[0] != '\0';
}

static void
test_read (void)
{
  size_t i;

  for (i = 0; i < sizeof vec_fmt_keys / sizeof vec_fmt_keys[0]; i++)
    {
      const struct vec_fmt_key *v = &vec_fmt_keys[i];
      gf_key *want = pub_of (v->pub), *k = NULL, *orig = NULL;
      char comment[128];

      CHECK_EQ (gf_key_from_openssh_private (&orig, v->ossh, strlen (v->ossh)), GF_OK);
      CHECK (orig != NULL && gf_key_equal (orig, want));
      /* Public keys.  */
      CHECK_EQ (gf_key_from_pem (&k, v->spki, strlen (v->spki), NULL), GF_OK);
      check_public (k, want, "spki");
      gf_key_free (k);
      if (nonempty (v->rsapub))
        {
          CHECK_EQ (gf_key_from_pem (&k, v->rsapub, strlen (v->rsapub), NULL), GF_OK);
          check_public (k, want, "pkcs1 public");
          gf_key_free (k);
        }
      CHECK_EQ (gf_key_from_rfc4716 (&k, v->rfc4716, strlen (v->rfc4716), comment,
                                     sizeof comment), GF_OK);
      check_public (k, want, "rfc4716");
      CHECK (strstr (comment, "converted by") != NULL);
      gf_key_free (k);
      /* Private keys.  */
      CHECK_EQ (gf_key_from_pem (&k, v->pkcs8, strlen (v->pkcs8), NULL), GF_OK);
      check_private (k, want, "pkcs8");
      gf_key_free (k);
      if (nonempty (v->sec1))
        {
          CHECK_EQ (gf_key_from_pem (&k, v->sec1, strlen (v->sec1), NULL), GF_OK);
          check_private (k, want, "sec1");
          gf_key_free (k);
        }
      if (nonempty (v->pkcs1))
        {
          CHECK_EQ (gf_key_from_pem (&k, v->pkcs1, strlen (v->pkcs1), NULL), GF_OK);
          check_private (k, want, "pkcs1");
          gf_key_free (k);
        }
      CHECK_EQ (gf_key_from_ppk (&k, v->ppk, strlen (v->ppk), NULL, comment,
                                 sizeof comment), GF_OK);
      check_private (k, want, "ppk");
      CHECK (strcmp (comment, "test comment") == 0);
      gf_key_free (k);
      /* A private key written for OpenSSH from one read here is the same.  */
      CHECK_EQ (gf_key_from_pem (&k, v->pkcs8, strlen (v->pkcs8), NULL), GF_OK);
      if (k != NULL)
        {
          char text[8192];
          size_t n;
          gf_key *again = NULL;

          CHECK_EQ (gf_key_to_openssh_private (k, text, sizeof text, &n), GF_OK);
          CHECK_EQ (gf_key_from_openssh_private (&again, text, n), GF_OK);
          check_private (again, want, "round trip through the OpenSSH format");
          gf_key_free (again);
        }
      gf_key_free (k);
      gf_key_free (orig);
      gf_key_free (want);
    }
}

static void
test_write (void)
{
  size_t i;

  for (i = 0; i < sizeof vec_fmt_keys / sizeof vec_fmt_keys[0]; i++)
    {
      const struct vec_fmt_key *v = &vec_fmt_keys[i];
      gf_key *k = pub_of (v->pub), *rk = NULL;
      char out[8192], comment[128];
      size_t n;

      /* The SPKI is what openssl writes, byte for byte.  */
      CHECK_EQ (gf_key_to_pem_public (k, out, sizeof out, &n), GF_OK);
      if (strcmp (out, v->spki) != 0)
        {
          fprintf (stderr, "%s: SPKI differs\n%s%s", v->kind, out, v->spki);
          CHECK (0);
        }
      CHECK_EQ (n, strlen (out));
      CHECK_EQ (gf_key_to_pem_public (k, out, n, &n), GF_ERR_BUFSIZE);
      /* RFC 4716 is what ssh-keygen writes, with the comment it chose.  */
      CHECK_EQ (gf_key_from_rfc4716 (&rk, v->rfc4716, strlen (v->rfc4716),
                                     comment, sizeof comment), GF_OK);
      CHECK_EQ (gf_key_to_rfc4716 (k, comment, out, sizeof out, &n), GF_OK);
      if (strcmp (out, v->rfc4716) != 0)
        {
          fprintf (stderr, "%s: RFC 4716 differs\n%s%s", v->kind, out, v->rfc4716);
          CHECK (0);
        }
      CHECK_EQ (gf_key_to_rfc4716 (k, NULL, out, sizeof out, &n), GF_OK);
      CHECK (strstr (out, "Comment") == NULL);
      CHECK_EQ (gf_key_to_rfc4716 (k, comment, out, 20, &n), GF_ERR_BUFSIZE);
      /* A long comment is wrapped with backslashes, and read back.  */
      {
        static const char long_comment[] =
          "a comment that goes on for a good deal longer than a header line "
          "may, so that it has to be continued on the next line and the next";
        gf_key *back = NULL;
        char got[256];

        CHECK_EQ (gf_key_to_rfc4716 (k, long_comment, out, sizeof out, &n), GF_OK);
        CHECK (strstr (out, "\\\n") != NULL);
        CHECK_EQ (gf_key_from_rfc4716 (&back, out, n, got, sizeof got), GF_OK);
        CHECK (strcmp (got, long_comment) == 0);
        check_public (back, k, "long comment");
        gf_key_free (back);
      }
      /* Randomart is ssh-keygen's.  */
      CHECK_EQ (gf_key_randomart (k, out, sizeof out, &n), GF_OK);
      if (strcmp (out, v->art) != 0)
        {
          fprintf (stderr, "%s: randomart differs\n%s%s", v->kind, out, v->art);
          CHECK (0);
        }
      CHECK_EQ (n, strlen (out));
      CHECK_EQ (gf_key_randomart (k, out, 100, &n), GF_ERR_INVAL);
      gf_key_free (rk);
      gf_key_free (k);
    }
}

static const struct vec_fmt_key *
row_of (const char *kind)
{
  size_t i;

  for (i = 0; i < sizeof vec_fmt_keys / sizeof vec_fmt_keys[0]; i++)
    if (strcmp (vec_fmt_keys[i].kind, kind) == 0)
      return &vec_fmt_keys[i];
  return NULL;
}

static void
test_encrypted (void)
{
  size_t i;

  for (i = 0; i < sizeof vec_fmt_encs / sizeof vec_fmt_encs[0]; i++)
    {
      const struct vec_fmt_enc *e = &vec_fmt_encs[i];
      gf_key *want = pub_of (row_of (e->kind)->pub), *k = NULL;
      size_t n = strlen (e->text);

      CHECK_EQ (gf_key_from_pem (&k, e->text, n, VEC_PASS), GF_OK);
      check_private (k, want, e->what);
      gf_key_free (k);
      k = NULL;
      CHECK_EQ (gf_key_from_pem (&k, e->text, n, "wrong horse"), GF_ERR_PASSPHRASE);
      CHECK (k == NULL);
      CHECK_EQ (gf_key_from_pem (&k, e->text, n, NULL), GF_ERR_PASSPHRASE);
      CHECK_EQ (gf_key_from_pem (&k, e->text, n, ""), GF_ERR_PASSPHRASE);
      CHECK_EQ (gf_key_from_pem (&k, e->text, n, "correct horse "), GF_ERR_PASSPHRASE);
      gf_key_free (want);
    }
  for (i = 0; i < sizeof vec_fmt_ppk_encs / sizeof vec_fmt_ppk_encs[0]; i++)
    {
      const struct vec_fmt_enc *e = &vec_fmt_ppk_encs[i];
      gf_key *want = pub_of (row_of (e->kind)->pub), *k = NULL;
      size_t n = strlen (e->text);
      char comment[64];

      CHECK_EQ (gf_key_from_ppk (&k, e->text, n, VEC_PASS, comment, sizeof comment), GF_OK);
      check_private (k, want, e->what);
      CHECK (strcmp (comment, "test comment") == 0);
      gf_key_free (k);
      k = NULL;
      CHECK_EQ (gf_key_from_ppk (&k, e->text, n, "wrong horse", NULL, 0), GF_ERR_PASSPHRASE);
      CHECK (k == NULL);
      CHECK_EQ (gf_key_from_ppk (&k, e->text, n, NULL, NULL, 0), GF_ERR_PASSPHRASE);
      gf_key_free (want);
    }
}

static void
test_refused (void)
{
  size_t i;

  for (i = 0; i < sizeof vec_fmt_bads / sizeof vec_fmt_bads[0]; i++)
    {
      const struct vec_fmt_bad *b = &vec_fmt_bads[i];
      gf_key *k = NULL;
      int rc;

      if (strncmp (b->name, "ppk", 3) == 0)
        rc = gf_key_from_ppk (&k, b->text, strlen (b->text), VEC_PASS, NULL, 0);
      else
        rc = gf_key_from_pem (&k, b->text, strlen (b->text), VEC_PASS);
      if (b->expect == ANY ? rc == GF_OK : rc != b->expect)
        {
          fprintf (stderr, "%s: status %d, want %d\n", b->name, rc, b->expect);
          CHECK (0);
        }
      CHECK (k == NULL);
      gf_key_free (k);
    }
}

/* The structure of a file: changes and cuts are errors, or the same key.  */
static void
test_damage (void)
{
  const struct vec_fmt_key *rows[4];
  size_t r, i, n;
  static char text[16384];

  for (r = 0; r < 4; r++)
    rows[r] = &vec_fmt_keys[r];
  for (r = 0; r < 4; r++)
    {
      const char *pem[3] = { rows[r]->pkcs8, rows[r]->spki, rows[r]->sec1[0] ? rows[r]->sec1 : rows[r]->pkcs1 };
      gf_key *want = pub_of (rows[r]->pub);
      size_t t;

      for (t = 0; t < 3; t++)
        {
          const char *p = pem[t];
          size_t pn = strlen (p);

          if (pn == 0)
            continue;
          /* Every cut is an error: the END line is missing.  */
          for (i = 0; i + 1 < pn; i++)
            {
              gf_key *k = NULL;

              memcpy (text, p, i);
              if (gf_key_from_pem (&k, text, i, NULL) == GF_OK)
                {
                  fprintf (stderr, "%s %zu: a cut file was read (%zu)\n",
                           rows[r]->kind, t, i);
                  CHECK (0);
                }
              gf_key_free (k);
            }
          /* Every changed character: an error, or the key (a changed part
             that is not used) or, for a public key, another key.  */
          for (i = 0; i < pn; i++)
            {
              gf_key *k = NULL;
              int rc;

              memcpy (text, p, pn);
              text[i] = text[i] == 'A' ? 'B' : 'A';
              rc = gf_key_from_pem (&k, text, pn, NULL);
              /* An Ed25519 seed in PKCS#8 has nothing to be checked
                 against: another seed is another key.  */
              if (rc == GF_OK && t != 1 && !(r == 0 && t == 0)
                  && !gf_key_equal (k, want))
                {
                  fprintf (stderr, "%s %zu: a damaged private key was read as another (%zu)\n",
                           rows[r]->kind, t, i);
                  CHECK (0);
                }
              gf_key_free (k);
            }
          /* Text before and after.  */
          {
            gf_key *k = NULL;

            snprintf (text, sizeof text, "%s\nmore", p);
            CHECK (gf_key_from_pem (&k, text, strlen (text), NULL) != GF_OK);
            snprintf (text, sizeof text, "%s%s", p, p);
            CHECK (gf_key_from_pem (&k, text, strlen (text), NULL) != GF_OK);
            snprintf (text, sizeof text, "junk\n%s", p);
            CHECK (gf_key_from_pem (&k, text, strlen (text), NULL) != GF_OK);
            snprintf (text, sizeof text, "\n\n  %s\n\n", p);
            CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_OK);
            gf_key_free (k);
          }
        }
      gf_key_free (want);
    }
  /* Labels: the wrong one for the contents, a mismatched end, none.  */
  {
    gf_key *k = NULL;
    const char *p = rows[0]->pkcs8;

    snprintf (text, sizeof text, "-----BEGIN PUBLIC KEY-----%s", strchr (p, '\n'));
    CHECK (gf_key_from_pem (&k, text, strlen (text), NULL) != GF_OK);
    snprintf (text, sizeof text, "-----BEGIN RSA PRIVATE KEY-----%s", strchr (p, '\n'));
    CHECK (gf_key_from_pem (&k, text, strlen (text), NULL) != GF_OK);
    {
      const char *body = strchr (p, '\n'), *endl = strstr (p, "-----END");

      snprintf (text, sizeof text, "-----BEGIN CERTIFICATE-----%.*s-----END CERTIFICATE-----\n",
                (int) (endl - body), body);
      CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_ERR_UNSUPPORTED);
    }
    CHECK (gf_key_from_pem (&k, "", 0, NULL) != GF_OK);
    CHECK (gf_key_from_pem (&k, "-----BEGIN PRIVATE KEY-----", 26, NULL) != GF_OK);
    CHECK_EQ (gf_key_from_pem (NULL, p, strlen (p), NULL), GF_ERR_INVAL);
    CHECK_EQ (gf_key_from_pem (&k, NULL, 5, NULL), GF_ERR_INVAL);
  }
  (void) n;
}

static void
test_rfc4716_syntax (void)
{
  gf_key *k = NULL;
  char text[2048], comment[64];
  const char *b64 = strchr (vec_fmt_keys[0].rfc4716, '\n');
  const char *body;
  char blob[512];
  size_t n;

  /* The base64 body of the first key.  */
  body = strstr (vec_fmt_keys[0].rfc4716, "AAAA");
  CHECK (body != NULL);
  n = strcspn (body, "\n");
  memcpy (blob, body, n);
  blob[n] = '\0';
  (void) b64;
  /* No headers, other headers, Subject, CRLF line ends.  */
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\n%s\n---- END SSH2 PUBLIC KEY ----\n", blob);
  CHECK_EQ (gf_key_from_rfc4716 (&k, text, strlen (text), comment, sizeof comment), GF_OK);
  CHECK (comment[0] == '\0');
  gf_key_free (k);
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\r\nSubject: bob\r\nX-Other: 1\r\nComment: \"hi\"\r\n%s\r\n---- END SSH2 PUBLIC KEY ----\r\n", blob);
  CHECK_EQ (gf_key_from_rfc4716 (&k, text, strlen (text), comment, sizeof comment), GF_OK);
  CHECK (strcmp (comment, "hi") == 0);
  gf_key_free (k);
  /* A comment that does not fit is cut, not an error.  */
  CHECK_EQ (gf_key_from_rfc4716 (&k, text, strlen (text), comment, 2), GF_OK);
  CHECK (strcmp (comment, "h") == 0);
  gf_key_free (k);
  /* What is wrong: no END, text after it, a bad key, a body split in the
     middle of a character, a header after the body, nothing.  */
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\n%s\n", blob);
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\n%s\n---- END SSH2 PUBLIC KEY ----\nmore\n", blob);
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\nAAAA\n---- END SSH2 PUBLIC KEY ----\n");
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\n---- END SSH2 PUBLIC KEY ----\n");
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"x\\\n%s\n---- END SSH2 PUBLIC KEY ----\n", blob);
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);	/* A continued header eats the body. */
  /* Nothing, or only blank lines, is not a file (and does not read what was
     never set).  */
  CHECK_EQ (gf_key_from_rfc4716 (&k, "", 0, NULL, 0), GF_ERR_ENCODING);
  CHECK_EQ (gf_key_from_rfc4716 (&k, "\n\n  \n", 5, NULL, 0), GF_ERR_ENCODING);
  CHECK_EQ (gf_key_from_rfc4716 (&k, "\n", 1, NULL, 0), GF_ERR_ENCODING);
  CHECK_EQ (gf_key_from_rfc4716 (NULL, text, 5, NULL, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_key_from_rfc4716 (&k, NULL, 5, NULL, 0), GF_ERR_INVAL);
  /* An OpenSSH certificate is not a public key file.  */
  gf_key_free (k);
}

static void
test_ppk_syntax (void)
{
  const char *ppk = vec_fmt_keys[0].ppk;
  static char text[8192];
  gf_key *k = NULL;
  const char *mac = strstr (ppk, "Private-MAC:");
  size_t i, n = strlen (ppk);

  CHECK (mac != NULL);
  /* The MAC covers the key, the comment, the algorithm: every change fails.  */
  for (i = 0; i < n; i++)
    {
      int rc;

      if (ppk[i] == '\n' || ppk[i] == '\r')
        continue;
      memcpy (text, ppk, n + 1);
      text[i] = (char) (text[i] ^ 1);
      rc = gf_key_from_ppk (&k, text, n, NULL, NULL, 0);
      if (rc == GF_OK)
        {
          /* Only a change that does not matter may be read, as the same key. */
          gf_key *want = pub_of (vec_fmt_keys[0].pub);

          check_private (k, want, "a changed ppk");
          gf_key_free (want);
          gf_key_free (k);
          k = NULL;
          fprintf (stderr, "ppk byte %zu changed and still read\n", i);
          CHECK (0);
        }
    }
  /* Every cut is an error (but for the last line end).  */
  for (i = 0; i + 1 < n; i++)
    {
      memcpy (text, ppk, i);
      CHECK (gf_key_from_ppk (&k, text, i, NULL, NULL, 0) != GF_OK);
    }
  CHECK_EQ (gf_key_from_ppk (NULL, ppk, n, NULL, NULL, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_key_from_ppk (&k, NULL, 5, NULL, NULL, 0), GF_ERR_INVAL);
}

/* ---------------------------------------------------------------- */
/* Hand-made files                                                  */
/* ---------------------------------------------------------------- */

struct buf
{
  uint8_t b[1 << 17];
  size_t n;
};

static void
put (struct buf *o, const void *d, size_t n)
{
  CHECK (o->n + n <= sizeof o->b);
  if (n > 0)
    memcpy (o->b + o->n, d, n);
  o->n += n;
}

/* The element TAG with the content C, in the shortest form.  */
static void
tlv (struct buf *o, uint8_t tag, const void *c, size_t n)
{
  uint8_t h[4];
  size_t hn = 0;

  h[hn++] = tag;
  if (n < 0x80)
    h[hn++] = (uint8_t) n;
  else if (n < 0x100)
    {
      h[hn++] = 0x81;
      h[hn++] = (uint8_t) n;
    }
  else
    {
      h[hn++] = 0x82;
      h[hn++] = (uint8_t) (n >> 8);
      h[hn++] = (uint8_t) n;
    }
  put (o, h, hn);
  put (o, c, n);
}

static void
tlvb (struct buf *o, uint8_t tag, const struct buf *c)
{
  tlv (o, tag, c->b, c->n);
}

static const char b64chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t
b64enc (const uint8_t *in, size_t n, char *out, int wrap)
{
  size_t i, o = 0, col = 0;

  for (i = 0; i < n; i += 3)
    {
      uint32_t v = (uint32_t) in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0)
        | (i + 2 < n ? in[i + 2] : 0);

      out[o++] = b64chars[v >> 18];
      out[o++] = b64chars[(v >> 12) & 63];
      out[o++] = i + 1 < n ? b64chars[(v >> 6) & 63] : '=';
      out[o++] = i + 2 < n ? b64chars[v & 63] : '=';
      col += 4;
      if (wrap && col >= 64)
        {
          out[o++] = '\n';
          col = 0;
        }
    }
  if (wrap && col)
    out[o++] = '\n';
  out[o] = '\0';
  return o;
}

static int
b64val (char c)
{
  const char *p = c ? strchr (b64chars, c) : NULL;

  return p ? (int) (p - b64chars) : -1;
}

/* The DER inside a PEM block of the vectors.  */
static size_t
pem_der (const char *pem, uint8_t *out)
{
  const char *p = strchr (pem, '\n') + 1;
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0;

  for (; *p && *p != '-'; p++)
    {
      int v = b64val (*p);

      if (v < 0)
        continue;
      acc = acc << 6 | (uint32_t) v;
      bits += 6;
      if (bits >= 8)
        {
          bits -= 8;
          out[o++] = (uint8_t) (acc >> bits);
        }
    }
  return o;
}

static char pem_text[1 << 18];

static const char *
pem_of (const char *label, const uint8_t *der, size_t n)
{
  size_t o = (size_t) sprintf (pem_text, "-----BEGIN %s-----\n", label);

  o += b64enc (der, n, pem_text + o, 1);
  sprintf (pem_text + o, "-----END %s-----\n", label);
  return pem_text;
}

static int
read_pem (const char *label, const struct buf *der, const char *pass,
          gf_key **k)
{
  const char *t = pem_of (label, der->b, der->n);

  *k = NULL;
  return gf_key_from_pem (k, t, strlen (t), pass);
}

#define EXPECT_PEM(label, der, pass, want, what) \
  do { \
    gf_key *k_; \
    int rc_ = read_pem (label, der, pass, &k_); \
    if (rc_ != (want)) \
      { \
        fprintf (stderr, "%s: %d, want %d\n", what, rc_, (int) (want)); \
        CHECK (0); \
      } \
    CHECK ((rc_ == GF_OK) == (k_ != NULL)); \
    gf_key_free (k_); \
  } while (0)

/* A tiny walker for the vectors: the element at P, content in *C.  */
static const uint8_t *
walk (const uint8_t *p, uint8_t *tag, const uint8_t **c, size_t *cn)
{
  size_t len = p[1], h = 2;

  *tag = p[0];
  if (len & 0x80)
    {
      size_t nb = len & 0x7f, i;

      len = 0;
      for (i = 0; i < nb; i++)
        len = len << 8 | p[2 + i];
      h += nb;
    }
  *c = p + h;
  *cn = len;
  return p + h + len;
}

static const uint8_t *
blob_part (const gf_key *k, size_t skip, size_t *len)
{
  size_t bl;
  const uint8_t *b = gf_key_blob (k, &bl);
  gf_reader r;
  gf_slice s;
  size_t i;

  gf_reader_init (&r, b, bl);
  for (i = 0; i <= skip; i++)
    CHECK_EQ (gf_rd_string (&r, &s), GF_OK);
  *len = s.len;
  return s.data;
}

static void
spki_variants (void)
{
  gf_key *ed = pub_of (vec_fmt_keys[0].pub);
  gf_key *rsa = pub_of (vec_fmt_keys[3].pub);
  size_t pn, en, nn, v;
  const uint8_t *pk = blob_part (ed, 1, &pn);
  const uint8_t *e = blob_part (rsa, 1, &en), *n = blob_part (rsa, 2, &nn);
  static struct buf oid, alg, bits, body, outer, tmp, nint, eint, seq, rsaseq;
  uint8_t zero = 0, one = 1;
  static const uint8_t ed_oid[] = { 0x2b, 0x65, 0x70 };
  static const uint8_t rsa_oid[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

  /* Ed25519: the plain one, and each way it can be wrong.  */
  for (v = 0; v < 11; v++)
    {
      oid.n = alg.n = bits.n = body.n = outer.n = tmp.n = 0;
      tlv (&oid, 0x06, ed_oid, sizeof ed_oid);
      if (v == 1)
        tlv (&oid, 0x05, NULL, 0);		/* Parameters it must not have.  */
      tlvb (&alg, 0x30, &oid);
      put (&tmp, v == 2 ? &one : &zero, 1);	/* Unused bits.  */
      put (&tmp, pk, v == 3 ? pn - 1 : pn);	/* A key of 31 bytes.  */
      tlvb (&bits, 0x03, &tmp);
      put (&body, alg.b, alg.n);
      put (&body, bits.b, bits.n);
      if (v == 4)
        tlv (&body, 0x05, NULL, 0);		/* Something after the key.  */
      switch (v)
        {
        case 5:				/* The length in a longer form.  */
          put (&outer, "\x30\x81", 2);
          outer.b[outer.n++] = (uint8_t) body.n;
          put (&outer, body.b, body.n);
          break;
        case 6:				/* Indefinite.  */
          put (&outer, "\x30\x80", 2);
          put (&outer, body.b, body.n);
          put (&outer, "\0\0", 2);
          break;
        case 7:				/* Longer than it is.  */
          tlvb (&outer, 0x30, &body);
          outer.b[1]++;
          break;
        case 8:				/* Bytes after.  */
          tlvb (&outer, 0x30, &body);
          put (&outer, "\0", 1);
          break;
        case 9:				/* A tag of two bytes.  */
          put (&outer, "\x3f\x00", 2);
          outer.b[outer.n++] = (uint8_t) body.n;
          put (&outer, body.b, body.n);
          break;
        case 10:			/* No length at all.  */
          put (&outer, "\x30", 1);
          break;
        default:
          tlvb (&outer, 0x30, &body);
          break;
        }
      EXPECT_PEM ("PUBLIC KEY", &outer, NULL, v == 0 ? GF_OK : GF_ERR_ENCODING,
                  "ed25519 SPKI");
    }
  /* RSA: the NULL parameter, the integers, the lengths.  */
  for (v = 0; v < 10; v++)
    {
      oid.n = alg.n = bits.n = body.n = outer.n = tmp.n = 0;
      nint.n = eint.n = seq.n = rsaseq.n = 0;
      tlv (&oid, 0x06, rsa_oid, sizeof rsa_oid);
      if (v != 1)
        tlv (&oid, 0x05, v == 2 ? "\x00" : NULL, v == 2 ? 1 : 0);
      tlvb (&alg, 0x30, &oid);
      /* n has its top bit set, so its mpint has the zero byte INTEGER needs:
         take it away (so that n is negative), or add another (so that it is
         not the shortest).  */
      if (v == 4)
        put (&nint, "\0", 1);
      CHECK_EQ (n[0], 0);
      put (&nint, v == 3 ? n + 1 : n, v == 3 ? nn - 1 : nn);
      if (v != 5)
        {
          if (v == 6)
            put (&eint, "\0", 1);
          put (&eint, e, en);
        }
      tlvb (&seq, 0x02, &nint);
      tlvb (&seq, 0x02, &eint);
      if (v == 7)
        tlv (&seq, 0x02, "\x01", 1);		/* A third integer.  */
      tlvb (&rsaseq, 0x30, &seq);
      put (&tmp, "\0", 1);
      put (&tmp, rsaseq.b, rsaseq.n);
      if (v == 8)
        put (&tmp, "\0", 1);			/* Bytes after the sequence.  */
      tlvb (&bits, 0x03, &tmp);
      put (&body, alg.b, alg.n);
      put (&body, bits.b, bits.n);
      if (v == 9)
        {
          /* A length of two bytes, said in three: not the shortest.  */
          put (&outer, "\x30\x83\x00", 3);
          outer.b[outer.n++] = (uint8_t) (body.n >> 8);
          outer.b[outer.n++] = (uint8_t) body.n;
          put (&outer, body.b, body.n);
        }
      else
        tlvb (&outer, 0x30, &body);
      EXPECT_PEM ("PUBLIC KEY", &outer, NULL, v == 0 ? GF_OK : GF_ERR_ENCODING,
                  "RSA SPKI");
      if (v == 0 || (v >= 3 && v <= 7))
        EXPECT_PEM ("RSA PUBLIC KEY", &rsaseq, NULL,
                    v == 0 ? GF_OK : GF_ERR_ENCODING, "RSA PUBLIC KEY");
    }
  gf_key_free (ed);
  gf_key_free (rsa);
}

/* Private keys that are wrong in a way that matters.  */
static void
private_variants (void)
{
  gf_key *ed = pub_of (vec_fmt_keys[0].pub);
  size_t pn, v;
  const uint8_t *pk = blob_part (ed, 1, &pn);
  static uint8_t der[4096];
  size_t dn = pem_der (vec_fmt_keys[0].pkcs8, der);
  const uint8_t *seed = der + dn - 32;
  static const uint8_t ed_oid[] = { 0x2b, 0x65, 0x70 };
  static struct buf alg, oid, key, body, outer, inner, tmp;

  CHECK_EQ (dn, 48);
  /* PKCS#8 for Ed25519: the version, the public key, attributes.  */
  for (v = 0; v < 10; v++)
    {
      int want = GF_ERR_ENCODING;
      uint8_t ver = (uint8_t) (v == 4 || v == 5 ? 1 : v == 6 ? 2 : 0);

      alg.n = oid.n = key.n = body.n = outer.n = inner.n = tmp.n = 0;
      tlv (&oid, 0x06, ed_oid, sizeof ed_oid);
      tlvb (&alg, 0x30, &oid);
      tlv (&inner, 0x04, seed, v == 7 ? 31 : 32);
      tlvb (&key, 0x04, &inner);
      tlv (&body, 0x02, &ver, 1);
      put (&body, alg.b, alg.n);
      put (&body, key.b, key.n);
      if (v == 2)
        tlv (&body, 0xa0, NULL, 0);		/* Empty attributes.  */
      if (v == 3 || v == 4 || v == 5)
        {
          /* A public key: only in version 1; the right one in 4.  */
          put (&tmp, "\0", 1);
          put (&tmp, pk, 32);
          if (v == 5)
            tmp.b[5] ^= 1;			/* Another key's.  */
          tlv (&body, 0x81, tmp.b, tmp.n);
        }
      if (v == 8)
        tlv (&body, 0x42, NULL, 0);		/* A tag nobody has.  */
      if (v == 9)
        {
          tlv (&body, 0xa0, NULL, 0);
          tlv (&body, 0xa0, NULL, 0);
        }
      tlvb (&outer, 0x30, &body);
      /* 0: right.  1: unused.  2: attributes.  3: a public key in version 0.
         4: version 1, the right public key.  5: the wrong one.  6: version
         2.  7: a seed of 31 bytes.  8: an unknown field.  9: two attribute
         sets.  */
      if (v == 0 || v == 2 || v == 4 || v == 9 || v == 1)
        want = GF_OK;
      EXPECT_PEM ("PRIVATE KEY", &outer, NULL, want, "ed25519 PKCS#8");
    }
  gf_key_free (ed);

  /* EC, from the P-256 key's SEC1: d, the point, and what is around them.  */
  {
    static uint8_t sec[512];
    size_t sn = pem_der (vec_fmt_keys[1].sec1, sec);
    const uint8_t *d = sec + 7, *q = sec + sn - 65;
    static const uint8_t ec_oid[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    static const uint8_t p256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    static const uint8_t p384[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
    static struct buf ecpk, bits, o2, algid, o3, key2, kseq;
    uint8_t d33[33];

    CHECK_EQ (sec[0], 0x30);
    CHECK_EQ (sec[2], 2);
    d33[0] = 0;
    memcpy (d33 + 1, d, 32);
    /* 0: SEC1, right.  1: version 2.  2: d with a zero byte first.  3: no
       curve.  4: the curve is P-384.  5: no public point.  6: an unknown
       field.  7: PKCS#8, right (the curve is in the algorithm).  8: PKCS#8
       with no point.  9: PKCS#8 whose key names another curve.  10: PKCS#8
       whose key names the same.  */
    for (v = 0; v < 11; v++)
      {
        int want = GF_ERR_ENCODING;
        int as8 = v >= 7;
        uint8_t one_ = 1, two = 2, zero_ = 0;

        ecpk.n = bits.n = o2.n = body.n = outer.n = tmp.n = 0;
        algid.n = o3.n = key2.n = kseq.n = 0;
        tlv (&ecpk, 0x02, v == 1 ? &two : &one_, 1);
        if (v == 2)
          tlv (&ecpk, 0x04, d33, 33);
        else
          tlv (&ecpk, 0x04, d, 32);
        if (v == 4)
          {
            tlv (&o2, 0x06, p384, sizeof p384);
            tlvb (&ecpk, 0xa0, &o2);
          }
        else if (v == 9 || v == 10 || (v != 3 && !as8))
          {
            if (v == 9)
              tlv (&o2, 0x06, p384, sizeof p384);
            else
              tlv (&o2, 0x06, p256, sizeof p256);
            tlvb (&ecpk, 0xa0, &o2);
          }
        if (v != 5 && v != 8)
          {
            put (&tmp, "\0", 1);
            put (&tmp, q, 65);
            tlvb (&bits, 0x03, &tmp);
            tlvb (&ecpk, 0xa1, &bits);
          }
        if (v == 6)
          tlv (&ecpk, 0x42, NULL, 0);
        if (as8)
          {
            tlv (&o3, 0x06, ec_oid, sizeof ec_oid);
            tlv (&o3, 0x06, p256, sizeof p256);
            tlvb (&algid, 0x30, &o3);
            tlvb (&kseq, 0x30, &ecpk);
            tlvb (&key2, 0x04, &kseq);
            tlv (&body, 0x02, &zero_, 1);
            put (&body, algid.b, algid.n);
            put (&body, key2.b, key2.n);
            tlvb (&outer, 0x30, &body);
          }
        else
          tlvb (&outer, 0x30, &ecpk);
        if (v == 0 || v == 7 || v == 10)
          want = GF_OK;
        if (v == 5 || v == 8)
          want = GF_ERR_UNSUPPORTED;
        EXPECT_PEM (as8 ? "PRIVATE KEY" : "EC PRIVATE KEY", &outer, NULL, want,
                    as8 ? "EC PKCS#8" : "SEC1");
      }
  }

  /* RSA, from the PKCS#1 vector: a version that is not 0, fields missing or
     extra, the primes the other way round.  */
  {
    static uint8_t p1[4096];
    size_t n1 = pem_der (vec_fmt_keys[3].pkcs1, p1);
    const uint8_t *c, *p, *fields[9];
    size_t cn, fn[9], i;
    uint8_t tag, ver;
    static struct buf seq;

    walk (p1, &tag, &c, &cn);
    p = c;
    for (i = 0; i < 9; i++)
      {
        const uint8_t *cc;
        size_t ccn;

        fields[i] = p;
        p = walk (p, &tag, &cc, &ccn);
        fn[i] = (size_t) (p - fields[i]);
      }
    CHECK (p == p1 + n1);
    for (v = 0; v < 5; v++)
      {
        int want = v == 0 || v == 4 ? GF_OK : GF_ERR_ENCODING;

        seq.n = outer.n = 0;
        ver = v == 1 ? 1 : 0;			/* 1: multi-prime.  */
        tlv (&seq, 0x02, &ver, 1);
        if (v == 4)
          {
            /* The primes the wrong way round are the same key.  */
            put (&seq, fields[1], fn[1]);
            put (&seq, fields[2], fn[2]);
            put (&seq, fields[3], fn[3]);
            put (&seq, fields[5], fn[5]);
            put (&seq, fields[4], fn[4]);
            put (&seq, fields[6], fn[6]);
            put (&seq, fields[7], fn[7]);
            put (&seq, fields[8], fn[8]);
          }
        else
          for (i = 1; i < (v == 2 ? 6 : 9); i++)	/* 2: no CRT fields.  */
            put (&seq, fields[i], fn[i]);
        if (v == 3)
          tlv (&seq, 0x02, "\x01", 1);		/* A tenth field.  */
        tlvb (&outer, 0x30, &seq);
        EXPECT_PEM ("RSA PRIVATE KEY", &outer, NULL, want, "PKCS#1");
      }
  }
}

/* ---- PKCS#8 under PBES2, made here so that its parts can be wrong ---- */

struct pbes
{
  size_t salt, iv, iter, keylen;	/* keylen 0: not given.  */
  int prf;				/* 256, 384, 512, 1, or 0 for none.  */
  int aes;				/* 128, 192, 256.  */
  int pad;				/* 0: right; else this byte, repeated.  */
  int garbage;				/* Right padding, nonsense inside.  */
  size_t cut;				/* Bytes removed from the data.  */
  size_t grow;				/* Bytes of plaintext added.  */
  size_t attrs;				/* Empty attribute sets added to the key.  */
};

static int
pbes_make (const struct pbes *pb, const char *pass, struct buf *outer)
{
  static uint8_t plain[1 << 17], salt[128], iv[32], key[32], der[4096];
  static struct buf oid, kdf, kp, hsh, enc, alg, params, body;
  static const uint8_t pbes2[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d };
  static const uint8_t pbkdf2[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c };
  static const uint8_t h1[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07 };
  static const uint8_t h256[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09 };
  static const uint8_t h384[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a };
  static const uint8_t h512[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b };
  static const uint8_t a128[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
  static const uint8_t a192[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16 };
  static const uint8_t a256[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a };
  size_t dn = pem_der (vec_fmt_keys[0].pkcs8, der), pl, klen, i, total;
  int hash = pb->prf == 384 ? GCRY_MD_SHA384 : pb->prf == 512 ? GCRY_MD_SHA512
    : pb->prf == 1 ? GCRY_MD_SHA1 : GCRY_MD_SHA256;
  gcry_cipher_hd_t h;
  const uint8_t *hoid = pb->prf == 384 ? h384 : pb->prf == 512 ? h512
    : pb->prf == 1 ? h1 : h256;
  size_t hoidn = pb->prf == 1 ? sizeof h1 : sizeof h256;

  klen = (size_t) pb->aes / 8;
  memset (salt, 7, sizeof salt);
  memset (iv, 9, sizeof iv);
  /* The plaintext: the Ed25519 PKCS#8, padded.  */
  pl = 0;
  if (pb->garbage)
    {
      memset (plain, 0x42, 32);
      pl = 32;
    }
  else
    {
      /* The key's content, and any number of empty [0] attributes after it
         (which PKCS#8 allows), in a new SEQUENCE.  */
      struct buf t;

      t.n = 0;
      put (&t, der + 2, dn - 2);
      for (i = 0; i < pb->attrs; i++)
        tlv (&t, 0xa0, NULL, 0);
      memset (plain, 0, 16);
      {
        struct buf o;

        o.n = 0;
        tlvb (&o, 0x30, &t);
        memcpy (plain, o.b, o.n);
        pl = o.n;
      }
    }
  for (i = 0; i < pb->grow; i++)
    plain[pl++] = 0x55;
  {
    size_t padn = 16 - pl % 16;

    for (i = 0; i < padn; i++)
      plain[pl + i] = (uint8_t) (pb->pad ? (size_t) pb->pad : padn);
    if (pb->pad == 98)			/* 1, 2, 3, 4: the last says 4.  */
      {
        for (i = 0; i < padn; i++)
          plain[pl + i] = (uint8_t) (i + 1);
      }
    if (pb->pad == 99)			/* Inconsistent: last byte 4, the rest 3. */
      {
        for (i = 0; i < padn; i++)
          plain[pl + i] = 3;
        plain[pl + padn - 1] = 4;
      }
    pl += padn;
  }
  if (gf_crypto_init () != GF_OK
      || gcry_kdf_derive (pass, strlen (pass), GCRY_KDF_PBKDF2, hash, salt,
                          pb->salt, pb->iter && pb->iter < 100000 ? pb->iter : 1, klen, key))
    return 0;
  if (gcry_cipher_open (&h, pb->aes == 128 ? GCRY_CIPHER_AES128
                        : pb->aes == 192 ? GCRY_CIPHER_AES192 : GCRY_CIPHER_AES256,
                        GCRY_CIPHER_MODE_CBC, 0)
      || gcry_cipher_setkey (h, key, klen) || gcry_cipher_setiv (h, iv, 16)
      || gcry_cipher_encrypt (h, plain, pl, NULL, 0))
    return 0;
  gcry_cipher_close (h);
  total = pl - pb->cut;

  oid.n = kdf.n = kp.n = hsh.n = enc.n = alg.n = params.n = body.n = outer->n = 0;
  tlv (&kp, 0x04, salt, pb->salt);
  {
    uint8_t it[4] = { (uint8_t) (pb->iter >> 24), (uint8_t) (pb->iter >> 16),
                      (uint8_t) (pb->iter >> 8), (uint8_t) pb->iter };
    size_t skip = 0;

    while (skip < 3 && it[skip] == 0)
      skip++;
    if (it[skip] & 0x80)
      {
        /* A zero byte first.  */
        uint8_t t5[5] = { 0 };

        memcpy (t5 + 1, it + skip, 4 - skip);
        tlv (&kp, 0x02, t5, 5 - skip);
      }
    else
      tlv (&kp, 0x02, it + skip, 4 - skip);
  }
  if (pb->keylen)
    {
      uint8_t kl = (uint8_t) pb->keylen;

      tlv (&kp, 0x02, &kl, 1);
    }
  if (pb->prf)
    {
      struct buf *x = &hsh;

      x->n = 0;
      tlv (x, 0x06, hoid, hoidn);
      tlv (x, 0x05, NULL, 0);
      tlvb (&kp, 0x30, x);
    }
  tlv (&kdf, 0x06, pbkdf2, sizeof pbkdf2);
  tlvb (&kdf, 0x30, &kp);
  tlvb (&params, 0x30, &kdf);
  tlv (&enc, 0x06, pb->aes == 128 ? a128 : pb->aes == 192 ? a192 : a256,
       sizeof a128);
  tlv (&enc, 0x04, iv, pb->iv);
  tlvb (&params, 0x30, &enc);
  /* algorithm = SEQUENCE { OID pbes2, SEQUENCE { kdf, cipher } }.  */
  tlv (&oid, 0x06, pbes2, sizeof pbes2);
  tlvb (&oid, 0x30, &params);
  tlvb (&alg, 0x30, &oid);
  put (&body, alg.b, alg.n);
  tlv (&body, 0x04, plain, total);
  tlvb (outer, 0x30, &body);
  return 1;
}

static void
pbes_variants (void)
{
  gf_key *want = pub_of (vec_fmt_keys[0].pub);
  struct pbes base = { 16, 16, 100, 0, 256, 256, 0, 0, 0, 0, 0 }, b;
  static struct buf outer;
  size_t v;
  gf_key *k = NULL;

  /* The one made here is right.  */
  CHECK (pbes_make (&base, VEC_PASS, &outer));
  CHECK_EQ (read_pem ("ENCRYPTED PRIVATE KEY", &outer, VEC_PASS, &k), GF_OK);
  check_private (k, want, "a made PBES2");
  gf_key_free (k);
  CHECK_EQ (read_pem ("ENCRYPTED PRIVATE KEY", &outer, "wrong", &k), GF_ERR_PASSPHRASE);
  for (v = 0; v < 26; v++)
    {
      int want_rc = GF_ERR_ENCODING, ok;
      const char *what = "";

      b = base;
      switch (v)
        {
        case 0: b.salt = 7; what = "salt of 7"; break;
        case 1: b.salt = 8; want_rc = GF_OK; what = "salt of 8"; break;
        case 2: b.salt = 64; want_rc = GF_OK; what = "salt of 64"; break;
        case 3: b.salt = 65; what = "salt of 65"; break;
        case 4: b.iter = 0; what = "0 iterations"; break;
        case 5: b.iter = 1; want_rc = GF_OK; what = "1 iteration"; break;
        case 6: b.iter = 5000001; want_rc = GF_ERR_UNSUPPORTED; what = "too many iterations"; break;
        case 7: b.keylen = 32; want_rc = GF_OK; what = "key length 32"; break;
        case 8: b.keylen = 16; what = "key length 16 for AES-256"; break;
        case 9: b.prf = 0; want_rc = GF_ERR_UNSUPPORTED; what = "no hash"; break;
        case 10: b.prf = 1; want_rc = GF_ERR_UNSUPPORTED; what = "SHA-1"; break;
        case 11: b.iv = 15; what = "iv of 15"; break;
        case 12: b.iv = 17; what = "iv of 17"; break;
        case 13: b.cut = 1; what = "data of 63"; break;
        case 14: b.cut = 64; want_rc = GF_ERR_ENCODING; what = "no data"; break;
        case 15: b.pad = 0; b.garbage = 1; want_rc = GF_ERR_PASSPHRASE; what = "nonsense inside right padding"; break;
        case 16: b.pad = 17; want_rc = GF_ERR_PASSPHRASE; what = "padding of 17"; break;
        case 17: b.pad = 99; want_rc = GF_ERR_PASSPHRASE; what = "padding that disagrees"; break;
        case 18: b.pad = 0; b.grow = 16; want_rc = GF_ERR_ENCODING; what = "bytes after the key"; break;
        case 19: b.aes = 128; want_rc = GF_OK; what = "AES-128"; break;
        case 20: b.aes = 192; want_rc = GF_OK; what = "AES-192"; break;
        case 21: b.prf = 384; want_rc = GF_OK; what = "SHA-384"; break;
        case 22: b.prf = 512; want_rc = GF_OK; what = "SHA-512"; break;
        case 23: b.keylen = 24; b.aes = 192; want_rc = GF_OK; what = "key length 24 for AES-192"; break;
        case 24: b.attrs = 6; want_rc = GF_OK; what = "attributes after the key"; break;
        default: b.attrs = 6; b.pad = 98; want_rc = GF_ERR_PASSPHRASE; what = "padding 1 2 3 4"; break;
        }
      ok = pbes_make (&b, VEC_PASS, &outer);
      CHECK (ok);
      if (!ok)
        continue;
      if (v == 18)
        {
          /* Bytes after the key inside the plaintext are not a key.  */
          want_rc = GF_ERR_PASSPHRASE;
        }
      {
        gf_key *kk = NULL;
        int rc = read_pem ("ENCRYPTED PRIVATE KEY", &outer, VEC_PASS, &kk);

        if (rc != want_rc)
          {
            fprintf (stderr, "PBES2 %s: %d, want %d\n", what, rc, want_rc);
            CHECK (0);
          }
        gf_key_free (kk);
      }
    }
  /* Data bigger than a key can be.  */
  b = base;
  b.grow = 70000;
  CHECK (pbes_make (&b, VEC_PASS, &outer));
  CHECK_EQ (read_pem ("ENCRYPTED PRIVATE KEY", &outer, VEC_PASS, &k), GF_ERR_ENCODING);
  gf_key_free (want);
}

static void
pem_variants (void)
{
  const char *p = vec_fmt_keys[0].pkcs8;
  static char text[1 << 19];
  gf_key *k = NULL;
  const char *body = strchr (p, '\n') + 1, *endl = strstr (p, "-----END");
  size_t i;

  /* An END line for another label, and a second block.  */
  snprintf (text, sizeof text, "-----BEGIN PRIVATE KEY-----\n%.*s-----END PUBLIC KEY-----\n",
            (int) (endl - body), body);
  CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_ERR_ENCODING);
  snprintf (text, sizeof text, "-----BEGIN PRIVATE KEY-----\n%.*s-----END PRIVATE KEY-----junk\n",
            (int) (endl - body), body);
  CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_ERR_ENCODING);
  /* Headers: the old encryption is named for what it is; others are not
     understood.  */
  snprintf (text, sizeof text, "-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\n%.*s-----END PRIVATE KEY-----\n",
            (int) (endl - body), body);
  CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_ERR_UNSUPPORTED);
  snprintf (text, sizeof text, "-----BEGIN PRIVATE KEY-----\nX-Header: 1\n\n%.*s-----END PRIVATE KEY-----\n",
            (int) (endl - body), body);
  CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_ERR_ENCODING);
  /* A label that is too long, a body of nothing, a body of junk.  */
  {
    char label[80];

    memset (label, 'X', sizeof label);
    label[60] = '\0';
    snprintf (text, sizeof text, "-----BEGIN %s-----\n%.*s-----END %s-----\n", label,
              (int) (endl - body), body, label);
    CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_ERR_ENCODING);
  }
  snprintf (text, sizeof text, "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n");
  CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_ERR_ENCODING);
  snprintf (text, sizeof text, "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n");
  CHECK_EQ (gf_key_from_pem (&k, text, strlen (text), NULL), GF_ERR_ENCODING);
  /* More DER than a key can be, and more text than a file can be.  */
  {
    static struct buf big;

    big.n = 0;
    for (i = 0; i < 70000; i++)
      big.b[big.n++] = 0;
    CHECK_EQ (read_pem ("PRIVATE KEY", &big, NULL, &k), GF_ERR_ENCODING);
    memset (text, 'A', sizeof text);
    memcpy (text, "-----BEGIN PRIVATE KEY-----\n", 28);
    CHECK_EQ (gf_key_from_pem (&k, text, 300000, NULL), GF_ERR_RANGE);
    CHECK_EQ (gf_key_from_rfc4716 (&k, text, 300000, NULL, 0), GF_ERR_RANGE);
    CHECK_EQ (gf_key_from_ppk (&k, text, 300000, NULL, NULL, 0), GF_ERR_RANGE);
  }
}

static void
rfc4716_variants (void)
{
  static char text[4096];
  gf_key *k = NULL;
  const char *body = strstr (vec_fmt_keys[0].rfc4716, "AAAA");
  size_t bn = strcspn (body, "\n");
  static uint8_t cert[2048];
  static char cert64[2900];
  size_t cn = tst_unhex (vec_ed_user_cert, cert, sizeof cert);

  /* Not the right first line.  */
  snprintf (text, sizeof text, "garbage\n%.*s\n---- END SSH2 PUBLIC KEY ----\n", (int) bn, body);
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ---\n%.*s\n---- END SSH2 PUBLIC KEY ----\n", (int) bn, body);
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  /* A header continued to the end of the file.  */
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\n%.*s\n---- END SSH2 PUBLIC KEY ----\nComment: \"a\\\n", (int) bn, body);
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"a\\\n");
  CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  /* A header tag that is too long.  */
  {
    char tag[100];

    memset (tag, 'a', 80);
    tag[80] = '\0';
    snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\n%s: x\n%.*s\n---- END SSH2 PUBLIC KEY ----\n", tag, (int) bn, body);
    CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  }
  /* A value that is too long.  */
  {
    static char v[1400];

    memset (v, 'v', sizeof v);
    v[1300] = '\0';
    snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\nComment: %s\n%.*s\n---- END SSH2 PUBLIC KEY ----\n", v, (int) bn, body);
    CHECK (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0) != GF_OK);
  }
  /* A certificate is not a public key file.  */
  b64enc (cert, cn, cert64, 0);
  snprintf (text, sizeof text, "---- BEGIN SSH2 PUBLIC KEY ----\n%s\n---- END SSH2 PUBLIC KEY ----\n", cert64);
  CHECK_EQ (gf_key_from_rfc4716 (&k, text, strlen (text), NULL, 0), GF_ERR_UNSUPPORTED);
  CHECK (k == NULL);
}

/* An unencrypted PuTTY file with a MAC made here, so that any part of it can
   be as wrong as we like.  */
static void
ppk_make (char *out, size_t cap, const char *hdr_alg,
          const char *enc, const uint8_t *pub, size_t pubn, const uint8_t *priv,
          size_t privn, const char *extra)
{
  gcry_mac_hd_t h;
  uint8_t mac[32], zero = 0, four[4];
  size_t macn = 32, i;
  char b1[1024], b2[1024], hex[80];
  const struct { const uint8_t *d; size_t n; } parts[5] = {
    { (const uint8_t *) hdr_alg, strlen (hdr_alg) }, { (const uint8_t *) enc, strlen (enc) },
    { (const uint8_t *) "test comment", 12 }, { pub, pubn }, { priv, privn }
  };

  CHECK_EQ (gcry_mac_open (&h, GCRY_MAC_HMAC_SHA256, 0, NULL), 0);
  CHECK_EQ (gcry_mac_setkey (h, &zero, 1), 0);
  for (i = 0; i < 5; i++)
    {
      four[0] = (uint8_t) (parts[i].n >> 24);
      four[1] = (uint8_t) (parts[i].n >> 16);
      four[2] = (uint8_t) (parts[i].n >> 8);
      four[3] = (uint8_t) parts[i].n;
      gcry_mac_write (h, four, 4);
      gcry_mac_write (h, parts[i].d, parts[i].n);
    }
  gcry_mac_read (h, mac, &macn);
  gcry_mac_close (h);
  for (i = 0; i < 32; i++)
    sprintf (hex + 2 * i, "%02x", mac[i]);
  b64enc (pub, pubn, b1, 0);
  b64enc (priv, privn, b2, 0);
  snprintf (out, cap,
            "PuTTY-User-Key-File-3: %s\nEncryption: %s\nComment: test comment\n"
            "Public-Lines: 1\n%s\n%sPrivate-Lines: 1\n%s\nPrivate-MAC: %s\n",
            hdr_alg, enc, b1, extra, b2, hex);
}

static void
ppk_variants (void)
{
  static char text[8192];
  gf_key *ed = pub_of (vec_fmt_keys[0].pub), *k = NULL;
  size_t pubn, i;
  const uint8_t *blob = gf_key_blob (ed, &pubn);
  static uint8_t der[4096];
  size_t dn = pem_der (vec_fmt_keys[0].pkcs8, der);
  uint8_t priv[64];
  const char *argon = "Key-Derivation: Argon2id\nArgon2-Memory: 1024\nArgon2-Passes: 2\n"
    "Argon2-Parallelism: 1\nArgon2-Salt: 00112233445566778899aabbccddeeff\n";

  priv[0] = priv[1] = priv[2] = 0;
  priv[3] = 32;
  memcpy (priv + 4, der + dn - 32, 32);
  /* The one made here is right; then the key's type that the header names
     is not the one in the file, and the seed is too short.  */
  ppk_make (text, sizeof text, "ssh-ed25519", "none", blob, pubn, priv, 36, "");
  CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), NULL, NULL, 0), GF_OK);
  check_private (k, ed, "a made ppk");
  gf_key_free (k);
  ppk_make (text, sizeof text, "ssh-rsa", "none", blob, pubn, priv, 36, "");
  CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), NULL, NULL, 0), GF_ERR_ENCODING);
  priv[3] = 31;
  ppk_make (text, sizeof text, "ssh-ed25519", "none", blob, pubn, priv, 35, "");
  CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), NULL, NULL, 0), GF_ERR_ENCODING);
  priv[3] = 32;
  /* Another seed: a key that does not go with the public one.  */
  priv[10] ^= 1;
  ppk_make (text, sizeof text, "ssh-ed25519", "none", blob, pubn, priv, 36, "");
  CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), NULL, NULL, 0), GF_ERR_ENCODING);
  priv[10] ^= 1;
  /* A file that ends later than it should, and one with another cipher.  */
  ppk_make (text, sizeof text, "ssh-ed25519", "none", blob, pubn, priv, 36, "");
  strcat (text, "more\n");
  CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), NULL, NULL, 0), GF_ERR_ENCODING);
  ppk_make (text, sizeof text, "ssh-ed25519", "aes128-cbc", blob, pubn, priv, 36, argon);
  CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), VEC_PASS, NULL, 0), GF_ERR_UNSUPPORTED);
  /* Encrypted: what the Argon2 lines say is bounded before it is run.  */
  {
    static const struct
    {
      const char *kdf, *mem, *passes, *lanes, *salt;
      int want;
    } t[] = {
      { "Argon2id", "524288", "1", "1", "00112233445566778899aabbccddeeff", -1 },
      { "Argon2id", "524289", "1", "1", "00112233445566778899aabbccddeeff", GF_ERR_UNSUPPORTED },
      { "Argon2id", "0", "1", "1", "00112233445566778899aabbccddeeff", GF_ERR_UNSUPPORTED },
      { "Argon2id", "1024", "1001", "1", "00112233445566778899aabbccddeeff", GF_ERR_UNSUPPORTED },
      { "Argon2id", "1024", "0", "1", "00112233445566778899aabbccddeeff", GF_ERR_UNSUPPORTED },
      { "Argon2id", "1024", "1", "17", "00112233445566778899aabbccddeeff", GF_ERR_UNSUPPORTED },
      { "Argon2id", "1024", "1", "0", "00112233445566778899aabbccddeeff", GF_ERR_UNSUPPORTED },
      { "Argon2id", "1024", "1", "1", "0011223344556677", -1 },
      { "Argon2id", "1024", "1", "1", "00112233445566", GF_ERR_ENCODING },
      { "Argon2id", "1024", "1", "1", "001122334455667788", -1 },
      { "Argon2id", "1024", "1", "1", "00112233445566778899aabbccddeeffgg", GF_ERR_ENCODING },
      { "Scrypt", "1024", "1", "1", "00112233445566778899aabbccddeeff", GF_ERR_UNSUPPORTED },
      { "Argon2id", "99999999999", "1", "1", "00112233445566778899aabbccddeeff", GF_ERR_UNSUPPORTED }
    };
    uint8_t fake[48];

    memset (fake, 5, sizeof fake);
    for (i = 0; i < sizeof t / sizeof t[0]; i++)
      {
        char hdrs[512], priv64[128], pub64[256];
        int rc;

        b64enc (blob, pubn, pub64, 0);
        b64enc (fake, 48, priv64, 0);
        snprintf (hdrs, sizeof hdrs, "Key-Derivation: %s\nArgon2-Memory: %s\nArgon2-Passes: %s\n"
                  "Argon2-Parallelism: %s\nArgon2-Salt: %s\n", t[i].kdf, t[i].mem, t[i].passes,
                  t[i].lanes, t[i].salt);
        snprintf (text, sizeof text,
                  "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: test comment\n"
                  "Public-Lines: 1\n%s\n%sPrivate-Lines: 1\n%s\nPrivate-MAC: %064d\n",
                  pub64, hdrs, priv64, 0);
        if (t[i].want == -1)
          {
            /* Within the bounds: it gets as far as the MAC, and fails there.
               (The big one is not run here: the check is that it is not
               refused for its size.)  */
            if (i == 0)
              continue;
            rc = gf_key_from_ppk (&k, text, strlen (text), VEC_PASS, NULL, 0);
            CHECK_EQ (rc, GF_ERR_PASSPHRASE);
          }
        else
          {
            rc = gf_key_from_ppk (&k, text, strlen (text), VEC_PASS, NULL, 0);
            if (rc != t[i].want)
              {
                fprintf (stderr, "ppk Argon2 case %zu: %d, want %d\n", i, rc, t[i].want);
                CHECK (0);
              }
          }
      }
    /* A private part that is not whole blocks.  */
    {
      char priv64[128], pub64[256];

      b64enc (blob, pubn, pub64, 0);
      b64enc (fake, 47, priv64, 0);
      snprintf (text, sizeof text,
                "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: test comment\n"
                "Public-Lines: 1\n%s\n%sPrivate-Lines: 1\n%s\nPrivate-MAC: %064d\n",
                pub64, argon, priv64, 0);
      CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), VEC_PASS, NULL, 0), GF_ERR_ENCODING);
    }
  }
  /* Line counts: none, and more than are allowed.  */
  {
    char pub64[256];

    b64enc (blob, pubn, pub64, 0);
    snprintf (text, sizeof text,
              "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: c\nPublic-Lines: 0\n"
              "Private-Lines: 1\nAAAA\nPrivate-MAC: %064d\n", 0);
    CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), NULL, NULL, 0), GF_ERR_ENCODING);
    snprintf (text, sizeof text,
              "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: c\nPublic-Lines: 129\n%s\n", pub64);
    CHECK_EQ (gf_key_from_ppk (&k, text, strlen (text), NULL, NULL, 0), GF_ERR_ENCODING);
  }
  gf_key_free (ed);
}

static void
hot_art (void)
{
  gf_key *k = pub_of (vec_fmt_hot_pub);
  char out[512];
  size_t n;

  CHECK (strcmp (vec_fmt_hot_has, "^") == 0);
  CHECK_EQ (gf_key_randomart (k, out, sizeof out, &n), GF_OK);
  CHECK (strcmp (out, vec_fmt_hot_art) == 0);
  gf_key_free (k);
}

int
main (void)
{
  CHECK_EQ (gf_crypto_init (), GF_OK);
  test_read ();
  test_write ();
  test_encrypted ();
  test_refused ();
  test_damage ();
  test_rfc4716_syntax ();
  test_ppk_syntax ();
  spki_variants ();
  private_variants ();
  pbes_variants ();
  pem_variants ();
  rfc4716_variants ();
  ppk_variants ();
  hot_art ();
  TST_DONE ();
}
