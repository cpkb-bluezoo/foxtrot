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

#include <stdio.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>
#include <foxtrot/knownhosts.h>

#include "tst-util.h"
#include "vectors-knownhosts.h"

#define NOW 1700000000u

static gf_key *
key_of (const char *text)
{
  gf_key *k = NULL;

  CHECK_EQ (gf_key_from_text (&k, text, strlen (text), NULL), GF_OK);
  return k;
}

static gf_knownhosts *
table (const char *text, size_t *bad)
{
  gf_knownhosts *kh = NULL;

  CHECK_EQ (gf_knownhosts_new (&kh), GF_OK);
  CHECK_EQ (gf_knownhosts_load (kh, text, strlen (text), bad), GF_OK);
  return kh;
}

static const char *
name_of (enum gf_hostcheck r)
{
  static const char *const n[] = { "UNKNOWN", "MATCH", "CHANGED", "REVOKED" };

  return n[r];
}

#define EXPECT(kh, host, port, key, want, now) \
  do { \
    enum gf_hostcheck r_ = gf_knownhosts_check (kh, host, port, key, now); \
    if (r_ != (want)) \
      { \
        fprintf (stderr, "%s:%d: %s:%u: %s, want %s\n", __FILE__, __LINE__, \
                 host, (unsigned) (port), name_of (r_), name_of (want)); \
        CHECK (0); \
      } \
  } while (0)

/* Which lines apply to which names, against what ssh-keygen -F says. */
static void
test_names (void)
{
  gf_knownhosts *kh;
  gf_key *k[3];
  static const char tag[] = "epr";
  size_t bad = 0, q, t;

  kh = table (vec_kh_file, &bad);
  CHECK_EQ (bad, 8);
  k[0] = key_of (vec_kh_e);
  k[1] = key_of (vec_kh_p);
  k[2] = key_of (vec_kh_r);
  for (q = 0; q < sizeof vec_kh_queries / sizeof vec_kh_queries[0]; q++)
    {
      const struct vec_kh_query *v = &vec_kh_queries[q];
      /* '?' is a line OpenSSH reads and we refuse: a key we will not have
         (ssh-dss), or a line that is not one.  */
      int refused = strchr (v->tags, '?') != NULL;
      int anything = 0;

      for (t = 0; t < 3; t++)
        if (strchr (v->tags, tag[t]))
          anything = 1;
      /* The one name under the CA line: known, by a CA.  */
      if (strcmp (v->host, "host.ca.example.net") == 0)
        anything = 1;
      for (t = 0; t < 3; t++)
        {
          enum gf_hostcheck want = refused ? GF_HOST_UNKNOWN
            : strchr (v->tags, tag[t]) ? GF_HOST_MATCH
            : anything ? GF_HOST_CHANGED : GF_HOST_UNKNOWN;

          if (gf_knownhosts_check (kh, v->host, v->port, k[t], NOW) != want)
            {
              fprintf (stderr, "%s:%u key %c: %s, want %s (ssh-keygen: \"%s\")\n",
                       v->host, v->port, tag[t],
                       name_of (gf_knownhosts_check (kh, v->host, v->port, k[t], NOW)),
                       name_of (want), v->tags);
              CHECK (0);
            }
        }
    }
  /* Port 0 is 22; a hashed name is found whatever the case of the query,
     as ssh lowers it first.  */
  EXPECT (kh, "example.org", 0, k[0], GF_HOST_MATCH, NOW);
  EXPECT (kh, "HASHED.example.org", 22, k[0], GF_HOST_MATCH, NOW);
  EXPECT (kh, "HASHED.example.org", 0, k[1], GF_HOST_CHANGED, NOW);
  /* Not host names at all.  */
  EXPECT (kh, "", 22, k[0], GF_HOST_UNKNOWN, NOW);
  EXPECT (kh, "example.org ", 22, k[0], GF_HOST_UNKNOWN, NOW);
  EXPECT (kh, "example.org,www.example.org", 22, k[0], GF_HOST_UNKNOWN, NOW);
  EXPECT (kh, "|1|abc|def", 22, k[0], GF_HOST_UNKNOWN, NOW);
  CHECK_EQ (gf_knownhosts_check (kh, NULL, 22, k[0], NOW), GF_HOST_UNKNOWN);
  {
    char big[400];

    memset (big, 'a', sizeof big);
    big[sizeof big - 1] = 0;
    EXPECT (kh, big, 22, k[0], GF_HOST_UNKNOWN, NOW);
  }
  EXPECT (NULL, "example.org", 22, k[0], GF_HOST_UNKNOWN, NOW);
  for (t = 0; t < 3; t++)
    gf_key_free (k[t]);
  gf_knownhosts_free (kh);
}

/* Revocation outranks a match, for a key and for the CA of a certificate. */
static void
test_revoked (void)
{
  gf_knownhosts *kh = table (vec_kh_file, NULL);
  gf_key *rev = key_of (vec_kh_rev), *c = key_of (vec_kh_cert_rev);
  gf_key *e = key_of (vec_kh_e);
  char text[512];

  EXPECT (kh, "anywhere.example.net", 22, rev, GF_HOST_REVOKED, NOW);
  EXPECT (kh, "anywhere.example.net", 2222, rev, GF_HOST_REVOKED, NOW);
  EXPECT (kh, "host.ca.example.net", 22, c, GF_HOST_REVOKED, NOW);
  EXPECT (kh, "example.org", 22, e, GF_HOST_MATCH, NOW);
  gf_knownhosts_free (kh);
  /* Even where a line names it, and when what is revoked is the CA. */
  snprintf (text, sizeof text, "example.org %s\n@revoked example.org %s\n",
            vec_kh_rev, vec_kh_rev);
  kh = table (text, NULL);
  EXPECT (kh, "example.org", 22, rev, GF_HOST_REVOKED, NOW);
  gf_knownhosts_free (kh);
  snprintf (text, sizeof text, "@cert-authority *.net %s\n@revoked *.net %s\n",
            vec_kh_ca, vec_kh_ca);
  kh = table (text, NULL);
  {
    gf_key *g = key_of (vec_kh_cert_good);

    EXPECT (kh, "host.ca.example.net", 22, g, GF_HOST_REVOKED, NOW);
    gf_key_free (g);
  }
  gf_knownhosts_free (kh);
  /* Revoked for some names only.  */
  snprintf (text, sizeof text, "@revoked other.example.org %s\n", vec_kh_e);
  kh = table (text, NULL);
  EXPECT (kh, "other.example.org", 22, e, GF_HOST_REVOKED, NOW);
  EXPECT (kh, "fine.example.org", 22, e, GF_HOST_UNKNOWN, NOW);
  gf_knownhosts_free (kh);
  gf_key_free (rev);
  gf_key_free (c);
  gf_key_free (e);
}

/* Host certificates through @cert-authority. */
static void
test_certificates (void)
{
  gf_knownhosts *kh = table (vec_kh_file, NULL);
  gf_key *good = key_of (vec_kh_cert_good), *noname = key_of (vec_kh_cert_noname);
  gf_key *expired = key_of (vec_kh_cert_expired), *ca2 = key_of (vec_kh_cert_ca2);
  gf_key *other = key_of (vec_kh_cert_other), *e = key_of (vec_kh_e);

  /* The CA's pattern covers *.ca.example.net; the certificate names two
     hosts, one by a wildcard.  */
  EXPECT (kh, "host.ca.example.net", 22, good, GF_HOST_MATCH, NOW);
  EXPECT (kh, "HOST.CA.EXAMPLE.NET", 0, good, GF_HOST_MATCH, NOW);
  /* Under the CA's pattern but not a name in the certificate; a name the
     certificate has but the CA's pattern does not cover.  */
  EXPECT (kh, "host2.ca.example.net", 22, good, GF_HOST_CHANGED, NOW);
  EXPECT (kh, "x.dept.ca.example.net", 22, good, GF_HOST_MATCH, NOW);
  EXPECT (kh, "x.dept.example.net", 22, good, GF_HOST_UNKNOWN, NOW);
  EXPECT (kh, "host.ca.example.net", 2222, good, GF_HOST_UNKNOWN, NOW);
  /* The wrong name inside, the wrong CA, out of date; in date.  */
  EXPECT (kh, "host.ca.example.net", 22, noname, GF_HOST_CHANGED, NOW);
  EXPECT (kh, "host.ca.example.net", 22, ca2, GF_HOST_CHANGED, NOW);
  EXPECT (kh, "host.ca.example.net", 22, expired, GF_HOST_CHANGED, NOW);
  EXPECT (kh, "host.ca.example.net", 22, expired, GF_HOST_MATCH, 1290000000);
  EXPECT (kh, "host.ca.example.net", 22, good, GF_HOST_CHANGED, 1500000000);
  /* The plain key of a certificate that is itself on a line for the host. */
  EXPECT (kh, "example.org", 22, good, GF_HOST_MATCH, NOW);
  EXPECT (kh, "example.org", 22, noname, GF_HOST_MATCH, NOW);
  EXPECT (kh, "example.org", 22, other, GF_HOST_CHANGED, NOW);
  /* A plain key where the host is known by its CA.  */
  EXPECT (kh, "host.ca.example.net", 22, e, GF_HOST_CHANGED, NOW);
  gf_knownhosts_free (kh);

  /* A CA for a host is a CA only for what its pattern covers; and a CA
     line is not a line for the CA's own key.  */
  kh = table ("@cert-authority *.net " "ssh-ed25519 AAAA\n", NULL);
  EXPECT (kh, "host.ca.example.net", 22, good, GF_HOST_UNKNOWN, NOW);
  gf_knownhosts_free (kh);
  {
    char text[512];
    gf_key *ca = key_of (vec_kh_ca);

    snprintf (text, sizeof text, "@cert-authority host.ca.example.net %s\n", vec_kh_ca);
    kh = table (text, NULL);
    EXPECT (kh, "host.ca.example.net", 22, ca, GF_HOST_CHANGED, NOW);
    EXPECT (kh, "host.ca.example.net", 22, good, GF_HOST_MATCH, NOW);
    gf_knownhosts_free (kh);
    gf_key_free (ca);
  }
  gf_key_free (good);
  gf_key_free (noname);
  gf_key_free (expired);
  gf_key_free (ca2);
  gf_key_free (other);
  gf_key_free (e);
}

static void
test_sigalgs (void)
{
  gf_knownhosts *kh = table (vec_kh_file, NULL);
  enum gf_sigalg a[16];
  size_t n, nd;

  /* Known by an Ed25519 key only: that and nothing else.  */
  n = gf_knownhosts_sigalgs (kh, "example.org", 22, a, 16);
  CHECK_EQ (n, 1);
  CHECK_EQ (a[0], GF_SIG_ED25519);
  n = gf_knownhosts_sigalgs (kh, "a.corp.example.com", 22, a, 16);
  CHECK_EQ (n, 1);
  CHECK_EQ (a[0], GF_SIG_ECDSA_NISTP256);
  n = gf_knownhosts_sigalgs (kh, "bastion.example.org", 2222, a, 16);
  CHECK_EQ (n, 2);
  CHECK (a[0] == GF_SIG_RSA_SHA2_512 && a[1] == GF_SIG_RSA_SHA2_256);
  /* Known by a CA: the certificate algorithms.  */
  n = gf_knownhosts_sigalgs (kh, "host.ca.example.net", 22, a, 16);
  CHECK_EQ (n, 5);
  CHECK (gf_sigalg_is_cert (a[0]) && gf_sigalg_is_cert (a[4]));
  /* Unknown: the whole list; the revoked line does not make a host known.  */
  (void) gf_policy_default_sigalgs (&nd);
  n = gf_knownhosts_sigalgs (kh, "who.example.net", 22, a, 16);
  CHECK_EQ (n, nd);
  n = gf_knownhosts_sigalgs (kh, "who.example.net", 22, a, 3);
  CHECK_EQ (n, 3);
  n = gf_knownhosts_sigalgs (NULL, "who.example.net", 22, a, 16);
  CHECK_EQ (n, nd);
  gf_knownhosts_free (kh);
  /* Both a key and a CA. */
  {
    char text[512];

    snprintf (text, sizeof text, "h.example.net %s\n@cert-authority h.example.net %s\n",
              vec_kh_p, vec_kh_ca);
    kh = table (text, NULL);
    n = gf_knownhosts_sigalgs (kh, "h.example.net", 22, a, 16);
    CHECK_EQ (n, 6);
    CHECK_EQ (a[0], GF_SIG_ECDSA_NISTP256);
    gf_knownhosts_free (kh);
  }
}

/* Adding and writing lines; and parsing what was written. */
static void
test_format (void)
{
  gf_knownhosts *kh = table ("", NULL), *back;
  gf_key *e = key_of (vec_kh_e), *p = key_of (vec_kh_p), *c = key_of (vec_kh_cert_good);
  char line[1024];
  size_t n;
  int hash;

  CHECK_EQ (gf_knownhosts_add (kh, "New.Example.Org", 0, e), GF_OK);
  CHECK_EQ (gf_knownhosts_add (kh, "new.example.org", 2022, p), GF_OK);
  EXPECT (kh, "new.example.org", 22, e, GF_HOST_MATCH, NOW);
  EXPECT (kh, "new.example.org", 22, p, GF_HOST_CHANGED, NOW);
  EXPECT (kh, "new.example.org", 2022, p, GF_HOST_MATCH, NOW);
  EXPECT (kh, "new.example.org", 2022, e, GF_HOST_CHANGED, NOW);
  CHECK_EQ (gf_knownhosts_add (kh, "x.example.org", 22, c), GF_ERR_INVAL);
  CHECK_EQ (gf_knownhosts_add (kh, "", 22, e), GF_ERR_INVAL);
  CHECK_EQ (gf_knownhosts_add (kh, "a,b", 22, e), GF_ERR_INVAL);
  gf_knownhosts_free (kh);

  for (hash = 0; hash < 2; hash++)
    {
      CHECK_EQ (gf_knownhosts_format (line, sizeof line, &n, "Fmt.Example.Org",
                                      22, e, hash), GF_OK);
      CHECK (n == strlen (line) && line[n - 1] == '\n');
      CHECK ((line[0] == '|') == hash);
      if (!hash)
        CHECK (strncmp (line, "fmt.example.org ssh-ed25519 AAAA", 32) == 0);
      back = table (line, &n);
      CHECK_EQ (n, 0);
      EXPECT (back, "fmt.example.org", 22, e, GF_HOST_MATCH, NOW);
      EXPECT (back, "fmt.example.org", 22, p, GF_HOST_CHANGED, NOW);
      EXPECT (back, "Fmt.Example.Org", 0, e, GF_HOST_MATCH, NOW);
      EXPECT (back, "other.example.org", 22, e, GF_HOST_UNKNOWN, NOW);
      EXPECT (back, "fmt.example.org", 2222, e, GF_HOST_UNKNOWN, NOW);
      gf_knownhosts_free (back);
      CHECK_EQ (gf_knownhosts_format (line, sizeof line, &n, "fmt.example.org",
                                      2222, p, hash), GF_OK);
      back = table (line, NULL);
      EXPECT (back, "fmt.example.org", 2222, p, GF_HOST_MATCH, NOW);
      EXPECT (back, "fmt.example.org", 22, p, GF_HOST_UNKNOWN, NOW);
      gf_knownhosts_free (back);
      CHECK_EQ (gf_knownhosts_format (line, 20, &n, "fmt.example.org", 22, e,
                                      hash), GF_ERR_BUFSIZE);
      CHECK_EQ (gf_knownhosts_format (line, sizeof line, &n, "fmt.example.org",
                                      22, c, hash), GF_ERR_INVAL);
    }
  /* Two lines hashed for the same name differ (a fresh salt each). */
  {
    char l2[1024];

    CHECK_EQ (gf_knownhosts_format (line, sizeof line, NULL, "s.example.org", 22, e, 1), GF_OK);
    CHECK_EQ (gf_knownhosts_format (l2, sizeof l2, NULL, "s.example.org", 22, e, 1), GF_OK);
    CHECK (strcmp (line, l2) != 0);
  }
  gf_key_free (e);
  gf_key_free (p);
  gf_key_free (c);
}

/* Lines in all shapes, and loading in pieces. */
static void
test_syntax (void)
{
  gf_knownhosts *kh;
  gf_key *e = key_of (vec_kh_e);
  char text[2048];
  size_t bad;

  /* No trailing newline, CRLF, tabs, trailing blanks, a comment on the line. */
  snprintf (text, sizeof text, "a.example.org\t%s some comment  \r\n  b.example.org %s",
            vec_kh_e, vec_kh_e);
  kh = table (text, &bad);
  CHECK_EQ (bad, 0);
  EXPECT (kh, "a.example.org", 22, e, GF_HOST_MATCH, NOW);
  EXPECT (kh, "b.example.org", 22, e, GF_HOST_MATCH, NOW);
  gf_knownhosts_free (kh);
  /* Refused: each of these makes no entry.  "@K@" stands for the key,
     "@B@" for its base64 alone.  */
  {
    static const char *const bad_lines[] = {
      "@K@",					/* No host.  */
      "x.example.org",				/* No key.  */
      "x.example.org ssh-ed25519",
      "@revoked",
      "@cert-authority x.example.org",
      "@Revoked x.example.org @K@",
      "@ x.example.org @K@",
      "|1|AAAA|AAAA @K@",
      "|1|@B@",
      "|1| @K@",
      "|1||| @K@",
      "|3|abc|def @K@",
      "! @K@",
      ", @K@",
      ",, @K@",
      "x.example.org ssh-rsa @B@"		/* Type and key disagree.  */
    };
    size_t i, refused = 0;

    for (i = 0; i < sizeof bad_lines / sizeof bad_lines[0]; i++)
      {
        char l[1024];
        size_t b = 0, o = 0;
        const char *p;

        for (p = bad_lines[i]; *p && o < sizeof l - 400; )
          {
            if (strncmp (p, "@K@", 3) == 0)
              {
                o += (size_t) snprintf (l + o, sizeof l - o, "%s", vec_kh_e);
                p += 3;
              }
            else if (strncmp (p, "@B@", 3) == 0)
              {
                o += (size_t) snprintf (l + o, sizeof l - o, "%s", vec_kh_e + 12);
                p += 3;
              }
            else
              l[o++] = *p++;
          }
        l[o] = '\0';
        kh = table (l, &b);
        if (b != 1)
          fprintf (stderr, "line %zu \"%s\": %zu refused\n", i, l, b);
        CHECK_EQ (b, 1);
        refused += b;
        EXPECT (kh, "x.example.org", 22, e, GF_HOST_UNKNOWN, NOW);
        gf_knownhosts_free (kh);
      }
    CHECK (refused > 10);
  }
  /* Loaded in two pieces; a key that is a certificate or a type the policy
     refuses never makes a host known. */
  kh = table ("", NULL);
  snprintf (text, sizeof text, "one.example.org %s\n", vec_kh_e);
  CHECK_EQ (gf_knownhosts_load (kh, text, strlen (text), &bad), GF_OK);
  CHECK_EQ (bad, 0);
  snprintf (text, sizeof text, "two.example.org %s\nthree.example.org %s\n",
            vec_kh_e, vec_kh_cert_good);
  CHECK_EQ (gf_knownhosts_load (kh, text, strlen (text), &bad), GF_OK);
  CHECK_EQ (bad, 1);
  EXPECT (kh, "one.example.org", 22, e, GF_HOST_MATCH, NOW);
  EXPECT (kh, "two.example.org", 22, e, GF_HOST_MATCH, NOW);
  EXPECT (kh, "three.example.org", 22, e, GF_HOST_UNKNOWN, NOW);
  CHECK_EQ (gf_knownhosts_load (kh, NULL, 5, NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_knownhosts_load (kh, NULL, 0, NULL), GF_OK);
  CHECK_EQ (gf_knownhosts_load (NULL, "", 0, NULL), GF_ERR_INVAL);
  gf_knownhosts_free (kh);
  /* A line that is too long is refused whole, and loading goes on. */
  {
    static char big[70002];
    size_t n;

    memset (big, 'a', 70000);
    memcpy (big, "x.example.org ", 14);
    n = 70000;
    big[n++] = '\n';
    big[n] = 0;
    kh = table (big, &bad);
    CHECK_EQ (bad, 1);
    gf_knownhosts_free (kh);
  }
  gf_key_free (e);
}

int
main (void)
{
  gf_crypto_init ();
  test_names ();
  test_revoked ();
  test_certificates ();
  test_sigalgs ();
  test_format ();
  test_syntax ();
  TST_DONE ();
}
