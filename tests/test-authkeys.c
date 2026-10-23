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

/* authorized_keys: which lines are read, which are refused, and what a
   request is told.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>
#include <foxtrot/auth.h>
#include <foxtrot/authkeys.h>

#include "tst-util.h"
#include "vectors-cert.h"
/* Both define vec_msg.  */
#define vec_msg vec_msg_sk
#include "vectors-sk.h"
#undef vec_msg

#define NOW 1700000000u

/* The authorized_keys text of the key whose private key is PRIV.  */
static const char *
ptext (const char *priv)
{
  static char buf[4][2048];
  static int n;
  char *b = buf[n++ % 4];
  gf_key *k = NULL;
  size_t len;

  CHECK_EQ (gf_key_from_openssh_private (&k, priv, strlen (priv)), GF_OK);
  CHECK_EQ (gf_key_to_text (k, b, sizeof buf[0], &len), GF_OK);
  while (len > 0 && b[len - 1] == '\n')
    b[--len] = '\0';
  gf_key_free (k);
  return b;
}

/* The text of a key, without a trailing newline or comment.  */
static const char *
pub (const char *text)
{
  static char buf[4][1024];
  static int n;
  char *b = buf[n++ % 4];
  size_t len = strlen (text);

  memcpy (b, text, len + 1);
  while (len > 0 && (b[len - 1] == '\n'))
    b[--len] = '\0';
  if (len > 1 && b[len - 2] == '\\' && b[len - 1] == 'n')
    b[len -= 2] = '\0';
  return b;
}

static gf_key *
key_of (const char *text)
{
  gf_key *k = NULL;
  const char *t = pub (text);

  CHECK_EQ (gf_key_from_text (&k, t, strlen (t), NULL), GF_OK);
  return k;
}

static gf_key *
cert_of (const char *hex)
{
  static uint8_t b[4096];
  gf_key *k = NULL;
  size_t n = tst_unhex (hex, b, sizeof b);

  CHECK_EQ (gf_key_from_blob (&k, b, n), GF_OK);
  return k;
}

/* The authorized_keys text of the certificate authority's key.  */
static const char *
ca_text (void)
{
  static char text[512];
  gf_key *ca = cert_of (vec_ca_ed_blob);
  size_t n;

  CHECK_EQ (gf_key_to_text (ca, text, sizeof text, &n), GF_OK);
  while (n > 0 && text[n - 1] == '\n')
    text[--n] = '\0';
  gf_key_free (ca);
  return text;
}

static gf_authkeys *
table (const char *text, size_t *bad)
{
  gf_authkeys *t = NULL;
  size_t b = 0;

  CHECK_EQ (gf_authkeys_new (&t), GF_OK);
  CHECK_EQ (gf_authkeys_load (t, text, strlen (text), &b), GF_OK);
  if (bad)
    *bad = b;
  return t;
}

static gf_auth_request
request (const gf_key *key, const char *user)
{
  gf_auth_request r;

  memset (&r, 0, sizeof r);
  r.method = GF_AUTH_PUBLICKEY;
  r.user.data = (const uint8_t *) user;
  r.user.len = strlen (user);
  r.key = key;
  r.has_signature = 1;
  return r;
}

/* A line of OPTS (may be empty) and the key.  */
static char *
line (char *out, size_t cap, const char *opts, const char *keytext)
{
  snprintf (out, cap, "%s%s%s\n", opts, opts[0] ? " " : "", pub (keytext));
  return out;
}

#define ADDR "192.0.2.50"

static int
accepts (const gf_authkeys *t, const gf_key *k, const char *user,
         const char *addr, const char *host, uint64_t now,
         gf_authkey_match *m)
{
  gf_auth_request r = request (k, user);
  int rc = gf_authkeys_check (t, &r, addr, host, now, m);

  CHECK (rc == 0 || rc == 1);
  return rc;
}

/* Plain lines: with and without options, comments and blanks, and the
   keys that are not read.  */
static void
test_lines (void)
{
  static char f[16384];
  size_t bad, o = 0;
  gf_authkeys *t;
  gf_key *ed = key_of (ptext (vec_ed_private)), *p256 = key_of (ptext (vec_p256_private)),
    *rsa = key_of (ptext (vec_rsa_private)), *p384 = key_of (ptext (vec_p384_private));
  char l[2048];

  o += (size_t) snprintf (f + o, sizeof f - o, "# a comment\n\n   \n");
  o += (size_t) snprintf (f + o, sizeof f - o, "%s", line (l, sizeof l, "", ptext (vec_ed_private)));
  o += (size_t) snprintf (f + o, sizeof f - o, "  \t%s",
                          line (l, sizeof l, "no-pty,Command=\"/bin/ls -l\"", ptext (vec_p256_private)));
  /* CR LF line ends and trailing blanks.  */
  o += (size_t) snprintf (f + o, sizeof f - o, "%s  \r\n", pub (ptext (vec_rsa_private)));
  t = table (f, &bad);
  CHECK_EQ (bad, 0);
  CHECK_EQ (gf_authkeys_count (t), 3);
  CHECK_EQ (accepts (t, ed, "alice", ADDR, NULL, NOW, NULL), 1);
  CHECK_EQ (accepts (t, rsa, "alice", ADDR, NULL, NOW, NULL), 1);
  CHECK_EQ (accepts (t, p384, "alice", ADDR, NULL, NOW, NULL), 0);
  {
    gf_authkey_match m;

    CHECK_EQ (accepts (t, p256, "alice", ADDR, NULL, NOW, &m), 1);
    CHECK_EQ (m.line, 5);
    CHECK (m.command != NULL && strcmp (m.command, "/bin/ls -l") == 0);
    CHECK (!m.cert_authority);
    CHECK_EQ (gf_authkey_permits (&m, GF_CERT_PERMIT_PTY), 0);
    CHECK_EQ (gf_authkey_permits (&m, GF_CERT_PERMIT_PORT_FORWARDING), 1);
    CHECK_EQ (gf_authkey_permits (&m, GF_CERT_PERMIT_USER_RC), 1);
    CHECK_EQ (gf_authkey_permits (&m, "permit-nothing"), 0);
    CHECK_EQ (gf_authkey_permits (&m, NULL), 0);
    CHECK_EQ (accepts (t, ed, "alice", ADDR, NULL, NOW, &m), 1);
    CHECK (m.command == NULL);
    CHECK_EQ (gf_authkey_permits (&m, GF_CERT_PERMIT_PTY), 1);
  }
  /* The user does not matter to a plain key: the file is the user's.  */
  CHECK_EQ (accepts (t, ed, "bob", ADDR, NULL, NOW, NULL), 1);
  gf_authkeys_free (t);

  /* Lines that are not read, counted, and not ones that block the rest.  */
  {
    static const char *const bad_lines[] = {
      "ssh-ed25519 notbase64 comment",
      "command=\"x\" ssh-ed25519 AAAA",
      "unknown-option ",
      "no-such-option ",
      "from=\"\" ",
      "command=\"\" ",
      "command=x ",
      "command=\"unterminated ",
      "command=\"a\",command=\"b\" ",
      "from=\"a\",from=\"b\" ",
      "expiry-time=\"20240101\",expiry-time=\"20250101\" ",
      "expiry-time=\"2024\" ",
      "expiry-time=\"20241301\" ",
      "expiry-time=\"19691231\" ",
      "expiry-time=\"20230229\" ",
      "expiry-time=\"21000229\" ",
      "expiry-time=\"20240101240000\" ",
      "unknown=\"x\" ",
      "Foo-Bar=\"x\" ",
      "expiry-time=\"20240230\" ",
      "expiry-time=\"20240101 ",
      "permitopen=\"nocolon\" ",
      "permitopen=\"host:0\" ",
      "permitopen=\"host:99999\" ",
      "permitopen=\"host:x\" ",
      "permitlisten=\"host:\" ",
      "environment=\"NOEQUALS\" ",
      "environment=\"=x\" ",
      "environment=\"1A=x\" ",
      "environment=\"A B=x\" ",
      "principals=\"alice\" ",		/* Only with cert-authority.  */
      "no-pty=\"yes\" ",
      "cert-authority=\"x\" ",
      "no-pty,,no-pty ",
      "no-pty, no-pty ",
      ",no-pty ",
      "no-pty, ",
      "\"quoted\" "
    };
    size_t i, expect = 0;

    for (i = 0; i < sizeof bad_lines / sizeof bad_lines[0]; i++)
      {
        o = 0;
        o += (size_t) snprintf (f + o, sizeof f - o, "%s", bad_lines[i]);
        /* Each is tried with a key after it, and alone.  */
        if (strstr (bad_lines[i], "AAAA") == NULL)
          o += (size_t) snprintf (f + o, sizeof f - o, "%s", pub (ptext (vec_ed_private)));
        snprintf (f + o, sizeof f - o, "\n");
        t = table (f, &bad);
        if (bad != 1 || gf_authkeys_count (t) != 0)
          {
            fprintf (stderr, "line was read or not counted: %s\n", f);
            CHECK (0);
          }
        gf_authkeys_free (t);
        expect++;
      }
    CHECK (expect > 0);
  }
  /* A NUL inside a value ends nothing: the line is refused.  */
  {
    char nul[2048];
    size_t n = (size_t) snprintf (nul, sizeof nul, "command=\"a_b\" %s\n",
                                  pub (ptext (vec_ed_private)));

    nul[10] = '\0';
    t = NULL;
    CHECK_EQ (gf_authkeys_new (&t), GF_OK);
    CHECK_EQ (gf_authkeys_load (t, nul, n, &bad), GF_OK);
    CHECK_EQ (bad, 1);
    CHECK_EQ (gf_authkeys_count (t), 0);
    gf_authkeys_free (t);
  }
  /* A certificate is not an authorized key, nor a key the policy refuses
     (ssh-dss is not a type this library has at all).  */
  {
    gf_key *c = cert_of (vec_ed_user_cert);
    static char text[2048];
    size_t n;

    CHECK_EQ (gf_key_to_text (c, text, sizeof text, &n), GF_OK);
    t = table (text, &bad);
    CHECK_EQ (bad, 1);
    CHECK_EQ (gf_authkeys_count (t), 0);
    gf_authkeys_free (t);
    gf_key_free (c);
    t = table ("ssh-dss AAAAB3NzaC1kc3MAAAA= x\n", &bad);
    CHECK_EQ (bad, 1);
    gf_authkeys_free (t);
  }
  /* A very long line is skipped; the next is read.  */
  {
    static char big[70000 + 2048];
    size_t n = 0;

    memset (big, 'a', 70000);
    n = 70000;
    n += (size_t) snprintf (big + n, sizeof big - n, "\n%s\n",
                            pub (ptext (vec_ed_private)));
    t = table (big, &bad);
    CHECK_EQ (bad, 1);
    CHECK_EQ (gf_authkeys_count (t), 1);
    gf_authkeys_free (t);
  }
  /* The last line needs no newline; tables add up.  */
  {
    gf_authkeys *u = NULL;

    CHECK_EQ (gf_authkeys_new (&u), GF_OK);
    CHECK_EQ (gf_authkeys_load (u, pub (ptext (vec_ed_private)), strlen (pub (ptext (vec_ed_private))), &bad), GF_OK);
    CHECK_EQ (gf_authkeys_load (u, pub (ptext (vec_rsa_private)), strlen (pub (ptext (vec_rsa_private))), &bad), GF_OK);
    CHECK_EQ (gf_authkeys_count (u), 2);
    CHECK_EQ (gf_authkeys_load (u, NULL, 0, NULL), GF_OK);
    CHECK_EQ (gf_authkeys_load (u, NULL, 3, NULL), GF_ERR_INVAL);
    CHECK_EQ (gf_authkeys_load (NULL, "", 0, NULL), GF_ERR_INVAL);
    gf_authkeys_free (u);
  }
  gf_key_free (ed);
  gf_key_free (p256);
  gf_key_free (rsa);
  gf_key_free (p384);
}

/* from=: addresses, ranges, wildcards, names and exclusions.  */
static void
test_from (void)
{
  static const struct
  {
    const char *from, *addr, *host;
    int ok;
  } v[] = {
    { "192.0.2.50", "192.0.2.50", NULL, 1 },
    { "192.0.2.50", "192.0.2.51", NULL, 0 },
    { "192.0.2.0/24", "192.0.2.50", NULL, 1 },
    { "192.0.2.0/24", "192.0.3.50", NULL, 0 },
    { "192.0.2.0/25", "192.0.2.200", NULL, 0 },
    { "192.0.2.*", "192.0.2.77", NULL, 1 },
    { "192.0.*", "192.0.2.77", NULL, 1 },
    { "192.1.*", "192.0.2.77", NULL, 0 },
    { "192.0.2.?0", "192.0.2.50", NULL, 1 },
    { "*", "192.0.2.50", NULL, 1 },
    { "*", NULL, NULL, 0 },
    { "10.0.0.0/8,192.0.2.0/24", "192.0.2.50", NULL, 1 },
    { "10.0.0.0/8,192.0.2.0/24", "11.0.0.1", NULL, 0 },
    /* An exclusion wins, wherever it is.  */
    { "192.0.2.0/24,!192.0.2.50", "192.0.2.50", NULL, 0 },
    { "!192.0.2.50,192.0.2.0/24", "192.0.2.50", NULL, 0 },
    { "192.0.2.0/24,!192.0.2.50", "192.0.2.51", NULL, 1 },
    { "*,!192.0.2.50", "192.0.2.50", NULL, 0 },
    { "*,!192.0.2.50", "192.0.2.51", NULL, 1 },
    /* Only exclusions match nothing.  */
    { "!192.0.2.50", "192.0.2.51", NULL, 0 },
    /* IPv6, and an IPv4 client on a dual-stack socket.  */
    { "2001:db8::/32", "2001:db8::1", NULL, 1 },
    { "2001:db8::/32", "2001:db9::1", NULL, 0 },
    { "2001:db8::1", "2001:db8:0:0:0:0:0:1", NULL, 1 },
    { "192.0.2.0/24", "::ffff:192.0.2.50", NULL, 1 },
    { "192.0.2.50", "::ffff:192.0.2.50", NULL, 1 },
    { "192.0.2.0/24", "2001:db8::1", NULL, 0 },
    { "2001:db8::/32", "192.0.2.50", NULL, 0 },
    /* A bad range matches nothing, not everything.  */
    { "192.0.2.0/33", "192.0.2.50", NULL, 0 },
    { "192.0.2.0/", "192.0.2.50", NULL, 0 },
    /* Names, without regard to case, only if given.  */
    { "*.example.org", "192.0.2.50", "host.example.org", 1 },
    { "*.EXAMPLE.org", "192.0.2.50", "Host.Example.ORG", 1 },
    { "*.example.org", "192.0.2.50", "host.example.net", 0 },
    { "*.example.org", "192.0.2.50", NULL, 0 },
    { "host.example.org", "192.0.2.50", "host.example.org", 1 },
    { "*.example.org,!bad.example.org", "192.0.2.50", "bad.example.org", 0 },
    { "*.example.org,!bad.example.org", "192.0.2.50", "ok.example.org", 1 },
    { "*.example.org,!192.0.2.50", "192.0.2.50", "ok.example.org", 0 },
    { "*.example.org", NULL, "ok.example.org", 1 },
    { "192.0.2.0/24", NULL, "ok.example.org", 0 },
    { "ok.example.org", "192.0.2.50", "", 0 },
    { ",,", "192.0.2.50", NULL, 0 }
  };
  size_t i;
  gf_key *ed = key_of (ptext (vec_ed_private));

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      char f[2048], l[2048];
      gf_authkeys *t;
      size_t bad;
      char opt[512];
      int got;

      snprintf (opt, sizeof opt, "from=\"%s\"", v[i].from);
      snprintf (f, sizeof f, "%s", line (l, sizeof l, opt, ptext (vec_ed_private)));
      t = table (f, &bad);
      if (bad == 1)		/* ",," is not a pattern list. */
        {
          CHECK_EQ (v[i].ok, 0);
          gf_authkeys_free (t);
          continue;
        }
      got = accepts (t, ed, "alice", v[i].addr, v[i].host, NOW, NULL);
      if (got != v[i].ok)
        {
          fprintf (stderr, "from=\"%s\" addr %s host %s: %d, want %d\n",
                   v[i].from, v[i].addr ? v[i].addr : "(none)",
                   v[i].host ? v[i].host : "(none)", got, v[i].ok);
          CHECK (0);
        }
      gf_authkeys_free (t);
    }
  /* A line that does not match its address does not stop a later line.  */
  {
    char f[4096], l[2048];
    gf_authkeys *t;
    gf_authkey_match m;

    snprintf (f, sizeof f, "%s", line (l, sizeof l, "from=\"10.0.0.0/8\",command=\"a\"", ptext (vec_ed_private)));
    snprintf (f + strlen (f), sizeof f - strlen (f), "%s",
              line (l, sizeof l, "command=\"b\"", ptext (vec_ed_private)));
    t = table (f, NULL);
    CHECK_EQ (accepts (t, ed, "alice", "10.1.2.3", NULL, NOW, &m), 1);
    CHECK (strcmp (m.command, "a") == 0);
    CHECK_EQ (m.line, 1);
    CHECK_EQ (accepts (t, ed, "alice", "192.0.2.1", NULL, NOW, &m), 1);
    CHECK (strcmp (m.command, "b") == 0);
    CHECK_EQ (m.line, 2);
    gf_authkeys_free (t);
  }
  gf_key_free (ed);
}

static void
test_expiry (void)
{
  static const struct
  {
    const char *when;
    uint64_t at;		/* The instant it means.  */
  } v[] = {
    { "20231114", 1699920000 },		/* 2023-11-14 00:00:00 */
    { "20231114Z", 1699920000 },
    { "202311142213", 1699999980 },	/* 22:13 */
    { "20231114221320Z", 1700000000 },
    { "20240229", 1709164800 },		/* A leap day. */
    { "19700102", 86400 }
  };
  size_t i;
  gf_key *ed = key_of (ptext (vec_ed_private));

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      char f[2048], l[2048], opt[128];
      gf_authkeys *t;
      gf_authkey_match m;

      snprintf (opt, sizeof opt, "expiry-time=\"%s\"", v[i].when);
      t = table (line (f, sizeof f, opt, ptext (vec_ed_private)), NULL);
      CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, v[i].at - 1, &m), 1);
      CHECK_EQ (m.expiry, v[i].at);
      CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, v[i].at, NULL), 0);
      CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, v[i].at + 1, NULL), 0);
      gf_authkeys_free (t);
      (void) l;
    }
  gf_key_free (ed);
}

static void
test_permissions (void)
{
  static const struct
  {
    const char *opts;
    int pty, fwd, agent, x11, rc;
  } v[] = {
    { "", 1, 1, 1, 1, 1 },
    { "no-pty", 0, 1, 1, 1, 1 },
    { "no-port-forwarding", 1, 0, 1, 1, 1 },
    { "no-agent-forwarding", 1, 1, 0, 1, 1 },
    { "NO-X11-FORWARDING", 1, 1, 1, 0, 1 },
    { "no-user-rc", 1, 1, 1, 1, 0 },
    { "restrict", 0, 0, 0, 0, 0 },
    { "restrict,pty", 1, 0, 0, 0, 0 },
    { "restrict,port-forwarding,x11-forwarding", 0, 1, 0, 1, 0 },
    { "restrict,agent-forwarding,user-rc", 0, 0, 1, 0, 1 },
    /* Options act in order: a later restrict takes back an earlier grant.  */
    { "pty,restrict", 0, 0, 0, 0, 0 },
    { "no-pty,pty", 1, 1, 1, 1, 1 },
    { "pty,no-pty", 0, 1, 1, 1, 1 },
    { "verify-required,no-touch-required,tunnel=\"0\",cert-authority", 1, 1, 1, 1, 1 }
  };
  size_t i;
  gf_key *ed = key_of (ptext (vec_ed_private));

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      char f[2048];
      gf_authkeys *t;
      gf_authkey_match m;
      size_t bad;

      t = table (line (f, sizeof f, v[i].opts, ptext (vec_ed_private)), &bad);
      if (strstr (v[i].opts, "cert-authority") != NULL)
        {
          /* A CA line: it matches certificates only.  */
          CHECK_EQ (gf_authkeys_count (t), 1);
          CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, NULL), 0);
          gf_authkeys_free (t);
          continue;
        }
      CHECK_EQ (bad, 0);
      CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, &m), 1);
      if (gf_authkey_permits (&m, GF_CERT_PERMIT_PTY) != v[i].pty
          || gf_authkey_permits (&m, GF_CERT_PERMIT_PORT_FORWARDING) != v[i].fwd
          || gf_authkey_permits (&m, GF_CERT_PERMIT_AGENT_FORWARDING) != v[i].agent
          || gf_authkey_permits (&m, GF_CERT_PERMIT_X11_FORWARDING) != v[i].x11
          || gf_authkey_permits (&m, GF_CERT_PERMIT_USER_RC) != v[i].rc)
        {
          fprintf (stderr, "options \"%s\" read wrongly\n", v[i].opts);
          CHECK (0);
        }
      gf_authkeys_free (t);
    }
  gf_key_free (ed);
}

static void
test_forwarding_lists (void)
{
  char f[4096], l[2048];
  gf_authkeys *t;
  gf_authkey_match m;
  gf_slice it;
  size_t pos;
  gf_key *ed = key_of (ptext (vec_ed_private));

  t = table (line (f, sizeof f,
                   "permitopen=\"db.example.org:5432\",permitopen=\"[2001:db8::1]:22\","
                   "permitopen=\"Web.Example.Org:*\",permitlisten=\"8080\","
                   "permitlisten=\"localhost:9000\",permitlisten=\"*:9100\","
                   "environment=\"A=1\",environment=\"B=two words\"", ptext (vec_ed_private)),
             NULL);
  CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, &m), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "db.example.org", 5432), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "DB.example.org", 5432), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "db.example.org", 5433), 0);
  CHECK_EQ (gf_authkey_permits_open (&m, "other.example.org", 5432), 0);
  CHECK_EQ (gf_authkey_permits_open (&m, "2001:db8::1", 22), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "2001:db8::1", 23), 0);
  CHECK_EQ (gf_authkey_permits_open (&m, "web.example.org", 1), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "web.example.org", 65535), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "xweb.example.org", 80), 0);
  CHECK_EQ (gf_authkey_permits_open (&m, NULL, 80), 0);
  CHECK_EQ (gf_authkey_permits_open (&m, "", 80), 0);
  CHECK_EQ (gf_authkey_permits_listen (&m, "127.0.0.1", 8080), 1);
  CHECK_EQ (gf_authkey_permits_listen (&m, NULL, 8080), 1);
  CHECK_EQ (gf_authkey_permits_listen (&m, "", 8080), 1);
  CHECK_EQ (gf_authkey_permits_listen (&m, "127.0.0.1", 8081), 0);
  CHECK_EQ (gf_authkey_permits_listen (&m, "localhost", 9000), 1);
  CHECK_EQ (gf_authkey_permits_listen (&m, "0.0.0.0", 9000), 0);
  CHECK_EQ (gf_authkey_permits_listen (&m, "0.0.0.0", 9100), 1);
  pos = 0;
  CHECK_EQ (gf_authkey_next (&m, GF_AUTHKEY_ENVIRONMENT, &pos, &it), 1);
  CHECK (gf_slice_equals (it, "A=1"));
  CHECK_EQ (gf_authkey_next (&m, GF_AUTHKEY_ENVIRONMENT, &pos, &it), 1);
  CHECK (gf_slice_equals (it, "B=two words"));
  CHECK_EQ (gf_authkey_next (&m, GF_AUTHKEY_ENVIRONMENT, &pos, &it), 0);
  pos = 0;
  CHECK_EQ (gf_authkey_next (&m, GF_AUTHKEY_PERMITOPEN, &pos, &it), 1);
  CHECK (gf_slice_equals (it, "db.example.org:5432"));
  CHECK_EQ (gf_authkey_next (&m, (enum gf_authkey_list) 99, &pos, &it), 0);
  gf_authkeys_free (t);

  /* No list, no limit; "none" nothing; "any" everything.  */
  t = table (line (f, sizeof f, "", ptext (vec_ed_private)), NULL);
  CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, &m), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "x", 1), 1);
  CHECK_EQ (gf_authkey_permits_listen (&m, "x", 1), 1);
  gf_authkeys_free (t);
  t = table (line (f, sizeof f, "permitopen=\"none\"", ptext (vec_ed_private)), NULL);
  CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, &m), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "x", 1), 0);
  gf_authkeys_free (t);
  t = table (line (f, sizeof f, "permitopen=\"none\",permitopen=\"any\"", ptext (vec_ed_private)), NULL);
  CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, &m), 1);
  CHECK_EQ (gf_authkey_permits_open (&m, "x", 1), 1);
  gf_authkeys_free (t);
  CHECK_EQ (gf_authkey_permits_open (NULL, "x", 1), 0);

  /* A socket path cannot be named by either list: any list shuts sockets
     out of its direction.  */
  t = table (line (f, sizeof f, "", ptext (vec_ed_private)), NULL);
  CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, &m), 1);
  CHECK_EQ (gf_authkey_permits_open_path (&m), 1);
  CHECK_EQ (gf_authkey_permits_listen_path (&m), 1);
  gf_authkeys_free (t);
  t = table (line (f, sizeof f, "permitopen=\"none\"", ptext (vec_ed_private)), NULL);
  CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, &m), 1);
  CHECK_EQ (gf_authkey_permits_open_path (&m), 0);
  CHECK_EQ (gf_authkey_permits_listen_path (&m), 1);
  gf_authkeys_free (t);
  t = table (line (f, sizeof f, "permitlisten=\"8080\"", ptext (vec_ed_private)), NULL);
  CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, &m), 1);
  CHECK_EQ (gf_authkey_permits_open_path (&m), 1);
  CHECK_EQ (gf_authkey_permits_listen_path (&m), 0);
  gf_authkeys_free (t);
  CHECK_EQ (gf_authkey_permits_open_path (NULL), 0);
  CHECK_EQ (gf_authkey_permits_listen_path (NULL), 0);
  (void) l;
  gf_key_free (ed);
}

/* Certificates come in through cert-authority lines only.  */
static void
test_cert_authority (void)
{
  gf_key *noperm = cert_of (vec_noperm_cert);	/* alice; no extensions. */
  gf_key *user = cert_of (vec_ed_user_cert);	/* alice,bob; command; address. */
  gf_key *expired = cert_of (vec_expired_cert);
  gf_key *ed = key_of (ptext (vec_ed_private));
  char f[4096], opt[512];
  gf_authkeys *t;
  gf_authkey_match m;
  const gf_key *cas[4];

  /* Without a CA line a certificate gets nowhere, even if its own key is
     listed.  */
  t = table (line (f, sizeof f, "", ptext (vec_ed_private)), NULL);
  CHECK_EQ (accepts (t, noperm, "alice", ADDR, NULL, NOW, NULL), 0);
  gf_authkeys_free (t);

  snprintf (f, sizeof f, "cert-authority %s\n", ca_text ());
  t = table (f, NULL);
  CHECK_EQ (gf_authkeys_cas (t, cas, 4), 1);
  CHECK_EQ (accepts (t, noperm, "alice", ADDR, NULL, NOW, &m), 1);
  CHECK (m.cert_authority);
  /* The user must be a principal.  */
  CHECK_EQ (accepts (t, noperm, "bob", ADDR, NULL, NOW, NULL), 0);
  CHECK_EQ (accepts (t, user, "bob", "192.0.2.9", NULL, NOW, &m), 1);
  /* The line names no command; the certificate's force-command is the
     one the user must be given.  */
  CHECK (m.command != NULL && strcmp (m.command, "/bin/true") == 0);
  /* The certificate's own conditions: dates, source address.  */
  CHECK_EQ (accepts (t, user, "bob", "198.51.100.1", NULL, NOW, NULL), 0);
  CHECK_EQ (accepts (t, user, "bob", NULL, NULL, NOW, NULL), 0);
  CHECK_EQ (accepts (t, expired, "alice", ADDR, NULL, NOW, NULL), 0);
  CHECK_EQ (accepts (t, noperm, "alice", ADDR, NULL, 1500000000000ull, NULL), 0);
  /* A line that lists the CA's key but is not a cert-authority line says
     nothing about certificates it signed.  */
  {
    gf_authkeys *u;

    snprintf (f, sizeof f, "%s\n", ca_text ());
    u = table (f, NULL);
    CHECK_EQ (accepts (u, noperm, "alice", ADDR, NULL, NOW, NULL), 0);
    CHECK_EQ (gf_authkeys_cas (u, cas, 4), 0);
    gf_authkeys_free (u);
  }
  /* A plain key is not got in by a CA line.  */
  CHECK_EQ (accepts (t, ed, "alice", ADDR, NULL, NOW, NULL), 0);
  gf_authkeys_free (t);

  /* principals= says who the certificate may be for, instead of the user
     name.  */
  snprintf (opt, sizeof opt, "cert-authority,principals=\"al*,carol\"");
  snprintf (f, sizeof f, "%s %s\n", opt, ca_text ());
  t = table (f, NULL);
  CHECK_EQ (accepts (t, noperm, "alice", ADDR, NULL, NOW, NULL), 1);
  CHECK_EQ (accepts (t, noperm, "dave", ADDR, NULL, NOW, NULL), 1);
  CHECK_EQ (accepts (t, user, "dave", "192.0.2.9", NULL, NOW, NULL), 1);
  gf_authkeys_free (t);
  snprintf (f, sizeof f, "cert-authority,principals=\"carol,dave\" %s\n", ca_text ());
  t = table (f, NULL);
  CHECK_EQ (accepts (t, noperm, "carol", ADDR, NULL, NOW, NULL), 0);
  CHECK_EQ (accepts (t, noperm, "alice", ADDR, NULL, NOW, NULL), 0);
  gf_authkeys_free (t);

  /* from= and expiry on the CA line.  */
  snprintf (f, sizeof f, "cert-authority,from=\"198.51.100.0/24\" %s\n", ca_text ());
  t = table (f, NULL);
  CHECK_EQ (accepts (t, noperm, "alice", "198.51.100.7", NULL, NOW, NULL), 1);
  CHECK_EQ (accepts (t, noperm, "alice", "192.0.2.7", NULL, NOW, NULL), 0);
  gf_authkeys_free (t);
  snprintf (f, sizeof f, "cert-authority,expiry-time=\"20200101\" %s\n", ca_text ());
  t = table (f, NULL);
  CHECK_EQ (accepts (t, noperm, "alice", ADDR, NULL, NOW, NULL), 0);
  gf_authkeys_free (t);

  /* A command in the line and another in the certificate: neither.  The
     same, or only one of them, is fine.  */
  snprintf (f, sizeof f, "cert-authority,command=\"/bin/false\" %s\n", ca_text ());
  t = table (f, NULL);
  CHECK_EQ (accepts (t, user, "alice", "192.0.2.9", NULL, NOW, NULL), 0);
  CHECK_EQ (accepts (t, noperm, "alice", ADDR, NULL, NOW, &m), 1);
  CHECK (strcmp (m.command, "/bin/false") == 0);
  gf_authkeys_free (t);
  snprintf (f, sizeof f, "cert-authority,command=\"/bin/true\" %s\n", ca_text ());
  t = table (f, NULL);
  CHECK_EQ (accepts (t, user, "alice", "192.0.2.9", NULL, NOW, NULL), 1);
  gf_authkeys_free (t);

  /* Other keys' CA lines do not count: the first line is another CA.  */
  snprintf (f, sizeof f, "cert-authority %s\ncert-authority %s\n",
            pub (ptext (vec_p256_private)), ca_text ());
  t = table (f, NULL);
  CHECK_EQ (gf_authkeys_cas (t, cas, 4), 2);
  CHECK_EQ (gf_authkeys_cas (t, cas, 1), 2);
  CHECK_EQ (gf_authkeys_cas (t, NULL, 0), 2);
  CHECK_EQ (accepts (t, noperm, "alice", ADDR, NULL, NOW, &m), 1);
  CHECK_EQ (m.line, 2);
  gf_authkeys_free (t);

  gf_key_free (noperm);
  gf_key_free (user);
  gf_key_free (expired);
  gf_key_free (ed);
}

static void
test_security_keys (void)
{
  gf_key *sk = key_of (vec_sk_ed_pub);
  char f[4096], l[2048];
  gf_authkeys *t;
  gf_auth_request r;

  t = table (line (l, sizeof l, "", vec_sk_ed_pub), NULL);
  r = request (sk, "alice");
  r.sk_flags = GF_SK_USER_PRESENT;
  CHECK_EQ (gf_authkeys_check (t, &r, ADDR, NULL, NOW, NULL), 1);
  gf_authkeys_free (t);

  t = table (line (f, sizeof f, "verify-required", vec_sk_ed_pub), NULL);
  r.sk_flags = GF_SK_USER_PRESENT;
  CHECK_EQ (gf_authkeys_check (t, &r, ADDR, NULL, NOW, NULL), 0);
  r.sk_flags = GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED;
  CHECK_EQ (gf_authkeys_check (t, &r, ADDR, NULL, NOW, NULL), 1);
  /* A query has no signature, so no flags: the signed request decides.  */
  r.has_signature = 0;
  r.sk_flags = 0;
  CHECK_EQ (gf_authkeys_check (t, &r, ADDR, NULL, NOW, NULL), 1);
  gf_authkeys_free (t);
  /* On a key that is not a security key it means nothing, as in OpenSSH.  */
  {
    gf_key *ed = key_of (ptext (vec_ed_private));

    t = table (line (f, sizeof f, "verify-required", ptext (vec_ed_private)), NULL);
    CHECK_EQ (accepts (t, ed, "alice", ADDR, NULL, NOW, NULL), 1);
    gf_authkeys_free (t);
    gf_key_free (ed);
  }
  gf_key_free (sk);

  /* verify-required on the certificate, with nothing about it on the line.  */
  {
    gf_key *skcert = cert_of (vec_sk_ed_cert_uv);
    gf_key *ca = cert_of (vec_sk_ca_blob);
    char text[512];
    size_t n;
    gf_auth_request req;

    CHECK_EQ (gf_key_to_text (ca, text, sizeof text, &n), GF_OK);
    while (n > 0 && text[n - 1] == '\n')
      text[--n] = '\0';
    snprintf (f, sizeof f, "cert-authority %s\n", text);
    t = table (f, NULL);
    req = request (skcert, "alice");
    req.sk_flags = GF_SK_USER_PRESENT;
    CHECK_EQ (gf_authkeys_check (t, &req, ADDR, NULL, NOW, NULL), 0);
    req.sk_flags = GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED;
    CHECK_EQ (gf_authkeys_check (t, &req, ADDR, NULL, NOW, NULL), 1);
    req.has_signature = 0;
    req.sk_flags = 0;
    CHECK_EQ (gf_authkeys_check (t, &req, ADDR, NULL, NOW, NULL), 1);
    gf_authkeys_free (t);
    gf_key_free (skcert);
    gf_key_free (ca);
  }
}

static void
test_arguments (void)
{
  gf_authkeys *t = table ("", NULL);
  gf_key *ed = key_of (ptext (vec_ed_private));
  gf_auth_request r = request (ed, "a");

  CHECK_EQ (gf_authkeys_count (t), 0);
  CHECK_EQ (gf_authkeys_count (NULL), 0);
  CHECK_EQ (accepts (t, ed, "a", ADDR, NULL, NOW, NULL), 0);
  CHECK_EQ (gf_authkeys_check (NULL, &r, ADDR, NULL, NOW, NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_authkeys_check (t, NULL, ADDR, NULL, NOW, NULL), GF_ERR_INVAL);
  r.key = NULL;
  CHECK_EQ (gf_authkeys_check (t, &r, ADDR, NULL, NOW, NULL), GF_ERR_INVAL);
  r = request (ed, "a");
  r.method = GF_AUTH_PASSWORD;
  CHECK_EQ (gf_authkeys_check (t, &r, ADDR, NULL, NOW, NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_authkeys_new (NULL), GF_ERR_INVAL);
  gf_authkeys_free (NULL);
  gf_authkeys_free (t);
  gf_key_free (ed);
}

int
main (void)
{
  CHECK_EQ (gf_crypto_init (), GF_OK);
  test_lines ();
  test_from ();
  test_expiry ();
  test_permissions ();
  test_forwarding_lists ();
  test_cert_authority ();
  test_security_keys ();
  test_arguments ();
  TST_DONE ();
}
