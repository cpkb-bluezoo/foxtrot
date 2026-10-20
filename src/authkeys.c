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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <foxtrot/status.h>
#include <foxtrot/key.h>
#include <foxtrot/authkeys.h>

#include "internal.h"

#define MAX_LINE 65536
#define MAX_VALUE 8192		/* The longest value of an option.  */
#define MAX_LIST 256		/* Most permitopen, permitlisten, environment.  */

/* The permissions, in the order of the flags of an entry.  */
static const char *const permit_names[] = {
  GF_CERT_PERMIT_PTY, GF_CERT_PERMIT_PORT_FORWARDING,
  GF_CERT_PERMIT_AGENT_FORWARDING, GF_CERT_PERMIT_X11_FORWARDING,
  GF_CERT_PERMIT_USER_RC
};
#define NPERMIT (sizeof permit_names / sizeof permit_names[0])

struct list
{
  char **v;
  size_t n;
};

struct entry
{
  gf_key *key;			/* Never a certificate.  */
  size_t line;
  int ca;
  int permit[NPERMIT];
  int verify;
  uint64_t expiry;
  char *command, *from, *principals;
  struct list open, listen, env;
};

struct gf_authkeys
{
  struct entry *e;
  size_t n, cap;
};

int
gf_authkeys_new (gf_authkeys **out)
{
  if (out == NULL)
    return GF_ERR_INVAL;
  *out = calloc (1, sizeof **out);
  return *out ? GF_OK : GF_ERR_NOMEM;
}

static void
list_free (struct list *l)
{
  size_t i;

  for (i = 0; i < l->n; i++)
    free (l->v[i]);
  free (l->v);
  l->v = NULL;
  l->n = 0;
}

static void
entry_free (struct entry *e)
{
  gf_key_free (e->key);
  free (e->command);
  free (e->from);
  free (e->principals);
  list_free (&e->open);
  list_free (&e->listen);
  list_free (&e->env);
}

void
gf_authkeys_free (gf_authkeys *t)
{
  size_t i;

  if (t == NULL)
    return;
  for (i = 0; i < t->n; i++)
    entry_free (&t->e[i]);
  free (t->e);
  free (t);
}

size_t
gf_authkeys_count (const gf_authkeys *t)
{
  return t ? t->n : 0;
}

size_t
gf_authkeys_cas (const gf_authkeys *t, const gf_key **out, size_t cap)
{
  size_t i, n = 0;

  if (t == NULL)
    return 0;
  for (i = 0; i < t->n; i++)
    if (t->e[i].ca)
      {
        if (out != NULL && n < cap)
          out[n] = t->e[i].key;
        n++;
      }
  return n;
}

/* ---- parsing a line ---- */

static int
is_blank (char c)
{
  return c == ' ' || c == '\t';
}

static char
lower (char c)
{
  return c >= 'A' && c <= 'Z' ? (char) (c - 'A' + 'a') : c;
}

static int
name_is (const char *n, size_t nn, const char *s)
{
  size_t i;

  if (strlen (s) != nn)
    return 0;
  for (i = 0; i < nn; i++)
    if (lower (n[i]) != lower (s[i]))
      return 0;
  return 1;
}

static int
is_leap (int64_t y)
{
  return y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
}

/* Seconds since 1970 of a date and time, or 0 if they are not one.  */
static uint64_t
civil (int64_t y, int m, int d, int hh, int mm, int ss)
{
  static const int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  int64_t era, yoe, doy, doe, days;

  if (y < 1970 || m < 1 || m > 12 || d < 1
      || d > mdays[m - 1] + (m == 2 && is_leap (y)) || hh > 23 || mm > 59
      || ss > 59)
    return 0;
  y -= m <= 2;
  era = y / 400;
  yoe = y - era * 400;
  doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  days = era * 146097 + doe - 719468;
  return (uint64_t) days * 86400 + (uint64_t) (hh * 3600 + mm * 60 + ss);
}

/* YYYYMMDD, YYYYMMDDHHMM or YYYYMMDDHHMMSS, then an optional Z.  0 if it
   is not one (the epoch itself is not a time anyone can mean).  */
static uint64_t
parse_expiry (const char *v)
{
  size_t n = strlen (v), i;
  int f[7] = { 0 };		/* y m d H M S */
  static const size_t w[6] = { 4, 2, 2, 2, 2, 2 };
  size_t pos = 0;
  int k, parts;

  if (n > 0 && v[n - 1] == 'Z')
    n--;
  if (n == 8)
    parts = 3;
  else if (n == 12)
    parts = 5;
  else if (n == 14)
    parts = 6;
  else
    return 0;
  for (i = 0; i < n; i++)
    if (v[i] < '0' || v[i] > '9')
      return 0;
  for (k = 0; k < parts; k++)
    {
      for (i = 0; i < w[k]; i++)
        f[k] = f[k] * 10 + (v[pos++] - '0');
    }
  return civil (f[0], f[1], f[2], f[3], f[4], f[5]);
}

static int
list_add (struct list *l, const char *s)
{
  char **nv;
  char *c;

  if (l->n >= MAX_LIST)
    return GF_ERR_RANGE;
  c = strdup (s);
  if (c == NULL)
    return GF_ERR_NOMEM;
  nv = realloc (l->v, (l->n + 1) * sizeof *nv);
  if (nv == NULL)
    {
      free (c);
      return GF_ERR_NOMEM;
    }
  l->v = nv;
  l->v[l->n++] = c;
  return GF_OK;
}

/* A port number 1 to 65535, or with STAR a lone '*'.  */
static int
port_ok (const char *s, int star)
{
  unsigned long v = 0;

  if (star && s[0] == '*' && s[1] == '\0')
    return 1;
  if (s[0] == '\0')
    return 0;
  for (; *s; s++)
    {
      if (*s < '0' || *s > '9')
        return 0;
      v = v * 10 + (unsigned long) (*s - '0');
      if (v > 65535)
        return 0;
    }
  return v > 0;
}

/* HOST:PORT or [HOST]:PORT (and with LISTEN, a lone PORT): the host and its
   length, and the port text.  0 if it is not one.  */
static int
split_hostport (const char *s, int listen, const char **host, size_t *hn,
                const char **port)
{
  const char *colon = strrchr (s, ':');

  if (colon == NULL)
    {
      if (!listen)
        return 0;
      *host = "*";
      *hn = 1;
      *port = s;
      return 1;
    }
  *port = colon + 1;
  *host = s;
  *hn = (size_t) (colon - s);
  if (*hn >= 2 && s[0] == '[' && colon[-1] == ']')
    {
      *host = s + 1;
      *hn -= 2;
    }
  return *hn > 0;
}

static int
hostport_ok (const char *s, int listen)
{
  const char *h, *p;
  size_t hn;

  if (!listen && (strcmp (s, "any") == 0 || strcmp (s, "none") == 0))
    return 1;
  return split_hostport (s, listen, &h, &hn, &p) && port_ok (p, 1);
}

static int
env_ok (const char *s)
{
  const char *eq = strchr (s, '=');
  const char *c;

  if (eq == NULL || eq == s || (*s >= '0' && *s <= '9'))
    return 0;
  for (c = s; c < eq; c++)
    if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z')
          || (*c >= '0' && *c <= '9') || *c == '_'))
      return 0;
  return 1;
}

/* Set a string option once.  */
static int
set_once (char **dst, const char *v)
{
  if (*dst != NULL)
    return GF_ERR_ENCODING;
  *dst = strdup (v);
  return *dst ? GF_OK : GF_ERR_NOMEM;
}

static void
set_all (struct entry *e, int v)
{
  size_t i;

  for (i = 0; i < NPERMIT; i++)
    e->permit[i] = v;
}

/* One option NAME (N bytes), with its value V (NUL-terminated) if HAS.
   GF_OK, GF_ERR_NOMEM, or another status for an option to refuse.  */
static int
apply_option (struct entry *e, const char *name, size_t n, int has,
              const char *v)
{
  static const struct
  {
    const char *name;
    size_t index;
    int value;
  } flags[] = {
    { "no-pty", 0, 0 }, { "pty", 0, 1 },
    { "no-port-forwarding", 1, 0 }, { "port-forwarding", 1, 1 },
    { "no-agent-forwarding", 2, 0 }, { "agent-forwarding", 2, 1 },
    { "no-x11-forwarding", 3, 0 }, { "x11-forwarding", 3, 1 },
    { "no-user-rc", 4, 0 }, { "user-rc", 4, 1 }
  };
  size_t i;
  int rc;

  for (i = 0; i < sizeof flags / sizeof flags[0]; i++)
    if (name_is (name, n, flags[i].name))
      {
        if (has)
          return GF_ERR_ENCODING;
        e->permit[flags[i].index] = flags[i].value;
        return GF_OK;
      }
  if (name_is (name, n, "restrict"))
    {
      if (has)
        return GF_ERR_ENCODING;
      set_all (e, 0);
      return GF_OK;
    }
  if (name_is (name, n, "cert-authority") || name_is (name, n, "verify-required")
      || name_is (name, n, "no-touch-required")
      || name_is (name, n, "touch-required"))
    {
      if (has)
        return GF_ERR_ENCODING;
      if (name_is (name, n, "cert-authority"))
        e->ca = 1;
      else if (name_is (name, n, "verify-required"))
        e->verify = 1;
      return GF_OK;
    }
  if (!has)
    return GF_ERR_ENCODING;
  if (name_is (name, n, "command"))
    return v[0] == '\0' ? GF_ERR_ENCODING : set_once (&e->command, v);
  if (name_is (name, n, "from"))
    return v[0] == '\0' ? GF_ERR_ENCODING : set_once (&e->from, v);
  if (name_is (name, n, "principals"))
    return v[0] == '\0' ? GF_ERR_ENCODING : set_once (&e->principals, v);
  if (name_is (name, n, "expiry-time"))
    {
      uint64_t t = parse_expiry (v);

      if (t == 0 || e->expiry != 0)
        return GF_ERR_ENCODING;
      e->expiry = t;
      return GF_OK;
    }
  if (name_is (name, n, "tunnel"))
    return GF_OK;		/* No tun forwarding: it can allow nothing.  */
  if (name_is (name, n, "permitopen"))
    rc = hostport_ok (v, 0) ? list_add (&e->open, v) : GF_ERR_ENCODING;
  else if (name_is (name, n, "permitlisten"))
    rc = hostport_ok (v, 1) ? list_add (&e->listen, v) : GF_ERR_ENCODING;
  else if (name_is (name, n, "environment"))
    rc = env_ok (v) ? list_add (&e->env, v) : GF_ERR_ENCODING;
  else
    rc = GF_ERR_ENCODING;	/* Unknown: do not guess it is harmless.  */
  return rc;
}

/* The options in [P, END), which end at white space outside quotes.
   Advances P past them.  */
static int
parse_options (struct entry *e, const char **pp, const char *end)
{
  const char *p = *pp;
  char value[MAX_VALUE + 1];

  for (;;)
    {
      const char *name = p;
      size_t nn, vn = 0;
      int has = 0, rc;

      value[0] = '\0';
      while (p < end && *p != '=' && *p != ',' && !is_blank (*p) && *p != '"')
        p++;
      nn = (size_t) (p - name);
      if (nn == 0)
        return GF_ERR_ENCODING;
      if (p < end && *p == '=')
        {
          has = 1;
          p++;
          if (p >= end || *p != '"')
            return GF_ERR_ENCODING;
          p++;
          for (;;)
            {
              if (p >= end)
                return GF_ERR_ENCODING;	/* Unterminated.  */
              if (*p == '"')
                {
                  p++;
                  break;
                }
              if (*p == '\\' && p + 1 < end && p[1] == '"')
                p++;
              if (vn >= MAX_VALUE || *p == '\0')
                return GF_ERR_ENCODING;
              value[vn++] = *p++;
            }
          value[vn] = '\0';
        }
      rc = apply_option (e, name, nn, has, value);
      if (rc != GF_OK)
        return rc;
      if (p < end && *p == ',')
        {
          p++;
          continue;
        }
      break;
    }
  if (p < end && !is_blank (*p))
    return GF_ERR_ENCODING;
  *pp = p;
  return GF_OK;
}

static int
entry_push (gf_authkeys *t, struct entry *e)
{
  if (t->n == t->cap)
    {
      size_t nc = t->cap ? t->cap * 2 : 16;
      struct entry *p = realloc (t->e, nc * sizeof *p);

      if (p == NULL)
        return GF_ERR_NOMEM;
      t->e = p;
      t->cap = nc;
    }
  t->e[t->n++] = *e;
  return GF_OK;
}

/* One line; 1 if it became an entry, 0 if it was refused, -1 for an error,
   2 for a line that is nothing (blank, comment).  */
static int
load_line (gf_authkeys *t, size_t lineno, const char *l, size_t n)
{
  const char *p = l, *end = l + n;
  struct entry e;
  int rc;

  memset (&e, 0, sizeof e);
  set_all (&e, 1);
  e.line = lineno;
  while (end > p && (end[-1] == '\r' || is_blank (end[-1])))
    end--;
  while (p < end && is_blank (*p))
    p++;
  if (p >= end || *p == '#')
    return 2;
  /* A key with no options, or options and then a key.  */
  if (gf_key_from_text (&e.key, p, (size_t) (end - p), NULL) != GF_OK)
    {
      e.key = NULL;
      rc = parse_options (&e, &p, end);
      if (rc == GF_ERR_NOMEM)
        {
          entry_free (&e);
          return -1;
        }
      while (rc == GF_OK && p < end && is_blank (*p))
        p++;
      if (rc != GF_OK || p >= end
          || gf_key_from_text (&e.key, p, (size_t) (end - p), NULL) != GF_OK)
        {
          e.key = NULL;
          entry_free (&e);
          return 0;
        }
    }
  /* Options that only mean something with others.  */
  if (gf_key_is_certificate (e.key) || (e.principals != NULL && !e.ca))
    {
      entry_free (&e);
      return 0;
    }
  if (entry_push (t, &e) != GF_OK)
    {
      entry_free (&e);
      return -1;
    }
  return 1;
}

int
gf_authkeys_load (gf_authkeys *t, const char *text, size_t len, size_t *bad)
{
  size_t i = 0, nbad = 0, lineno = 0;

  if (t == NULL || (text == NULL && len > 0))
    return GF_ERR_INVAL;
  while (i < len)
    {
      size_t j = i;
      int r;

      while (j < len && text[j] != '\n')
        j++;
      lineno++;
      r = j - i > MAX_LINE ? 0 : load_line (t, lineno, text + i, j - i);
      if (r < 0)
        return GF_ERR_NOMEM;
      if (r == 0)
        nbad++;
      i = j + 1;
    }
  if (bad)
    *bad = nbad;
  return GF_OK;
}

/* ---- checking ---- */

/* The patterns of a from= list against the client: some match and no
   excluded one does.  An entry without wildcards that is an address or a
   range is compared as one; the others as patterns for the address text
   and the name.  */
static int
from_ok (const char *list, const char *address, const char *host)
{
  uint8_t peer[16];
  char atext[INET6_ADDRSTRLEN], hlow[256];
  int have = 0, pfam = 0, matched = 0;
  size_t i = 0, ll = strlen (list), hl = 0;

  if (gfi_parse_peer (address, &pfam, peer))
    {
      have = 1;
      if (inet_ntop (pfam, peer, atext, sizeof atext) == NULL)
        have = 0;
    }
  if (host != NULL)
    {
      hl = strlen (host);
      if (hl >= sizeof hlow)
        hl = 0;			/* Not a host name: no name matches.  */
      for (i = 0; i < hl; i++)
        hlow[i] = lower (host[i]);
    }
  i = 0;
  while (i <= ll)
    {
      size_t j = i, pn;
      const char *pat;
      int neg, m = 0, wild = 0;
      size_t k;

      while (j < ll && list[j] != ',')
        j++;
      neg = j > i && list[i] == '!';
      pat = list + i + neg;
      pn = j - i - neg;
      i = j + 1;
      if (pn == 0)
        continue;
      for (k = 0; k < pn; k++)
        if (pat[k] == '*' || pat[k] == '?')
          wild = 1;
      if (!wild)
        {
          int fam;
          uint8_t a[16];
          unsigned bits;

          if (gfi_parse_cidr (pat, pn, &fam, a, &bits))
            {
              m = have && fam == pfam && gfi_prefix_equal (a, peer, bits);
              if (neg && m)
                return 0;
              matched |= m;
              continue;
            }
        }
      if (have && gfi_wildmatch (pat, pn, atext, strlen (atext)))
        m = 1;
      if (!m && hl > 0)
        {
          char plow[256];

          if (pn < sizeof plow)
            {
              for (k = 0; k < pn; k++)
                plow[k] = lower (pat[k]);
              m = gfi_wildmatch (plow, pn, hlow, hl);
            }
        }
      if (neg && m)
        return 0;
      matched |= m;
    }
  return matched;
}

/* Does a certificate have a principal that one of the patterns of LIST (a
   comma separated list) matches?  */
static int
principal_in (const gf_key *cert, const char *list)
{
  size_t pos = 0, ll = strlen (list);
  gf_slice p;

  while (gf_cert_principal_next (cert, &pos, &p))
    {
      size_t i = 0;

      while (i <= ll)
        {
          size_t j = i;

          while (j < ll && list[j] != ',')
            j++;
          if (j > i && gfi_wildmatch (list + i, j - i, (const char *) p.data,
                                      p.len))
            return 1;
          i = j + 1;
        }
    }
  return 0;
}

/* Does the entry authorize this request?  */
static int
entry_accepts (const struct entry *e, const gf_auth_request *req,
               const gf_key *key, int cert, const gf_cert_info *ci,
               const char *address, const char *hostname, uint64_t now)
{
  if (cert)
    {
      gf_slice fc;
      int found;

      if (!e->ca || !gf_key_equal (e->key, ci->ca))
        return 0;
      if (e->principals != NULL ? !principal_in (key, e->principals)
          : !gf_cert_has_principal (key, (const char *) req->user.data,
                                    req->user.len, 0))
        return 0;
      /* A command in the line and another in the certificate: neither.  */
      found = gf_cert_critical_option (key, "force-command", &fc);
      if (found < 0)
        return 0;
      if (found == 1 && e->command != NULL
          && !gf_slice_equals (fc, e->command))
        return 0;
    }
  else if (e->ca || !gf_key_equal (e->key, key))
    return 0;
  if (e->expiry != 0 && now >= e->expiry)
    return 0;
  if (e->from != NULL && !from_ok (e->from, address, hostname))
    return 0;
  if (e->verify && gf_key_is_security_key (key) && req->has_signature
      && !(req->sk_flags & GF_SK_USER_VERIFIED))
    return 0;
  return 1;
}

int
gf_authkeys_check (const gf_authkeys *t, const gf_auth_request *req,
                   const char *address, const char *hostname, uint64_t now,
                   gf_authkey_match *match)
{
  gf_cert_info ci;
  const gf_key *key;
  int cert;
  size_t i;

  if (t == NULL || req == NULL || req->key == NULL
      || req->method != GF_AUTH_PUBLICKEY)
    return GF_ERR_INVAL;
  key = req->key;
  memset (&ci, 0, sizeof ci);
  cert = gf_key_is_certificate (key);
  if (cert)
    {
      /* The machine has checked all this before it asks; a caller that
         did not use it gets the same answer.  */
      if (gf_key_certificate_info (key, &ci) != GF_OK
          || gf_cert_check (key, GF_CERT_USER, now, NULL) != GF_OK
          || !gf_cert_source_address_ok (key, address))
        return 0;
    }
  for (i = 0; i < t->n; i++)
    {
      const struct entry *e = &t->e[i];

      if (!entry_accepts (e, req, key, cert, &ci, address, hostname, now))
        continue;
      if (match != NULL)
        {
          memset (match, 0, sizeof *match);
          match->line = e->line;
          match->cert_authority = e->ca;
          match->command = e->command;
          match->expiry = e->expiry;
          match->entry = e;
        }
      return 1;
    }
  return 0;
}

int
gf_authkey_permits (const gf_authkey_match *m, const char *permission)
{
  const struct entry *e;
  size_t i;

  if (m == NULL || m->entry == NULL || permission == NULL)
    return 0;
  e = m->entry;
  for (i = 0; i < NPERMIT; i++)
    if (strcmp (permission, permit_names[i]) == 0)
      return e->permit[i];
  return 0;
}

/* Is HOST:PORT in LIST of permitopen or permitlisten values?  */
static int
in_hostport_list (const struct list *l, int listen, const char *host,
                  unsigned port)
{
  size_t i, hn = host ? strlen (host) : 0, k;

  if (l->n == 0)
    return 1;
  for (i = 0; i < l->n; i++)
    {
      const char *h, *p;
      size_t pn;
      int hok, pok;

      if (!listen && strcmp (l->v[i], "any") == 0)
        return 1;
      if (!listen && strcmp (l->v[i], "none") == 0)
        continue;
      if (!split_hostport (l->v[i], listen, &h, &pn, &p))
        continue;
      if (p[0] == '*')
        pok = 1;
      else
        pok = (unsigned) atoi (p) == port;
      if (pn == 1 && h[0] == '*')
        hok = 1;
      else if (hn != pn)
        hok = 0;
      else
        {
          hok = 1;
          for (k = 0; k < pn; k++)
            if (lower (h[k]) != lower (host[k]))
              hok = 0;
        }
      if (hok && pok)
        return 1;
    }
  return 0;
}

int
gf_authkey_permits_open (const gf_authkey_match *m, const char *host,
                         unsigned port)
{
  if (m == NULL || m->entry == NULL || host == NULL)
    return 0;
  return in_hostport_list (&((const struct entry *) m->entry)->open, 0, host,
                           port);
}

int
gf_authkey_permits_listen (const gf_authkey_match *m, const char *host,
                           unsigned port)
{
  const struct entry *e;

  if (m == NULL || m->entry == NULL)
    return 0;
  e = m->entry;
  /* A request that names no address is for the default one, which no
     line but one with a host of "*" (or no host) names.  */
  if (host == NULL)
    host = "";
  return in_hostport_list (&e->listen, 1, host, port);
}

int
gf_authkey_next (const gf_authkey_match *m, enum gf_authkey_list which,
                 size_t *pos, gf_slice *item)
{
  const struct entry *e;
  const struct list *l;

  if (m == NULL || m->entry == NULL || pos == NULL || item == NULL)
    return 0;
  e = m->entry;
  switch (which)
    {
    case GF_AUTHKEY_PERMITOPEN:
      l = &e->open;
      break;
    case GF_AUTHKEY_PERMITLISTEN:
      l = &e->listen;
      break;
    case GF_AUTHKEY_ENVIRONMENT:
      l = &e->env;
      break;
    default:
      return 0;
    }
  if (*pos >= l->n)
    return 0;
  item->data = (const uint8_t *) l->v[*pos];
  item->len = strlen (l->v[*pos]);
  (*pos)++;
  return 1;
}
