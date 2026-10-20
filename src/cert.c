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
#include <arpa/inet.h>
#include <sys/socket.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

#include "internal.h"
#include "keyint.h"

#define CERT_SUFFIX "-cert-v01@openssh.com"

int
gfi_wildmatch (const char *pat, size_t pn, const char *s, size_t sn)
{
  size_t p = 0, i = 0, star = (size_t) -1, mark = 0;

  while (i < sn)
    {
      if (p < pn && (pat[p] == '?' || pat[p] == s[i]) && pat[p] != '*')
        {
          p++;
          i++;
        }
      else if (p < pn && pat[p] == '*')
        {
          star = p++;
          mark = i;
        }
      else if (star != (size_t) -1)
        {
          p = star + 1;
          i = ++mark;
        }
      else
        return 0;
    }
  while (p < pn && pat[p] == '*')
    p++;
  return p == pn;
}

void
gfi_cert_free (struct gf_cert *c)
{
  if (c == NULL)
    return;
  gf_key_free (c->ca);
  free (c);
}

/* Packed strings must be a whole number of strings; packed pairs a whole
   number of (name, data) pairs, with the names strictly increasing, which
   forbids duplicates.  */
static int
valid_strings (gf_slice packed)
{
  gf_reader r;
  gf_slice s;

  gf_reader_init (&r, packed.data, packed.len);
  while (gf_rd_remaining (&r) > 0)
    if (gf_rd_string (&r, &s) != GF_OK)
      return 0;
  return 1;
}

static int
valid_pairs (gf_slice packed)
{
  gf_reader r;
  gf_slice name, data, prev = { NULL, 0 };
  int first = 1;

  gf_reader_init (&r, packed.data, packed.len);
  while (gf_rd_remaining (&r) > 0)
    {
      size_t n;
      int c;

      if (gf_rd_string (&r, &name) != GF_OK || gf_rd_string (&r, &data) != GF_OK)
        return 0;
      n = name.len < prev.len ? name.len : prev.len;
      c = n ? memcmp (name.data, prev.data, n) : 0;
      if (!first && (c < 0 || (c == 0 && name.len <= prev.len)))
        return 0;
      prev = name;
      first = 0;
    }
  return 1;
}

static int
parse (gf_key **out, const uint8_t *blob, size_t len, gf_slice name,
       uint8_t *plain, size_t plain_cap)
{
  gf_reader r;
  gf_slice nonce, a, b, key_id, principals, critical, extensions, reserved;
  gf_slice sigkey, sig, signame, sigdata;
  uint64_t serial, valid_after, valid_before;
  uint32_t type;
  gf_writer w;
  size_t base_len = name.len - (sizeof CERT_SUFFIX - 1), signed_len, off;
  gf_key *k = NULL, *ca = NULL;
  struct gf_cert *c = NULL;
  uint8_t *copy = NULL;
  enum gf_sigalg alg;
  gf_reader sr;
  int rc = GF_ERR_ENCODING, is_rsa, is_ec, is_sk;
  char plain_name[64];
  size_t pnl;

  if (out == NULL || name.len <= sizeof CERT_SUFFIX - 1)
    return GF_ERR_INVAL;
  /* The security keys keep "@openssh.com" in their plain names, and carry
     an application after the key.  */
  is_sk = base_len > 3 && memcmp (name.data, "sk-", 3) == 0;
  is_rsa = base_len == 7 && memcmp (name.data, "ssh-rsa", 7) == 0;
  is_ec = base_len > 6 && memcmp (name.data + (is_sk ? 3 : 0), "ecdsa-", 6) == 0;
  if (base_len + sizeof "@openssh.com" > sizeof plain_name)
    return GF_ERR_UNSUPPORTED;
  memcpy (plain_name, name.data, base_len);
  pnl = base_len;
  if (is_sk)
    {
      memcpy (plain_name + pnl, "@openssh.com", sizeof "@openssh.com" - 1);
      pnl += sizeof "@openssh.com" - 1;
    }

  gf_reader_init (&r, blob, len);
  if (gf_rd_string (&r, &a) != GF_OK		/* The type name again.  */
      || gf_rd_string (&r, &nonce) != GF_OK || nonce.len == 0)
    return GF_ERR_ENCODING;

  /* The key inside, as the plain blob it would have been.  */
  gf_writer_init (&w, plain, plain_cap);
  gf_wr_string (&w, plain_name, pnl);
  if (is_rsa)
    {
      if (gf_rd_mpint (&r, &a) != GF_OK || gf_rd_mpint (&r, &b) != GF_OK)
        return GF_ERR_ENCODING;
      gf_wr_mpint (&w, a.data, a.len);		/* e, then n.  */
      gf_wr_mpint (&w, b.data, b.len);
    }
  else if (is_ec)
    {
      if (gf_rd_string (&r, &a) != GF_OK || gf_rd_string (&r, &b) != GF_OK)
        return GF_ERR_ENCODING;
      gf_wr_string (&w, a.data, a.len);
      gf_wr_string (&w, b.data, b.len);
    }
  else
    {
      if (gf_rd_string (&r, &a) != GF_OK)
        return GF_ERR_ENCODING;
      gf_wr_string (&w, a.data, a.len);
    }
  if (is_sk)
    {
      if (gf_rd_string (&r, &a) != GF_OK)
        return GF_ERR_ENCODING;
      gf_wr_string (&w, a.data, a.len);
    }
  if (gf_wr_status (&w) != GF_OK)
    return GF_ERR_ENCODING;

  if (gf_rd_u64 (&r, &serial) != GF_OK || gf_rd_u32 (&r, &type) != GF_OK
      || (type != GF_CERT_USER && type != GF_CERT_HOST)
      || gf_rd_string (&r, &key_id) != GF_OK
      || gf_rd_string (&r, &principals) != GF_OK
      || gf_rd_u64 (&r, &valid_after) != GF_OK
      || gf_rd_u64 (&r, &valid_before) != GF_OK
      || gf_rd_string (&r, &critical) != GF_OK
      || gf_rd_string (&r, &extensions) != GF_OK
      || gf_rd_string (&r, &reserved) != GF_OK
      || gf_rd_string (&r, &sigkey) != GF_OK)
    return GF_ERR_ENCODING;
  signed_len = len - gf_rd_remaining (&r);
  if (gf_rd_string (&r, &sig) != GF_OK || gf_rd_finish (&r) != GF_OK)
    return GF_ERR_ENCODING;
  if (!valid_strings (principals) || !valid_pairs (critical)
      || !valid_pairs (extensions))
    return GF_ERR_ENCODING;

  /* The CA's signature, by an algorithm the policy has.  */
  if (gf_key_from_blob (&ca, sigkey.data, sigkey.len) != GF_OK)
    return GF_ERR_UNSUPPORTED;
  if (gf_key_is_certificate (ca))
    {
      gf_key_free (ca);
      return GF_ERR_UNSUPPORTED;		/* No chains.  */
    }
  gf_reader_init (&sr, sig.data, sig.len);
  if (gf_rd_string (&sr, &signame) != GF_OK
      || gf_rd_string (&sr, &sigdata) != GF_OK)
    {
      gf_key_free (ca);
      return GF_ERR_ENCODING;
    }
  alg = gf_sigalg_from_name ((const char *) signame.data, signame.len);
  if (alg == 0 || gf_sigalg_is_cert (alg))
    {
      gf_key_free (ca);
      return GF_ERR_UNSUPPORTED;	/* Including SHA-1.  */
    }
  rc = gf_key_verify (ca, alg, blob, signed_len, sig.data, sig.len);
  if (rc != GF_OK)
    {
      gf_key_free (ca);
      return rc == GF_ERR_UNSUPPORTED ? rc : GF_ERR_HOSTKEY;
    }

  /* The key itself, which the policy must accept too.  */
  rc = gf_key_from_blob (&k, plain, w.len);
  if (rc != GF_OK)
    {
      gf_key_free (ca);
      return rc;
    }
  copy = malloc (len);
  c = calloc (1, sizeof *c);
  if (copy == NULL || c == NULL)
    {
      free (copy);
      free (c);
      gf_key_free (ca);
      gf_key_free (k);
      return GF_ERR_NOMEM;
    }
  memcpy (copy, blob, len);
  /* The key's plain blob moves aside; the certificate is the blob.  */
  k->plain = k->blob;
  k->plainlen = k->bloblen;
  k->blob = copy;
  k->bloblen = len;
  c->serial = serial;
  c->type = type;
  c->valid_after = valid_after;
  c->valid_before = valid_before;
  c->ca = ca;
  /* Rebase the slices onto our copy.  */
#define REBASE(f, sl) \
  do { off = (size_t) ((sl).data - blob); (f).data = copy + off; \
       (f).len = (sl).len; } while (0)
  REBASE (c->key_id, key_id);
  REBASE (c->principals, principals);
  REBASE (c->critical, critical);
  REBASE (c->extensions, extensions);
#undef REBASE
  k->cert = c;
  (void) reserved;
  *out = k;
  return GF_OK;
}

int
gfi_cert_parse (gf_key **out, const uint8_t *blob, size_t len, gf_slice name)
{
  /* The key inside is no bigger than the certificate that holds it.  */
  uint8_t *plain = malloc (len + 64);
  int rc;

  if (plain == NULL)
    return GF_ERR_NOMEM;
  rc = parse (out, blob, len, name, plain, len + 64);
  free (plain);
  return rc;
}

int
gf_key_certificate_info (const gf_key *k, gf_cert_info *info)
{
  if (k == NULL || info == NULL || k->cert == NULL)
    return GF_ERR_INVAL;
  info->serial = k->cert->serial;
  info->type = (int) k->cert->type;
  info->key_id = k->cert->key_id;
  info->valid_after = k->cert->valid_after;
  info->valid_before = k->cert->valid_before;
  info->ca = k->cert->ca;
  return GF_OK;
}

static int
next_string (gf_slice packed, size_t *pos, gf_slice *s)
{
  gf_reader r;

  if (*pos >= packed.len)
    return 0;
  gf_reader_init (&r, packed.data + *pos, packed.len - *pos);
  if (gf_rd_string (&r, s) != GF_OK)
    return 0;
  *pos = packed.len - gf_rd_remaining (&r);
  return 1;
}

static int
next_pair (gf_slice packed, size_t *pos, gf_slice *name, gf_slice *data)
{
  gf_reader r;

  if (*pos >= packed.len)
    return 0;
  gf_reader_init (&r, packed.data + *pos, packed.len - *pos);
  if (gf_rd_string (&r, name) != GF_OK || gf_rd_string (&r, data) != GF_OK)
    return 0;
  *pos = packed.len - gf_rd_remaining (&r);
  return 1;
}

int
gf_cert_principal_next (const gf_key *k, size_t *pos, gf_slice *name)
{
  return k->cert != NULL && next_string (k->cert->principals, pos, name);
}

int
gf_cert_critical_next (const gf_key *k, size_t *pos, gf_slice *name,
                       gf_slice *data)
{
  return k->cert != NULL && next_pair (k->cert->critical, pos, name, data);
}

int
gf_cert_extension_next (const gf_key *k, size_t *pos, gf_slice *name,
                        gf_slice *data)
{
  return k->cert != NULL && next_pair (k->cert->extensions, pos, name, data);
}

int
gf_cert_has_extension (const gf_key *k, const char *name)
{
  size_t pos = 0;
  gf_slice n, d;

  while (k != NULL && name != NULL && gf_cert_extension_next (k, &pos, &n, &d))
    if (gf_slice_equals (n, name))
      return 1;
  return 0;
}

int
gf_cert_has_principal (const gf_key *k, const char *name, size_t n,
                       int wildcards)
{
  size_t pos = 0;
  gf_slice p;

  while (gf_cert_principal_next (k, &pos, &p))
    {
      if (wildcards ? gfi_wildmatch ((const char *) p.data, p.len, name, n)
                    : (p.len == n && memcmp (p.data, name, n) == 0))
        return 1;
    }
  return 0;
}

/* The value of a critical option is a string inside its data (or no data at
   all, for the options that are only flags).  */
static int
option_value (gf_slice data, gf_slice *value)
{
  gf_reader r;

  if (data.len == 0)
    {
      value->data = data.data;
      value->len = 0;
      return 1;
    }
  gf_reader_init (&r, data.data, data.len);
  return gf_rd_string (&r, value) == GF_OK && gf_rd_finish (&r) == GF_OK;
}

int
gf_cert_critical_option (const gf_key *k, const char *name, gf_slice *value)
{
  size_t pos = 0;
  gf_slice n, d;

  while (gf_cert_critical_next (k, &pos, &n, &d))
    if (gf_slice_equals (n, name))
      return option_value (d, value) ? 1 : -1;
  return 0;
}

/* One entry of a source-address list: an address, or an address and a
   prefix length (CIDR).  */
int
gfi_parse_cidr (const char *e, size_t n, int *family, uint8_t *addr,
                unsigned *bits)
{
  char buf[64];
  const char *slash = memchr (e, '/', n);
  size_t an = slash ? (size_t) (slash - e) : n;
  unsigned long len;

  if (an == 0 || an >= sizeof buf)
    return 0;
  memcpy (buf, e, an);
  buf[an] = '\0';
  if (inet_pton (AF_INET, buf, addr) == 1)
    {
      *family = AF_INET;
      *bits = 32;
    }
  else if (inet_pton (AF_INET6, buf, addr) == 1)
    {
      *family = AF_INET6;
      *bits = 128;
    }
  else
    return 0;
  if (slash)
    {
      size_t i;

      if (n - an - 1 == 0 || n - an - 1 > 3)
        return 0;
      for (len = 0, i = an + 1; i < n; i++)
        {
          if (e[i] < '0' || e[i] > '9')
            return 0;
          len = len * 10 + (unsigned long) (e[i] - '0');
        }
      if (len > *bits)
        return 0;
      *bits = (unsigned) len;
    }
  return 1;
}

int
gfi_prefix_equal (const uint8_t *a, const uint8_t *b, unsigned bits)
{
  unsigned whole = bits / 8, rest = bits % 8;

  if (memcmp (a, b, whole) != 0)
    return 0;
  return rest == 0
    || ((a[whole] ^ b[whole]) & (uint8_t) (0xff << (8 - rest))) == 0;
}

/* Walk the list.  -1 if any entry is malformed, else 1 if one of them
   contains the address (family PFAM, bytes PEER), else 0.  Every entry is
   read, so that a list that is wrong anywhere matches nothing.  */
static int
walk_list (gf_slice list, int pfam, const uint8_t *peer)
{
  size_t start = 0;
  int matched = 0;

  for (;;)
    {
      const uint8_t *comma = memchr (list.data + start, ',', list.len - start);
      size_t end = comma ? (size_t) (comma - list.data) : list.len;
      uint8_t a[16];
      int fam;
      unsigned bits;

      if (!gfi_parse_cidr ((const char *) list.data + start, end - start, &fam,
                           a, &bits))
        return -1;
      if (peer != NULL && fam == pfam && gfi_prefix_equal (a, peer, bits))
        matched = 1;
      if (comma == NULL)
        return matched;
      start = end + 1;
    }
}

/* The client's address as bytes, an IPv4-mapped one as the IPv4 address.  */
int
gfi_parse_peer (const char *address, int *family, uint8_t *peer)
{
  static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

  if (address == NULL)
    return 0;
  if (inet_pton (AF_INET, address, peer) == 1)
    *family = AF_INET;
  else if (inet_pton (AF_INET6, address, peer) == 1)
    {
      /* An IPv4 client on a dual-stack socket is still that IPv4 address.  */
      if (memcmp (peer, mapped, sizeof mapped) == 0)
        {
          memmove (peer, peer + 12, 4);
          *family = AF_INET;
        }
      else
        *family = AF_INET6;
    }
  else
    return 0;
  return 1;
}

int
gf_cert_source_address_ok (const gf_key *k, const char *address)
{
  gf_slice list;
  uint8_t peer[16];
  int pfam, found;

  found = gf_cert_critical_option (k, "source-address", &list);
  if (found == 0)
    return 1;
  /* Present but unreadable, or nothing to compare with: nobody.  */
  if (found < 0 || list.len == 0 || !gfi_parse_peer (address, &pfam, peer))
    return 0;
  return walk_list (list, pfam, peer) == 1;
}

int
gf_cert_check (const gf_key *k, int type, uint64_t now, const char **why)
{
  const char *w = NULL;
  size_t pos = 0;
  gf_slice name, data;

  if (k == NULL || k->cert == NULL)
    return GF_ERR_INVAL;
  if ((int) k->cert->type != type)
    w = type == GF_CERT_HOST ? "not a host certificate"
                             : "not a user certificate";
  else if (now < k->cert->valid_after)
    w = "not yet valid";
  else if (now >= k->cert->valid_before)
    w = "expired";
  else
    while (w == NULL && gf_cert_critical_next (k, &pos, &name, &data))
      {
        if (type == GF_CERT_HOST)
          w = "critical option on a host certificate";
        else if (!gf_slice_equals (name, "force-command")
                 && !gf_slice_equals (name, "source-address")
                 && !gf_slice_equals (name, "verify-required"))
          w = "unknown critical option";
        else
          {
            gf_slice v;

            if (!option_value (data, &v))
              w = "malformed critical option";
            else if (!gf_slice_equals (name, "verify-required") && v.len == 0)
              w = "empty critical option";
            else if (gf_slice_equals (name, "force-command")
                     && memchr (v.data, '\0', v.len) != NULL)
              w = "malformed critical option";
            else if (gf_slice_equals (name, "source-address")
                     && walk_list (v, 0, NULL) < 0)
              w = "malformed source-address";
          }
      }
  if (why)
    *why = w;
  return w ? GF_ERR_HOSTKEY : GF_OK;
}

int
gf_key_with_certificate (const gf_key *key, const gf_key *cert, gf_key **out)
{
  gf_key *k = NULL;
  int rc;

  if (key == NULL || cert == NULL || out == NULL || key->priv == NULL
      || key->cert != NULL || cert->cert == NULL)
    return GF_ERR_INVAL;
  if (cert->plainlen != key->bloblen
      || memcmp (cert->plain, key->blob, key->bloblen) != 0)
    return GF_ERR_INVAL;		/* The certificate is for another key.  */
  rc = gf_key_from_blob (&k, cert->blob, cert->bloblen);
  if (rc != GF_OK)
    return rc;
  k->priv = gcry_sexp_find_token (key->priv, "private-key", 0);
  if (k->priv == NULL)
    {
      gf_key_free (k);
      return GF_ERR_CRYPTO;
    }
  *out = k;
  return GF_OK;
}

/* ---- Making certificates ---- */

#define MAX_ID 255
#define MAX_PRINCIPALS 256
#define MAX_COMMAND 4096

/* Printable UTF-8, no controls, between 1 and MAX bytes.  */
static int
text_ok (const char *t, size_t max)
{
  size_t n, i;

  if (t == NULL)
    return 0;
  n = strlen (t);
  if (n == 0 || n > max || !gf_utf8_valid ((const uint8_t *) t, n))
    return 0;
  for (i = 0; i < n; i++)
    if ((unsigned char) t[i] < 0x20 || t[i] == 0x7f)
      return 0;
  return 1;
}

static int
addresses_ok (const char *list)
{
  size_t n = strlen (list), start = 0, i;

  if (!text_ok (list, MAX_COMMAND))
    return 0;
  for (i = 0; i <= n; i++)
    if (i == n || list[i] == ',')
      {
        uint8_t a[16];
        int fam;
        unsigned bits;

        if (!gfi_parse_cidr (list + start, i - start, &fam, a, &bits))
          return 0;
        start = i + 1;
      }
  return 1;
}

/* A critical option or extension whose data is the string VALUE (or empty,
   if VALUE is NULL).  */
static void
put_option (gf_writer *w, const char *name, const char *value)
{
  size_t m, d;

  gf_wr_string (w, name, strlen (name));
  m = gf_wr_string_begin (w);
  if (value != NULL)
    {
      d = gf_wr_string_begin (w);
      gf_wr_bytes (w, value, strlen (value));
      gf_wr_string_end (w, d);
    }
  gf_wr_string_end (w, m);
}

int
gf_cert_sign (gf_key **out, const gf_key *ca, const gf_key *subject,
              const gf_cert_spec *sp, enum gf_sigalg alg)
{
  /* The extensions in the order the format requires (by name).  */
  static const struct
  {
    const char *name;
    unsigned bit;
  } ext[] = {
    { GF_CERT_PERMIT_X11_FORWARDING, GF_CERT_ALLOW_X11_FORWARDING },
    { GF_CERT_PERMIT_AGENT_FORWARDING, GF_CERT_ALLOW_AGENT_FORWARDING },
    { GF_CERT_PERMIT_PORT_FORWARDING, GF_CERT_ALLOW_PORT_FORWARDING },
    { GF_CERT_PERMIT_PTY, GF_CERT_ALLOW_PTY },
    { GF_CERT_PERMIT_USER_RC, GF_CERT_ALLOW_USER_RC }
  };
  uint8_t sig[GF_SIG_MAX], nonce[32];
  const uint8_t *pb, *cb;
  size_t pl, cl, i, cap, m, signed_len, siglen, tl;
  const char *tname;
  char cname[128];
  gf_slice rd_type;
  gf_reader rd;
  gf_writer w;
  uint8_t *buf;
  size_t nalg;
  const enum gf_sigalg *algs;
  int rc;

  if (out == NULL)
    return GF_ERR_INVAL;
  *out = NULL;
  if (ca == NULL || subject == NULL || sp == NULL
      || gf_key_is_certificate (ca) || gf_key_is_certificate (subject)
      || (sp->type != GF_CERT_USER && sp->type != GF_CERT_HOST))
    return GF_ERR_INVAL;
  if (sp->serial == 0 || !text_ok (sp->key_id, MAX_ID)
      || sp->principals == NULL || sp->nprincipals == 0
      || sp->nprincipals > MAX_PRINCIPALS
      || sp->valid_before == UINT64_MAX || sp->valid_after >= sp->valid_before)
    return GF_ERR_INVAL;
  for (i = 0; i < sp->nprincipals; i++)
    if (!text_ok (sp->principals[i], MAX_ID))
      return GF_ERR_INVAL;
  if (sp->type == GF_CERT_HOST)
    {
      if (sp->allow != 0 || sp->force_command != NULL
          || sp->source_address != NULL || sp->verify_required)
        return GF_ERR_INVAL;
    }
  else if ((sp->allow & ~(unsigned) GF_CERT_ALLOW_ALL) != 0
           || (sp->force_command != NULL && !text_ok (sp->force_command, MAX_COMMAND))
           || (sp->source_address != NULL && !addresses_ok (sp->source_address)))
    return GF_ERR_INVAL;

  /* The algorithm: the CA's own first one, unless asked, and one it has.  */
  algs = gf_key_sigalgs (ca, &nalg);
  if (algs == NULL || nalg == 0)
    return GF_ERR_UNSUPPORTED;
  if (alg == 0)
    alg = algs[0];
  else
    {
      for (i = 0; i < nalg && algs[i] != alg; i++)
        ;
      if (i == nalg)
        return GF_ERR_UNSUPPORTED;
    }

  /* The certificate's type name is the key's with the suffix, and where the
     key's name ends in "@openssh.com" (security keys) that moves to the
     end of the suffix.  */
  tname = gf_key_type_name (subject);
  tl = strlen (tname);
  if (tl > sizeof "@openssh.com" - 1
      && strcmp (tname + tl - (sizeof "@openssh.com" - 1), "@openssh.com") == 0)
    tl -= sizeof "@openssh.com" - 1;
  if (tl + sizeof CERT_SUFFIX > sizeof cname)
    return GF_ERR_UNSUPPORTED;
  memcpy (cname, tname, tl);
  memcpy (cname + tl, CERT_SUFFIX, sizeof CERT_SUFFIX);
  tl += sizeof CERT_SUFFIX - 1;

  pb = gf_key_plain_blob (subject, &pl);
  cb = gf_key_blob (ca, &cl);
  if (pb == NULL || cb == NULL)
    return GF_ERR_INVAL;
  /* The key's blob minus its type name, which is how it is carried.  */
  gf_reader_init (&rd, pb, pl);
  if (gf_rd_string (&rd, &rd_type) != GF_OK)
    return GF_ERR_INVAL;
  rc = gf_random (nonce, sizeof nonce);
  if (rc != GF_OK)
    return rc;

  cap = tl + pl + cl + GF_SIG_MAX + 1024 + MAX_COMMAND * 2 + MAX_ID * 2;
  for (i = 0; i < sp->nprincipals; i++)
    cap += strlen (sp->principals[i]) + 4;
  buf = malloc (cap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, cap);
  gf_wr_string (&w, cname, tl);
  gf_wr_string (&w, nonce, sizeof nonce);
  gf_wr_bytes (&w, pb + (pl - gf_rd_remaining (&rd)), gf_rd_remaining (&rd));
  gf_wr_u64 (&w, sp->serial);
  gf_wr_u32 (&w, (uint32_t) sp->type);
  gf_wr_string (&w, sp->key_id, strlen (sp->key_id));
  m = gf_wr_string_begin (&w);
  for (i = 0; i < sp->nprincipals; i++)
    gf_wr_string (&w, sp->principals[i], strlen (sp->principals[i]));
  gf_wr_string_end (&w, m);
  gf_wr_u64 (&w, sp->valid_after);
  gf_wr_u64 (&w, sp->valid_before);
  /* Critical options, sorted by name: f, s, v.  */
  m = gf_wr_string_begin (&w);
  if (sp->force_command != NULL)
    put_option (&w, "force-command", sp->force_command);
  if (sp->source_address != NULL)
    put_option (&w, "source-address", sp->source_address);
  if (sp->verify_required)
    put_option (&w, "verify-required", NULL);
  gf_wr_string_end (&w, m);
  m = gf_wr_string_begin (&w);
  for (i = 0; i < sizeof ext / sizeof ext[0]; i++)
    if (sp->allow & ext[i].bit)
      put_option (&w, ext[i].name, NULL);
  gf_wr_string_end (&w, m);
  gf_wr_string (&w, "", 0);		/* Reserved.  */
  gf_wr_string (&w, cb, cl);
  signed_len = w.len;
  if (gf_wr_status (&w) != GF_OK)
    {
      free (buf);
      return GF_ERR_BUFSIZE;
    }
  rc = gf_key_sign (ca, alg, buf, signed_len, sig, sizeof sig, &siglen);
  if (rc != GF_OK)
    {
      free (buf);
      return rc;
    }
  gf_wr_string (&w, sig, siglen);
  if (gf_wr_status (&w) != GF_OK)
    {
      free (buf);
      return GF_ERR_BUFSIZE;
    }
  /* What was made is read back by the same code that reads anyone's: it
     checks the signature, the key and the structure.  */
  rc = gf_key_from_blob (out, buf, w.len);
  free (buf);
  return rc;
}
