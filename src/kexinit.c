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

#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/kexinit.h>

int
gf_kexinit_parse (const uint8_t *payload, size_t len, struct gf_kexinit *out)
{
  gf_reader r;
  gf_slice cookie;
  uint8_t type;
  uint32_t reserved;

  gf_reader_init (&r, payload, len);
  if (gf_rd_u8 (&r, &type) != GF_OK || type != GF_MSG_KEXINIT
      || gf_rd_bytes (&r, 16, &cookie) != GF_OK)
    return GF_ERR_ENCODING;
  memcpy (out->cookie, cookie.data, 16);
  if (gf_rd_namelist (&r, &out->kex) != GF_OK
      || gf_rd_namelist (&r, &out->hostkey) != GF_OK
      || gf_rd_namelist (&r, &out->enc_c2s) != GF_OK
      || gf_rd_namelist (&r, &out->enc_s2c) != GF_OK
      || gf_rd_namelist (&r, &out->mac_c2s) != GF_OK
      || gf_rd_namelist (&r, &out->mac_s2c) != GF_OK
      || gf_rd_namelist (&r, &out->comp_c2s) != GF_OK
      || gf_rd_namelist (&r, &out->comp_s2c) != GF_OK
      || gf_rd_namelist (&r, &out->lang_c2s) != GF_OK
      || gf_rd_namelist (&r, &out->lang_s2c) != GF_OK
      || gf_rd_bool (&r, &out->first_kex_follows) != GF_OK
      || gf_rd_u32 (&r, &reserved) != GF_OK)	/* Reserved: ignored.  */
    return GF_ERR_ENCODING;
  return gf_rd_finish (&r);
}

/* ------------------------------------------------------------------ */
/* Making ours                                                        */
/* ------------------------------------------------------------------ */

#define LIST_MAX 1024

/* Append S to the comma list in BUF.  */
static int
append (char *buf, size_t *n, const char *s)
{
  size_t l = strlen (s);

  if (*n + l + 2 > LIST_MAX)
    return GF_ERR_BUFSIZE;
  if (*n > 0)
    buf[(*n)++] = ',';
  memcpy (buf + *n, s, l);
  *n += l;
  buf[*n] = '\0';
  return GF_OK;
}

int
gf_kexinit_make (uint8_t *buf, size_t cap, size_t *len, int server,
                 int initial, const struct gf_kex_prefs *prefs)
{
  static const struct gf_kex_prefs none;
  const enum gf_kex *kex;
  const enum gf_sigalg *sig;
  const enum gf_cipher *ciph;
  size_t nk, ns, nc, i, n;
  char list[LIST_MAX + 1];
  uint8_t cookie[16];
  gf_writer w;
  int r;

  if (buf == NULL || len == NULL)
    return GF_ERR_INVAL;
  if (prefs == NULL)
    prefs = &none;
  kex = prefs->kex;
  nk = prefs->nkex;
  if (kex == NULL)
    kex = gf_policy_default_kex (&nk);
  sig = prefs->sigalgs;
  ns = prefs->nsigalgs;
  if (sig == NULL)
    sig = gf_policy_default_sigalgs (&ns);
  ciph = prefs->ciphers;
  nc = prefs->nciphers;
  if (ciph == NULL)
    ciph = gf_policy_default_ciphers (&nc);
  if (nk == 0 || ns == 0 || nc == 0)
    return GF_ERR_INVAL;
  r = gf_random (cookie, sizeof cookie);
  if (r != GF_OK)
    return r;

  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, GF_MSG_KEXINIT);
  gf_wr_bytes (&w, cookie, sizeof cookie);

  n = 0;
  list[0] = '\0';
  for (i = 0; i < nk; i++)
    {
      const char *names = gf_kex_names (kex[i]);

      if (names == NULL)
        return GF_ERR_UNSUPPORTED;
      if ((r = append (list, &n, names)) != GF_OK)
        return r;
    }
  if (initial)
    {
      r = append (list, &n, server ? GF_KEX_EXTINFO_SERVER
                                   : GF_KEX_EXTINFO_CLIENT);
      if (r == GF_OK)
        r = append (list, &n, server ? GF_KEX_STRICT_SERVER
                                     : GF_KEX_STRICT_CLIENT);
      if (r != GF_OK)
        return r;
    }
  gf_wr_namelist (&w, list);

  n = 0;
  list[0] = '\0';
  for (i = 0; i < ns; i++)
    {
      const char *name = gf_sigalg_name (sig[i]);

      /* A security key signs on a token for a user; a host has none.  */
      if (name == NULL || gf_sigalg_is_user_only (sig[i]))
        return GF_ERR_UNSUPPORTED;
      if ((r = append (list, &n, name)) != GF_OK)
        return r;
    }
  gf_wr_namelist (&w, list);

  n = 0;
  list[0] = '\0';
  for (i = 0; i < nc; i++)
    {
      const char *name = gf_cipher_name (ciph[i]);

      if (name == NULL)
        return GF_ERR_UNSUPPORTED;
      if ((r = append (list, &n, name)) != GF_OK)
        return r;
    }
  gf_wr_namelist (&w, list);		/* Client to server.  */
  gf_wr_namelist (&w, list);		/* Server to client.  */

  gf_wr_namelist (&w, "");		/* MACs: none, AEAD only.  */
  gf_wr_namelist (&w, "");
  gf_wr_namelist (&w, "none");		/* Compression.  */
  gf_wr_namelist (&w, "none");
  gf_wr_namelist (&w, "");		/* Languages.  */
  gf_wr_namelist (&w, "");
  gf_wr_bool (&w, 0);			/* No guessed packet.  */
  gf_wr_u32 (&w, 0);

  if (gf_wr_status (&w) != GF_OK)
    return GF_ERR_BUFSIZE;
  *len = w.len;
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Negotiation                                                        */
/* ------------------------------------------------------------------ */

/* The first name of CLIENT that policy knows (via FROM) and SERVER also
   lists.  Returns the value, 0 if none.  */
static unsigned
pick (gf_slice client, gf_slice server,
      unsigned (*from) (const char *, size_t))
{
  gf_slice n;

  while (gf_namelist_next (&client, &n))
    {
      unsigned v = from ((const char *) n.data, n.len);

      if (v != 0 && gf_namelist_has (server, n))
        return v;
    }
  return 0;
}

static unsigned
kex_from (const char *s, size_t n)
{
  return (unsigned) gf_kex_from_name (s, n);
}

static unsigned
sig_from (const char *s, size_t n)
{
  enum gf_sigalg a = gf_sigalg_from_name (s, n);

  return gf_sigalg_is_user_only (a) ? 0 : (unsigned) a;
}

static unsigned
cipher_from (const char *s, size_t n)
{
  return (unsigned) gf_cipher_from_name (s, n);
}

int
gf_kexinit_negotiate (const struct gf_kexinit *c, const struct gf_kexinit *s,
                      int initial, struct gf_algs *out)
{
  if (c == NULL || s == NULL || out == NULL)
    return GF_ERR_INVAL;
  memset (out, 0, sizeof *out);

  /* A guess would let a peer send a key exchange message ahead of
     agreement; we never do, and do not take it.  */
  if (c->first_kex_follows || s->first_kex_follows)
    return GF_ERR_PROTOCOL;

  if (initial)
    {
      if (!gf_namelist_contains (c->kex, GF_KEX_STRICT_CLIENT)
          || !gf_namelist_contains (s->kex, GF_KEX_STRICT_SERVER))
        return GF_ERR_PROTOCOL;
      out->ext_info = gf_namelist_contains (c->kex, GF_KEX_EXTINFO_CLIENT);
    }

  out->kex = (enum gf_kex) pick (c->kex, s->kex, kex_from);
  out->hostkey = (enum gf_sigalg) pick (c->hostkey, s->hostkey, sig_from);
  out->c2s = (enum gf_cipher) pick (c->enc_c2s, s->enc_c2s, cipher_from);
  out->s2c = (enum gf_cipher) pick (c->enc_s2c, s->enc_s2c, cipher_from);
  if (out->kex == 0 || out->hostkey == 0 || out->c2s == 0 || out->s2c == 0)
    return GF_ERR_UNSUPPORTED;

  /* No compression: both ends must list "none" in both directions.  */
  if (!gf_namelist_contains (c->comp_c2s, "none")
      || !gf_namelist_contains (s->comp_c2s, "none")
      || !gf_namelist_contains (c->comp_s2c, "none")
      || !gf_namelist_contains (s->comp_s2c, "none"))
    return GF_ERR_UNSUPPORTED;
  return GF_OK;
}
