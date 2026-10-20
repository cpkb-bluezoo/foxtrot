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

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/kexinit.h>

#include "tst-util.h"

struct lists
{
  const char *kex, *hostkey, *enc, *comp;
  int guess;
};

/* A KEXINIT as a peer would send it: same cipher list both ways.  */
static size_t
peer (uint8_t *buf, size_t cap, const struct lists *l)
{
  gf_writer w;
  uint8_t cookie[16];

  memset (cookie, 0xcc, sizeof cookie);
  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, GF_MSG_KEXINIT);
  gf_wr_bytes (&w, cookie, 16);
  gf_wr_namelist (&w, l->kex);
  gf_wr_namelist (&w, l->hostkey);
  gf_wr_namelist (&w, l->enc);
  gf_wr_namelist (&w, l->enc);
  gf_wr_namelist (&w, "hmac-sha2-256-etm@openssh.com,hmac-sha2-512");
  gf_wr_namelist (&w, "hmac-sha2-256-etm@openssh.com,hmac-sha2-512");
  gf_wr_namelist (&w, l->comp);
  gf_wr_namelist (&w, l->comp);
  gf_wr_namelist (&w, "");
  gf_wr_namelist (&w, "");
  gf_wr_bool (&w, l->guess);
  gf_wr_u32 (&w, 0);
  return gf_wr_status (&w) == GF_OK ? w.len : 0;
}

static int
negotiate (const struct lists *c, const struct lists *s, int initial,
           struct gf_algs *out)
{
  uint8_t cb[2048], sb[2048];
  struct gf_kexinit ci, si;
  size_t cn = peer (cb, sizeof cb, c), sn = peer (sb, sizeof sb, s);

  CHECK (cn && sn);
  CHECK_EQ (gf_kexinit_parse (cb, cn, &ci), GF_OK);
  CHECK_EQ (gf_kexinit_parse (sb, sn, &si), GF_OK);
  return gf_kexinit_negotiate (&ci, &si, initial, out);
}

/* What OpenSSH 9.6 offers, from ssh -vv.  */
static const struct lists openssh96 = {
  "sntrup761x25519-sha512@openssh.com,curve25519-sha256,"
  "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,"
  "ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,"
  "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
  "diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com",
  "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,"
  "rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,"
  "ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256",
  "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,"
  "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
  "none,zlib@openssh.com", 0
};

/* Ours as a server.  */
static size_t
ours (uint8_t *buf, size_t cap, int server, int initial,
      const struct gf_kex_prefs *prefs)
{
  size_t n;

  CHECK_EQ (gf_kexinit_make (buf, cap, &n, server, initial, prefs), GF_OK);
  return n;
}

static void
test_make_and_parse (void)
{
  uint8_t buf[2048], buf2[2048];
  struct gf_kexinit k;
  size_t n = ours (buf, sizeof buf, 0, 1, NULL), n2;

  CHECK_EQ (gf_kexinit_parse (buf, n, &k), GF_OK);
  CHECK (gf_namelist_contains (k.kex, "mlkem768x25519-sha256"));
  CHECK (gf_namelist_contains (k.kex, "sntrup761x25519-sha512"));
  CHECK (gf_namelist_contains (k.kex, "sntrup761x25519-sha512@openssh.com"));
  CHECK (gf_namelist_contains (k.kex, "curve25519-sha256"));
  CHECK (gf_namelist_contains (k.kex, "kex-strict-c-v00@openssh.com"));
  CHECK (gf_namelist_contains (k.kex, "ext-info-c"));
  CHECK (!gf_namelist_contains (k.kex, "kex-strict-s-v00@openssh.com"));
  CHECK (!gf_namelist_contains (k.kex, "diffie-hellman-group14-sha256"));
  CHECK (!gf_namelist_contains (k.kex, "curve25519-sha256@libssh.org"));
  CHECK (gf_namelist_contains (k.hostkey, "ssh-ed25519"));
  CHECK (gf_namelist_contains (k.hostkey, "rsa-sha2-256"));
  CHECK (!gf_namelist_contains (k.hostkey, "ssh-rsa"));
  CHECK (gf_namelist_contains (k.enc_c2s, "chacha20-poly1305@openssh.com"));
  CHECK (!gf_namelist_contains (k.enc_c2s, "aes128-ctr"));
  CHECK_EQ (k.mac_c2s.len, 0);
  CHECK (gf_slice_equals (k.comp_s2c, "none"));
  CHECK (!k.first_kex_follows);

  /* Not the first exchange: no markers.  */
  n2 = ours (buf2, sizeof buf2, 1, 0, NULL);
  CHECK_EQ (gf_kexinit_parse (buf2, n2, &k), GF_OK);
  CHECK (!gf_namelist_contains (k.kex, "kex-strict-s-v00@openssh.com"));
  CHECK (!gf_namelist_contains (k.kex, "ext-info-s"));
  /* Cookies are random.  */
  CHECK (memcmp (buf + 1, buf2 + 1, 16) != 0);

  /* Every prefix of a KEXINIT, and one with a byte too many, is refused.  */
  for (n2 = 0; n2 < n; n2++)
    CHECK_EQ (gf_kexinit_parse (buf, n2, &k), GF_ERR_ENCODING);
  buf[n] = 0;
  CHECK_EQ (gf_kexinit_parse (buf, n + 1, &k), GF_ERR_ENCODING);
  buf[0] = 21;
  CHECK_EQ (gf_kexinit_parse (buf, n, &k), GF_ERR_ENCODING);
}

static void
test_make_prefs (void)
{
  uint8_t buf[2048];
  struct gf_kexinit k;
  static const enum gf_kex kx[] = { GF_KEX_CURVE25519_SHA256 };
  static const enum gf_sigalg sg[] = { GF_SIG_ED25519 };
  static const enum gf_cipher ci[] = { GF_CIPHER_AES256_GCM };
  struct gf_kex_prefs p = { kx, 1, sg, 1, ci, 1 };
  size_t n;

  n = ours (buf, sizeof buf, 0, 1, &p);
  CHECK_EQ (gf_kexinit_parse (buf, n, &k), GF_OK);
  CHECK (gf_namelist_contains (k.kex, "curve25519-sha256"));
  CHECK (!gf_namelist_contains (k.kex, "mlkem768x25519-sha256"));
  CHECK (gf_slice_equals (k.hostkey, "ssh-ed25519"));
  CHECK (gf_slice_equals (k.enc_c2s, "aes256-gcm@openssh.com"));

  /* Values outside the policy are refused; empty lists too.  */
  {
    static const enum gf_kex bad[] = { (enum gf_kex) 99 };
    static const enum gf_cipher badc[] = { GF_CIPHER_NONE };
    struct gf_kex_prefs b1 = { bad, 1, NULL, 0, NULL, 0 };
    struct gf_kex_prefs b2 = { NULL, 0, NULL, 0, badc, 1 };
    struct gf_kex_prefs b3 = { kx, 0, sg, 1, ci, 1 };

    CHECK_EQ (gf_kexinit_make (buf, sizeof buf, &n, 0, 1, &b1),
              GF_ERR_UNSUPPORTED);
    CHECK_EQ (gf_kexinit_make (buf, sizeof buf, &n, 0, 1, &b2),
              GF_ERR_UNSUPPORTED);
    CHECK_EQ (gf_kexinit_make (buf, sizeof buf, &n, 0, 1, &b3), GF_ERR_INVAL);
  }
  CHECK_EQ (gf_kexinit_make (buf, 100, &n, 0, 1, NULL), GF_ERR_BUFSIZE);
}

static void
test_negotiate_defaults (void)
{
  uint8_t cb[2048], sb[2048];
  struct gf_kexinit c, s;
  struct gf_algs a;
  size_t cn = ours (cb, sizeof cb, 0, 1, NULL);
  size_t sn = ours (sb, sizeof sb, 1, 1, NULL);

  CHECK_EQ (gf_kexinit_parse (cb, cn, &c), GF_OK);
  CHECK_EQ (gf_kexinit_parse (sb, sn, &s), GF_OK);
  CHECK_EQ (gf_kexinit_negotiate (&c, &s, 1, &a), GF_OK);
  CHECK_EQ (a.kex, GF_KEX_MLKEM768X25519_SHA256);
  CHECK_EQ (a.hostkey, GF_SIG_ED25519);
  CHECK_EQ (a.c2s, GF_CIPHER_CHACHA20_POLY1305);
  CHECK_EQ (a.s2c, GF_CIPHER_CHACHA20_POLY1305);
  CHECK (a.ext_info);
}

static void
test_negotiate_openssh (void)
{
  struct gf_algs a;
  uint8_t cb[2048], sb[2048];
  struct gf_kexinit c, s;
  size_t sn = ours (sb, sizeof sb, 1, 1, NULL), cn;

  /* An OpenSSH 9.6 client against us: the sntrup hybrid under the name it
     knows, the first of its ciphers that we also have.  */
  cn = peer (cb, sizeof cb, &openssh96);
  CHECK_EQ (gf_kexinit_parse (cb, cn, &c), GF_OK);
  CHECK_EQ (gf_kexinit_parse (sb, sn, &s), GF_OK);
  CHECK_EQ (gf_kexinit_negotiate (&c, &s, 1, &a), GF_OK);
  CHECK_EQ (a.kex, GF_KEX_SNTRUP761X25519_SHA512);
  CHECK_EQ (a.hostkey, GF_SIG_ED25519);
  CHECK_EQ (a.c2s, GF_CIPHER_CHACHA20_POLY1305);
  CHECK (a.ext_info);

  /* The same client without the sntrup hybrid: curve25519-sha256.  */
  {
    struct lists l = openssh96;

    l.kex = "curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com";
    l.hostkey = "rsa-sha2-256,ssh-ed25519";
    l.enc = "aes128-gcm@openssh.com,aes256-gcm@openssh.com";
    CHECK_EQ (negotiate (&l, &(struct lists) {
                "mlkem768x25519-sha256,curve25519-sha256,"
                "kex-strict-s-v00@openssh.com",
                "ssh-ed25519,rsa-sha2-256", "aes256-gcm@openssh.com",
                "none", 0 }, 1, &a), GF_OK);
    CHECK_EQ (a.kex, GF_KEX_CURVE25519_SHA256);
    /* The client's order wins over the server's, among what both have.  */
    CHECK_EQ (a.hostkey, GF_SIG_RSA_SHA2_256);
    CHECK_EQ (a.c2s, GF_CIPHER_AES256_GCM);
  }
}

static void
test_negotiate_refusals (void)
{
  struct gf_algs a;
  struct lists good = {
    "curve25519-sha256,kex-strict-c-v00@openssh.com", "ssh-ed25519",
    "chacha20-poly1305@openssh.com", "none", 0
  };
  struct lists sgood = {
    "curve25519-sha256,kex-strict-s-v00@openssh.com", "ssh-ed25519",
    "chacha20-poly1305@openssh.com", "none", 0
  };
  struct lists c, s;

  CHECK_EQ (negotiate (&good, &sgood, 1, &a), GF_OK);
  CHECK (!a.ext_info);

  /* Only legacy algorithms in common: nothing is negotiated, whatever
     the lists say.  */
  c = good;
  s = sgood;
  c.kex = "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,"
          "diffie-hellman-group-exchange-sha256,kex-strict-c-v00@openssh.com";
  s.kex = "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,"
          "diffie-hellman-group-exchange-sha256,kex-strict-s-v00@openssh.com";
  CHECK_EQ (negotiate (&c, &s, 1, &a), GF_ERR_UNSUPPORTED);
  c = good;
  s = sgood;
  c.hostkey = s.hostkey = "ssh-rsa,ssh-dss,ecdsa-sha2-nistp521";
  CHECK_EQ (negotiate (&c, &s, 1, &a), GF_ERR_UNSUPPORTED);
  c = good;
  s = sgood;
  c.enc = s.enc = "aes128-cbc,aes256-ctr,3des-cbc,aes128-ctr,arcfour";
  CHECK_EQ (negotiate (&c, &s, 1, &a), GF_ERR_UNSUPPORTED);
  /* A legacy name first does not stop a modern one after it.  */
  c = good;
  c.enc = "aes128-ctr,chacha20-poly1305@openssh.com";
  c.kex = "diffie-hellman-group14-sha1,curve25519-sha256,"
          "kex-strict-c-v00@openssh.com";
  CHECK_EQ (negotiate (&c, &sgood, 1, &a), GF_OK);
  CHECK_EQ (a.kex, GF_KEX_CURVE25519_SHA256);
  /* Prefix of a name is not the name.  */
  c = good;
  c.enc = "chacha20-poly1305";
  CHECK_EQ (negotiate (&c, &sgood, 1, &a), GF_ERR_UNSUPPORTED);

  /* Strict key exchange is required in the first exchange.  */
  c = good;
  c.kex = "curve25519-sha256";
  CHECK_EQ (negotiate (&c, &sgood, 1, &a), GF_ERR_PROTOCOL);
  s = sgood;
  s.kex = "curve25519-sha256";
  CHECK_EQ (negotiate (&good, &s, 1, &a), GF_ERR_PROTOCOL);
  /* The wrong side's marker does not count.  */
  s.kex = "curve25519-sha256,kex-strict-c-v00@openssh.com";
  CHECK_EQ (negotiate (&good, &s, 1, &a), GF_ERR_PROTOCOL);
  /* But a later exchange has no marker.  */
  c.kex = s.kex = "curve25519-sha256";
  CHECK_EQ (negotiate (&c, &s, 0, &a), GF_OK);

  /* Compression the peer insists on.  */
  c = good;
  c.comp = "zlib@openssh.com";
  CHECK_EQ (negotiate (&c, &sgood, 1, &a), GF_ERR_UNSUPPORTED);
  c.comp = "zlib@openssh.com,none";
  CHECK_EQ (negotiate (&c, &sgood, 1, &a), GF_OK);

  /* A guessed first packet.  */
  c = good;
  c.guess = 1;
  CHECK_EQ (negotiate (&c, &sgood, 1, &a), GF_ERR_PROTOCOL);
  s = sgood;
  s.guess = 1;
  CHECK_EQ (negotiate (&good, &s, 1, &a), GF_ERR_PROTOCOL);
}

int
main (void)
{
  gf_crypto_init ();
  test_make_and_parse ();
  test_make_prefs ();
  test_negotiate_defaults ();
  test_negotiate_openssh ();
  test_negotiate_refusals ();
  TST_DONE ();
}
