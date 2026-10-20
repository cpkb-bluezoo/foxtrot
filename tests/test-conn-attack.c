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

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/conn.h>
#include <foxtrot/ident.h>
#include <foxtrot/packet.h>
#include <foxtrot/kex.h>

#include "tst-pair.h"

/* A scripted peer for a connection under test: it sends exactly what a
   test wants, plaintext, as a client (against our server).  */

static gf_key *hostkey;

struct lists
{
  const char *kex, *hostkey, *enc, *comp;
  int guess;
};

static const struct lists good_client = {
  "curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com",
  "ssh-ed25519,rsa-sha2-512", "chacha20-poly1305@openssh.com", "none", 0
};

static size_t
kexinit_payload (uint8_t *buf, size_t cap, const struct lists *l)
{
  gf_writer w;
  uint8_t cookie[16];

  memset (cookie, 0x5a, sizeof cookie);
  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, 20);
  gf_wr_bytes (&w, cookie, 16);
  gf_wr_namelist (&w, l->kex);
  gf_wr_namelist (&w, l->hostkey);
  gf_wr_namelist (&w, l->enc);
  gf_wr_namelist (&w, l->enc);
  gf_wr_namelist (&w, "");
  gf_wr_namelist (&w, "");
  gf_wr_namelist (&w, l->comp);
  gf_wr_namelist (&w, l->comp);
  gf_wr_namelist (&w, "");
  gf_wr_namelist (&w, "");
  gf_wr_bool (&w, l->guess);
  gf_wr_u32 (&w, 0);
  return w.len;
}

struct script
{
  struct end sv;
  gf_packet out;			/* The scripted peer's sending state.  */
};

static void
script_new (struct script *s)
{
  gf_conn_config sc;
  gf_conn_events ev;

  memset (s, 0, sizeof *s);
  memset (&sc, 0, sizeof sc);
  sc.host_keys = &hostkey;
  sc.nhost_keys = 1;
  ev = end_events (&s->sv);
  s->sv.is_server = 1;
  CHECK_EQ (gf_conn_server_new (&s->sv.c, &sc, &ev), GF_OK);
  CHECK_EQ (gf_conn_start (s->sv.c, tst_now), GF_OK);
  gf_packet_init (&s->out);
}

static int
send_raw (struct script *s, const void *data, size_t n)
{
  return gf_conn_receive (s->sv.c, tst_now, data, n);
}

static int
send_ident (struct script *s, const char *line)
{
  return send_raw (s, line, strlen (line));
}

static int
send_payload (struct script *s, const uint8_t *p, size_t n)
{
  uint8_t out[GF_MAX_PACKET];
  size_t outlen;

  CHECK_EQ (gf_packet_send (&s->out, p, n, out, sizeof out, &outlen), GF_OK);
  return send_raw (s, out, outlen);
}

static int
send_kexinit (struct script *s, const struct lists *l)
{
  uint8_t buf[2048];

  return send_payload (s, buf, kexinit_payload (buf, sizeof buf, l));
}

/* The message types the server wrote, in order, and the reason of its
   DISCONNECT, if any.  */
struct seen
{
  int types[16];
  size_t n;
  uint32_t reason;
  uint32_t unimpl_seq;
};

static int
note (void *user, const uint8_t *p, size_t n)
{
  struct seen *s = user;

  if (s->n < 16)
    s->types[s->n++] = p[0];
  if (p[0] == 1 && n >= 5)
    s->reason = (uint32_t) p[1] << 24 | p[2] << 16 | p[3] << 8 | p[4];
  if (p[0] == 3 && n >= 5)
    s->unimpl_seq = (uint32_t) p[1] << 24 | p[2] << 16 | p[3] << 8 | p[4];
  return 0;
}

static struct seen
read_output (struct end *e)
{
  struct seen s;
  gf_packet in;
  uint8_t *b = e->out.buf;
  size_t len = e->out.len, i = 0;

  memset (&s, 0, sizeof s);
  gf_packet_init (&in);
  /* The identification line first.  */
  while (i < len && b[i] != '\n')
    i++;
  i++;
  b += i;
  len -= i < len ? i : len;
  (void) gf_packet_receive (&in, &b, &len, note, &s);
  e->out.len = 0;
  return s;
}

static int
has (const struct seen *s, int type)
{
  size_t i;

  for (i = 0; i < s->n; i++)
    if (s->types[i] == type)
      return 1;
  return 0;
}

static void
script_free (struct script *s)
{
  end_clear (&s->sv);
}

#define IDENT "SSH-2.0-scripted\r\n"

/* The server must close, with a DISCONNECT of REASON, and then refuse
   everything.  */
static void
expect_refused (struct script *s, uint32_t reason, int status)
{
  struct seen seen = read_output (&s->sv);

  CHECK_EQ (s->sv.closed, 1);
  CHECK_EQ (s->sv.close_error, status);
  CHECK (has (&seen, 1));
  CHECK_EQ (seen.reason, reason);
  CHECK_EQ (s->sv.established, 0);
  CHECK_EQ (send_raw (s, "xxxx", 4) != GF_OK, 1);
}

static void
test_strict_kex_required (void)
{
  struct script s;
  struct lists l = good_client;

  /* No marker.  */
  script_new (&s);
  l.kex = "curve25519-sha256,ext-info-c";
  CHECK_EQ (send_ident (&s, IDENT), GF_OK);
  CHECK (send_kexinit (&s, &l) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_PROTOCOL);
  script_free (&s);

  /* The server's marker from a client does not count.  */
  script_new (&s);
  l.kex = "curve25519-sha256,kex-strict-s-v00@openssh.com";
  send_ident (&s, IDENT);
  CHECK (send_kexinit (&s, &l) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_PROTOCOL);
  script_free (&s);

  /* The good one proceeds as far as waiting for ECDH_INIT.  */
  script_new (&s);
  CHECK_EQ (send_ident (&s, IDENT), GF_OK);
  CHECK_EQ (send_kexinit (&s, &good_client), GF_OK);
  CHECK_EQ (s.sv.closed, 0);
  script_free (&s);
}

/* Terrapin (CVE-2023-48795): extra packets in the initial exchange, which
   the attacker can inject or delete because the sequence numbers are not
   yet authenticated, must end the connection.  */
static void
test_terrapin (void)
{
  static const uint8_t ignore[] = { 2, 0, 0, 0, 0 };
  static const uint8_t debug[] = { 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  static const uint8_t unimpl[] = { 3, 0, 0, 0, 1 };
  struct script s;
  size_t i;

  /* Before the peer's KEXINIT.  */
  for (i = 0; i < 3; i++)
    {
      const uint8_t *m = i == 0 ? ignore : i == 1 ? debug : unimpl;
      size_t n = i == 0 ? sizeof ignore : i == 1 ? sizeof debug : sizeof unimpl;

      script_new (&s);
      send_ident (&s, IDENT);
      CHECK (send_payload (&s, m, n) != GF_OK);
      expect_refused (&s, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
      script_free (&s);
    }
  /* Between the KEXINIT and the key exchange message.  */
  for (i = 0; i < 3; i++)
    {
      const uint8_t *m = i == 0 ? ignore : i == 1 ? debug : unimpl;
      size_t n = i == 0 ? sizeof ignore : i == 1 ? sizeof debug : sizeof unimpl;

      script_new (&s);
      send_ident (&s, IDENT);
      CHECK_EQ (send_kexinit (&s, &good_client), GF_OK);
      CHECK (send_payload (&s, m, n) != GF_OK);
      expect_refused (&s, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
      script_free (&s);
    }
  /* Anything else than KEXINIT first, such as an init or NEWKEYS, or a
     service request.  */
  {
    static const uint8_t newkeys[] = { 21 };
    static const uint8_t init[] = { 30, 0, 0, 0, 32, 1, 2, 3, 4, 5, 6, 7, 8,
                                    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
                                    7, 8, 1, 2, 3, 4 };
    static const uint8_t svc[] = { 5, 0, 0, 0, 12, 's', 's', 'h', '-', 'u',
                                   's', 'e', 'r', 'a', 'u', 't', 'h' };
    static const uint8_t data[] = { 94, 0, 0, 0, 0 };

    for (i = 0; i < 4; i++)
      {
        const uint8_t *m = i == 0 ? newkeys : i == 1 ? init : i == 2 ? svc
                                                                     : data;
        size_t n = i == 0 ? sizeof newkeys : i == 1 ? sizeof init
                   : i == 2 ? sizeof svc : sizeof data;

        script_new (&s);
        send_ident (&s, IDENT);
        CHECK (send_payload (&s, m, n) != GF_OK);
        expect_refused (&s, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
        script_free (&s);
      }
    /* Same, after the KEXINIT: NEWKEYS before keys, a second KEXINIT, a
       service request, application data.  */
    for (i = 0; i < 3; i++)
      {
        const uint8_t *m = i == 0 ? newkeys : i == 1 ? svc : data;
        size_t n = i == 0 ? sizeof newkeys : i == 1 ? sizeof svc : sizeof data;

        script_new (&s);
        send_ident (&s, IDENT);
        send_kexinit (&s, &good_client);
        CHECK (send_payload (&s, m, n) != GF_OK);
        expect_refused (&s, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
        script_free (&s);
      }
    script_new (&s);
    send_ident (&s, IDENT);
    send_kexinit (&s, &good_client);
    CHECK (send_kexinit (&s, &good_client) != GF_OK);
    expect_refused (&s, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
    script_free (&s);
  }
}

static void
test_negotiation_refusals (void)
{
  struct script s;
  struct lists l;

  l = good_client;
  l.kex = "diffie-hellman-group14-sha256,kex-strict-c-v00@openssh.com";
  script_new (&s);
  send_ident (&s, IDENT);
  CHECK (send_kexinit (&s, &l) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_UNSUPPORTED);
  script_free (&s);

  l = good_client;
  l.enc = "aes256-ctr,aes128-cbc";
  script_new (&s);
  send_ident (&s, IDENT);
  CHECK (send_kexinit (&s, &l) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_UNSUPPORTED);
  script_free (&s);

  l = good_client;
  l.hostkey = "ssh-rsa,ssh-dss";
  script_new (&s);
  send_ident (&s, IDENT);
  CHECK (send_kexinit (&s, &l) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_UNSUPPORTED);
  script_free (&s);

  l = good_client;
  l.guess = 1;
  script_new (&s);
  send_ident (&s, IDENT);
  CHECK (send_kexinit (&s, &l) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_PROTOCOL);
  script_free (&s);

  /* The server has only an Ed25519 key, so an RSA-only client fails.  */
  l = good_client;
  l.hostkey = "rsa-sha2-512,rsa-sha2-256";
  script_new (&s);
  send_ident (&s, IDENT);
  CHECK (send_kexinit (&s, &l) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_UNSUPPORTED);
  script_free (&s);

  /* A malformed KEXINIT.  */
  {
    uint8_t buf[2048];
    size_t n = kexinit_payload (buf, sizeof buf, &good_client);

    script_new (&s);
    send_ident (&s, IDENT);
    CHECK (send_payload (&s, buf, n - 3) != GF_OK);
    expect_refused (&s, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
    script_free (&s);
  }
}

static void
test_identification (void)
{
  static const char *const bad[] = {
    "SSH-1.99-old\r\n", "SSH-1.5-old\r\n", "SSH-2.0-x\n", "HTTP/1.1 200 OK\r\n",
    "SSH-2.0\r\n", "\r\nSSH-2.0-x\r\n"
  };
  size_t i;

  for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      struct script s;

      script_new (&s);
      CHECK (send_ident (&s, bad[i]) != GF_OK);
      CHECK_EQ (s.sv.closed, 1);
      CHECK_EQ (s.sv.established, 0);
      script_free (&s);
    }
}

static size_t
ecdh_init (uint8_t *buf, size_t cap, const uint8_t *q, size_t qlen)
{
  gf_writer w;

  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, 30);
  gf_wr_string (&w, q, qlen);
  return w.len;
}

static void
test_bad_ecdh_value (void)
{
  uint8_t m[64], q[32];
  struct script s;
  size_t n;

  /* The all-zero point: a low-order X25519 value, which would give the
     all-zero shared secret.  */
  memset (q, 0, sizeof q);
  n = ecdh_init (m, sizeof m, q, 32);
  script_new (&s);
  send_ident (&s, IDENT);
  send_kexinit (&s, &good_client);
  CHECK (send_payload (&s, m, n) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_CRYPTO);
  script_free (&s);

  /* The wrong length.  */
  n = ecdh_init (m, sizeof m, q, 5);
  script_new (&s);
  send_ident (&s, IDENT);
  send_kexinit (&s, &good_client);
  CHECK (send_payload (&s, m, n) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_KEY_EXCHANGE_FAILED, GF_ERR_PROTOCOL);
  script_free (&s);
}

static void
test_oversize_and_garbage (void)
{
  struct script s;
  uint8_t junk[64];

  /* A first packet announcing 2 GB, or random bytes: refused at once.  */
  script_new (&s);
  send_ident (&s, IDENT);
  CHECK (send_raw (&s, "\x7f\xff\xff\xff", 4) != GF_OK);
  expect_refused (&s, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
  script_free (&s);

  script_new (&s);
  send_ident (&s, IDENT);
  memset (junk, 0xa5, sizeof junk);
  CHECK (send_raw (&s, junk, sizeof junk) != GF_OK);
  CHECK_EQ (s.sv.closed, 1);
  script_free (&s);
}

/* After the keys are in use: a flipped bit ends the connection, an
   unknown message is answered with its sequence number, and a message
   that must not arrive does not.  */
static void
test_established_attacks (void)
{
  struct pair p;
  gf_conn_config cc, sc;
  uint8_t m[40];
  size_t n;

  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  sc.host_keys = &hostkey;
  sc.nhost_keys = 1;

  /* Flip a bit in a data packet.  */
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  CHECK_EQ (p.cl.established, 1);
  n = mkmsg (m, 94, 40, 1);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, n), GF_OK);
  p.cl.out.buf[p.cl.out.len - 20] ^= 4;
  pump (&p, 0);
  CHECK_EQ (p.sv.closed, 1);
  CHECK_EQ (p.sv.close_error, GF_ERR_CRYPTO);
  CHECK_EQ (p.sv.close_reason, GF_DISCONNECT_MAC_ERROR);
  CHECK_EQ (p.sv.nmsgs, 0);
  pair_free (&p);

  /* Drop a packet: the next one no longer authenticates (Terrapin's
     deletion, in the established phase, is caught by the sequence
     number).  */
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  n = mkmsg (m, 94, 40, 1);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, n), GF_OK);
  p.cl.out.len = 0;
  n = mkmsg (m, 94, 40, 2);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, n), GF_OK);
  pump (&p, 0);
  CHECK_EQ (p.sv.closed, 1);
  CHECK_EQ (p.sv.nmsgs, 0);
  pair_free (&p);

  /* A replayed packet.  */
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  n = mkmsg (m, 94, 40, 1);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, n), GF_OK);
  {
    size_t len = p.cl.out.len;
    uint8_t *copy = malloc (len);

    memcpy (copy, p.cl.out.buf, len);
    pump (&p, 0);
    CHECK_EQ (p.sv.nmsgs, 1);
    CHECK_EQ (gf_conn_receive (p.sv.c, tst_now, copy, len) != GF_OK, 1);
    CHECK_EQ (p.sv.closed, 1);
    CHECK_EQ (p.sv.nmsgs, 1);
    free (copy);
  }
  pair_free (&p);

}

/* ------------------------------------------------------------------ */
/* A scripted client that completes a real key exchange                */
/* ------------------------------------------------------------------ */

struct pk
{
  int type;
  uint8_t data[2200];
  size_t len;
};

struct packets
{
  struct pk p[16];
  size_t n;
};

struct client
{
  struct script s;
  gf_packet in;
  uint8_t server_ident[256];
  size_t server_ident_len;
  int ident_done;
  /* Handshake state, live while drain runs the exchange.  */
  int hs;
  uint8_t ki[2048];
  size_t kil;
  uint8_t server_ki[2048];
  size_t server_kil;
  uint8_t init[64];
  size_t initlen;
  gf_kex_client *kc;
  uint8_t rkey[64];
  int have_rkey;
  int sig_ok;
  struct packets ps;
};

static const char client_ident[] = "SSH-2.0-scripted";

static int
client_cb (void *user, const uint8_t *payload, size_t len)
{
  struct client *c = user;
  struct packets *ps = &c->ps;

  if (c->hs && payload[0] == 31)
    {
      gf_reader r;
      gf_slice ks, qs, sig;
      gf_kex_secret k;
      struct gf_kex_transcript t;
      uint8_t h[32], ckey[64];

      gf_reader_init (&r, payload + 1, len - 1);
      CHECK_EQ (gf_rd_string (&r, &ks), GF_OK);
      CHECK_EQ (gf_rd_string (&r, &qs), GF_OK);
      CHECK_EQ (gf_rd_string (&r, &sig), GF_OK);
      CHECK_EQ (gf_kex_client_finish (c->kc, qs.data, qs.len, &k), GF_OK);
      t.v_c.data = (const uint8_t *) client_ident;
      t.v_c.len = sizeof client_ident - 1;
      t.v_s.data = c->server_ident;
      t.v_s.len = c->server_ident_len;
      t.i_c.data = c->ki;
      t.i_c.len = c->kil;
      t.i_s.data = c->server_ki;
      t.i_s.len = c->server_kil;
      t.k_s = ks;
      t.q_c.data = c->init;
      t.q_c.len = c->initlen;
      t.q_s = qs;
      CHECK_EQ (gf_kex_exchange_hash (GF_KEX_CURVE25519_SHA256, &t, &k, h, 32),
                GF_OK);
      c->sig_ok = gf_key_verify (hostkey, GF_SIG_ED25519, h, 32, sig.data,
                                 sig.len) == GF_OK;
      CHECK_EQ (gf_kex_derive (GF_HASH_SHA256, &k, h, 32, h, 32, 'C', ckey, 64),
                GF_OK);
      CHECK_EQ (gf_kex_derive (GF_HASH_SHA256, &k, h, 32, h, 32, 'D', c->rkey,
                               64), GF_OK);
      c->have_rkey = 1;
      /* Our NEWKEYS, and then the keys for what we send.  */
      {
        static const uint8_t nk = 21;

        CHECK_EQ (send_payload (&c->s, &nk, 1), GF_OK);
        CHECK_EQ (gf_packet_set_keys (&c->s.out, GF_DIR_WRITE,
                                      GF_CIPHER_CHACHA20_POLY1305, ckey, 64,
                                      NULL, 0, 1), GF_OK);
      }
      gf_wipe (&k, sizeof k);
    }
  if (c->hs && payload[0] == 21 && c->have_rkey)
    CHECK_EQ (gf_packet_set_keys (&c->in, GF_DIR_READ,
                                  GF_CIPHER_CHACHA20_POLY1305, c->rkey, 64,
                                  NULL, 0, 1), GF_OK);
  if (ps->n < 16 && len <= sizeof ps->p[0].data)
    {
      ps->p[ps->n].type = payload[0];
      ps->p[ps->n].len = len;
      memcpy (ps->p[ps->n].data, payload, len);
      ps->n++;
    }
  return 0;
}

/* Parse what the server has written so far.  */
static struct packets
drain (struct client *c)
{
  uint8_t *b = c->s.sv.out.buf;
  size_t len = c->s.sv.out.len;

  memset (&c->ps, 0, sizeof c->ps);
  if (!c->ident_done && len > 0)
    {
      size_t i = 0;

      while (i < len && b[i] != '\n')
        i++;
      c->server_ident_len = i - 1;		/* Without CR LF.  */
      memcpy (c->server_ident, b, c->server_ident_len);
      b += i + 1;
      len -= i + 1;
      c->ident_done = 1;
    }
  (void) gf_packet_receive (&c->in, &b, &len, client_cb, c);
  c->s.sv.out.len = 0;
  return c->ps;
}

static size_t
init_msg (uint8_t *buf, size_t cap, const uint8_t *q, size_t qlen)
{
  return ecdh_init (buf, cap, q, qlen);
}

static void
client_start (struct client *c)
{
  struct lists l = {
    "curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com",
    "ssh-ed25519", "chacha20-poly1305@openssh.com", "none", 0
  };
  struct packets ps;
  uint8_t msg[64];
  size_t n;

  memset (c, 0, sizeof *c);
  script_new (&c->s);
  gf_packet_init (&c->in);
  c->hs = 1;
  CHECK_EQ (send_ident (&c->s, IDENT), GF_OK);
  c->kil = kexinit_payload (c->ki, sizeof c->ki, &l);
  CHECK_EQ (send_payload (&c->s, c->ki, c->kil), GF_OK);
  ps = drain (c);
  CHECK_EQ (ps.n, 1);
  CHECK_EQ (ps.p[0].type, 20);
  memcpy (c->server_ki, ps.p[0].data, ps.p[0].len);
  c->server_kil = ps.p[0].len;
  CHECK_EQ (gf_kex_client_start (&c->kc, GF_KEX_CURVE25519_SHA256, c->init,
                                 sizeof c->init, &c->initlen), GF_OK);
  n = init_msg (msg, sizeof msg, c->init, c->initlen);
  CHECK_EQ (send_payload (&c->s, msg, n), GF_OK);
}

/* Finish: the server's REPLY, NEWKEYS and EXT_INFO.  */
static void
client_finish (struct client *c)
{
  struct packets ps = drain (c);

  CHECK_EQ (ps.n, 3);
  CHECK_EQ (ps.p[0].type, 31);
  CHECK_EQ (ps.p[1].type, 21);
  CHECK_EQ (ps.p[2].type, 7);		/* EXT_INFO, sent under the new keys.  */
  CHECK (c->sig_ok);
  c->hs = 0;
  gf_kex_client_free (c->kc);
  c->kc = NULL;
  CHECK_EQ (c->s.sv.established, 1);
}

static void
client_handshake (struct client *c)
{
  client_start (c);
  client_finish (c);
}

static void
client_free (struct client *c)
{
  gf_kex_client_free (c->kc);
  script_free (&c->s);
}

static void
test_scripted_client (void)
{
  struct client c;
  struct packets ps;
  static const uint8_t unknown[] = { 9 };
  static const uint8_t ext[] = { 7, 0, 0, 0, 0 };
  static const uint8_t accept[] = { 6, 0, 0, 0, 3, 'a', 'b', 'c' };
  static const uint8_t newkeys[] = { 21 };
  static const uint8_t kex33[] = { 33, 0, 0, 0, 0 };
  static const uint8_t ignore[] = { 2, 0, 0, 0, 3, 'a', 'b', 'c' };
  static const uint8_t data[] = { 94, 1, 2, 3 };
  static const uint8_t svc[] = { 5, 0, 0, 0, 12, 's', 's', 'h', '-', 'u', 's',
                                 'e', 'r', 'a', 'u', 't', 'h' };
  size_t i;

  /* The exchange itself works with a client built from the pieces, and
     the server's signature over our independently computed hash holds.  */
  client_handshake (&c);
  CHECK_EQ (c.s.sv.closed, 0);

  /* An EXT_INFO straight after the NEWKEYS is accepted (OpenSSH sends
     one), delivered to the extension callback, and only once.  */
  {
    static const uint8_t einfo[] = {
      7, 0, 0, 0, 1, 0, 0, 0, 4, 'p', 'i', 'n', 'g', 0, 0, 0, 1, '0'
    };

    CHECK_EQ (send_payload (&c.s, einfo, sizeof einfo), GF_OK);
    CHECK (strstr (c.s.sv.extension, "ping=0;") != NULL);
    CHECK_EQ (c.s.sv.closed, 0);
  }

  /* Strict key exchange: both counters restarted at NEWKEYS, so the first
     packet we send is number 0.  Unknown numbers are answered with
     UNIMPLEMENTED naming the packet.  */
  CHECK_EQ (send_payload (&c.s, unknown, 1), GF_OK);
  CHECK_EQ (send_payload (&c.s, unknown, 1), GF_OK);
  ps = drain (&c);
  CHECK_EQ (ps.n, 2);
  CHECK_EQ (ps.p[0].type, 3);
  CHECK (ps.p[0].len == 5 && ps.p[0].data[4] == 1);
  CHECK (ps.p[1].len == 5 && ps.p[1].data[4] == 2);

  /* A server-to-client message sent the wrong way is not understood.  */
  CHECK_EQ (send_payload (&c.s, accept, sizeof accept), GF_OK);
  ps = drain (&c);
  CHECK_EQ (ps.n, 1);
  CHECK_EQ (ps.p[0].type, 3);

  /* IGNORE and application data are fine once established.  */
  CHECK_EQ (send_payload (&c.s, ignore, sizeof ignore), GF_OK);
  CHECK_EQ (send_payload (&c.s, data, sizeof data), GF_OK);
  CHECK_EQ (c.s.sv.nmsgs, 1);
  CHECK_EQ (c.s.sv.closed, 0);
  CHECK_EQ (send_payload (&c.s, svc, sizeof svc), GF_OK);
  ps = drain (&c);
  CHECK_EQ (ps.n, 1);
  CHECK_EQ (ps.p[0].type, 6);
  client_free (&c);

  /* Messages that are not valid in this state end the connection.  */
  for (i = 0; i < 4; i++)
    {
      const uint8_t *m = i == 0 ? ext : i == 1 ? newkeys : i == 2 ? kex33
                                                                  : svc;
      size_t n = i == 0 ? sizeof ext : i == 1 ? sizeof newkeys
                 : i == 2 ? sizeof kex33 : sizeof svc;
      client_handshake (&c);
      /* EXT_INFO is allowed only as the very first message.  */
      if (i == 0)
        CHECK_EQ (send_payload (&c.s, ignore, sizeof ignore), GF_OK);
      if (i == 3)
        {
          /* Not invalid by itself: a second request is simply answered; use
             a service the server refuses.  */
          static const uint8_t bad[] = { 5, 0, 0, 0, 3, 'a', 'b', 'c' };

          CHECK (send_payload (&c.s, bad, sizeof bad) != GF_OK);
        }
      else
        CHECK (send_payload (&c.s, m, n) != GF_OK);
      ps = drain (&c);
      CHECK_EQ (c.s.sv.closed, 1);
      CHECK (ps.n >= 1 && ps.p[ps.n - 1].type == 1);
      client_free (&c);
    }
}

/* A rekey the peer starts: until its NEWKEYS it may send only transport and
   key exchange messages.  */
static void
test_scripted_rekey_rules (void)
{
  struct client c;
  struct packets ps;
  uint8_t ki[2048];
  size_t n;
  static const uint8_t data[] = { 94, 1, 2, 3 };
  struct lists l = {
    "curve25519-sha256", "ssh-ed25519", "chacha20-poly1305@openssh.com",
    "none", 0
  };

  /* A KEXINIT without the first-exchange markers is a proper rekey start,
     and the server answers with its own.  */
  client_handshake (&c);
  n = kexinit_payload (ki, sizeof ki, &l);
  CHECK_EQ (send_payload (&c.s, ki, n), GF_OK);
  ps = drain (&c);
  CHECK_EQ (ps.n, 1);
  CHECK_EQ (ps.p[0].type, 20);
  CHECK_EQ (c.s.sv.closed, 0);
  /* Application data now is a violation.  */
  CHECK (send_payload (&c.s, data, sizeof data) != GF_OK);
  CHECK_EQ (c.s.sv.closed, 1);
  CHECK_EQ (c.s.sv.nmsgs, 0);
  client_free (&c);

  /* A rekey KEXINIT that carries the strict markers again is also fine
     (they are only meaningful the first time).  */
  client_handshake (&c);
  n = kexinit_payload (ki, sizeof ki, &good_client);
  CHECK_EQ (send_payload (&c.s, ki, n), GF_OK);
  ps = drain (&c);
  CHECK_EQ (ps.n, 1);
  CHECK_EQ (c.s.sv.closed, 0);
  /* A second KEXINIT in the same exchange.  */
  CHECK (send_payload (&c.s, ki, n) != GF_OK);
  CHECK_EQ (c.s.sv.closed, 1);
  client_free (&c);
}

int
main (void)
{
  gf_crypto_init ();
  CHECK_EQ (gf_key_generate (&hostkey, GF_KEY_ED25519, 0), GF_OK);
  test_strict_kex_required ();
  test_terrapin ();
  test_negotiation_refusals ();
  test_identification ();
  test_bad_ecdh_value ();
  test_oversize_and_garbage ();
  test_established_attacks ();
  test_scripted_client ();
  test_scripted_rekey_rules ();
  gf_key_free (hostkey);
  TST_DONE ();
}
