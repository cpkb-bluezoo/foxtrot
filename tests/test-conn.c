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

static gf_key *keys[4];		/* ed25519, p256, p384, rsa.  */

static void
make_keys (void)
{
  CHECK_EQ (gf_key_generate (&keys[0], GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&keys[1], GF_KEY_ECDSA_P256, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&keys[2], GF_KEY_ECDSA_P384, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&keys[3], GF_KEY_RSA, 2048), GF_OK);
}

static gf_conn_config
config (int server, size_t nkeys)
{
  gf_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  if (server)
    {
      cfg.host_keys = keys;
      cfg.nhost_keys = nkeys;
    }
  return cfg;
}

static void
expect_established (struct pair *p)
{
  CHECK_EQ (p->cl.established, 1);
  CHECK_EQ (p->sv.established, 1);
  CHECK (gf_conn_is_established (p->cl.c));
  CHECK (gf_conn_is_established (p->sv.c));
  CHECK_EQ (p->cl.closed, 0);
  CHECK_EQ (p->sv.closed, 0);
}

/* Every key exchange method, every cipher, every host key type.  */
static void
test_matrix (void)
{
  static const enum gf_kex kexes[] = {
    GF_KEX_CURVE25519_SHA256, GF_KEX_MLKEM768X25519_SHA256,
    GF_KEX_MLKEM768NISTP256_SHA256, GF_KEX_MLKEM1024NISTP384_SHA384,
    GF_KEX_SNTRUP761X25519_SHA512, GF_KEX_ECDH_NISTP256_SHA256,
    GF_KEX_ECDH_NISTP384_SHA384
  };
  static const enum gf_cipher ciphers[] = {
    GF_CIPHER_CHACHA20_POLY1305, GF_CIPHER_AES256_GCM, GF_CIPHER_AES128_GCM
  };
  static const enum gf_sigalg sigs[] = {
    GF_SIG_ED25519, GF_SIG_ECDSA_NISTP256, GF_SIG_ECDSA_NISTP384,
    GF_SIG_RSA_SHA2_512, GF_SIG_RSA_SHA2_256
  };
  size_t k, c, s;

  for (k = 0; k < sizeof kexes / sizeof kexes[0]; k++)
    for (c = 0; c < sizeof ciphers / sizeof ciphers[0]; c++)
      {
        /* Cover the signature algorithms alongside, not as a full cube.  */
        s = (k + c) % (sizeof sigs / sizeof sigs[0]);
        {
          struct pair p;
          gf_conn_config cc = config (0, 0), sc = config (1, 4);
          uint8_t m[100], reply[100];
          size_t n;

          cc.prefs.kex = sc.prefs.kex = &kexes[k];
          cc.prefs.nkex = sc.prefs.nkex = 1;
          cc.prefs.ciphers = sc.prefs.ciphers = &ciphers[c];
          cc.prefs.nciphers = sc.prefs.nciphers = 1;
          cc.prefs.sigalgs = &sigs[s];
          cc.prefs.nsigalgs = 1;
          CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
          pair_start (&p);
          pump (&p, 0);
          expect_established (&p);
          if (!p.cl.established)
            {
              pair_free (&p);
              continue;
            }
          CHECK_EQ (p.cl.info.kex, kexes[k]);
          CHECK_EQ (p.cl.info.cipher_c2s, ciphers[c]);
          CHECK_EQ (p.sv.info.cipher_s2c, ciphers[c]);
          CHECK_EQ (p.cl.info.hostkey_alg, sigs[s]);
          CHECK_EQ (p.cl.host_key_calls, 1);
          CHECK (p.cl.info.session_id_len > 0);
          CHECK (p.cl.info.session_id_len == p.sv.info.session_id_len);
          CHECK (memcmp (p.cl.info.session_id, p.sv.info.session_id,
                         p.cl.info.session_id_len) == 0);
          CHECK (gf_key_equal (p.cl.info.host_key, p.sv.info.host_key));
          CHECK (gf_slice_equals (p.cl.info.peer_software, "foxtrot_" VERSION));

          /* Data both ways.  */
          n = mkmsg (m, 94, 100, 7);
          CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, n), GF_OK);
          pump (&p, 0);
          CHECK_EQ (p.sv.nmsgs, 1);
          CHECK (p.sv.nmsgs && msg_is (&p.sv.msgs[0], 94, 100, 7));
          n = mkmsg (reply, 95, 31, 9);
          CHECK_EQ (gf_conn_send (p.sv.c, tst_now, reply, n), GF_OK);
          pump (&p, 0);
          CHECK_EQ (p.cl.nmsgs, 1);
          CHECK (p.cl.nmsgs && msg_is (&p.cl.msgs[0], 95, 31, 9));
          pair_free (&p);
        }
      }
}

/* The same handshake and traffic, delivered a byte at a time and in
   assorted odd sizes.  */
static void
test_chunks (void)
{
  static const size_t chunks[] = { 1, 2, 3, 7, 64, 1000, 4097 };
  size_t i;

  for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++)
    {
      struct pair p;
      gf_conn_config cc = config (0, 0), sc = config (1, 1);
      static uint8_t m[GF_MAX_PAYLOAD];
      size_t n, j;

      CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
      pair_start (&p);
      pump (&p, chunks[i]);
      expect_established (&p);
      for (j = 0; j < 4; j++)
        {
          n = mkmsg (m, 100, j == 3 ? GF_MAX_PAYLOAD : 50 + j * 700, (uint8_t) j);
          CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, n), GF_OK);
        }
      pump (&p, chunks[i]);
      CHECK_EQ (p.sv.nmsgs, 4);
      for (j = 0; j < p.sv.nmsgs; j++)
        CHECK (msg_is (&p.sv.msgs[j], 100, j == 3 ? GF_MAX_PAYLOAD : 50 + j * 700,
                       (uint8_t) j));
      pair_free (&p);
    }
}

static void
traffic (struct pair *p, size_t count, size_t size, uint8_t seed)
{
  uint8_t m[GF_MAX_PAYLOAD];
  size_t i;

  for (i = 0; i < count; i++)
    {
      size_t n = mkmsg (m, 120, size, (uint8_t) (seed + i));

      CHECK_EQ (gf_conn_send (p->cl.c, tst_now, m, n), GF_OK);
      n = mkmsg (m, 121, size, (uint8_t) (seed + i + 1));
      CHECK_EQ (gf_conn_send (p->sv.c, tst_now, m, n), GF_OK);
    }
}

static void
test_rekey (void)
{
  struct pair p;
  gf_conn_config cc = config (0, 0), sc = config (1, 1);
  uint8_t sid[64];
  size_t sidlen, i;

  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  expect_established (&p);
  sidlen = p.cl.info.session_id_len;
  memcpy (sid, p.cl.info.session_id, sidlen);

  /* Rekey by the client, then by the server, with traffic going both ways
     while it happens.  */
  for (i = 0; i < 4; i++)
    {
      struct end *who = i % 2 ? &p.sv : &p.cl;
      uint8_t m[40];
      size_t n;

      CHECK_EQ (gf_conn_rekey (who->c, tst_now), GF_OK);
      /* Sent between KEXINIT and NEWKEYS: held and sent after.  */
      n = mkmsg (m, 130, 40, (uint8_t) i);
      CHECK_EQ (gf_conn_send (who->c, tst_now, m, n), GF_OK);
      n = mkmsg (m, 131, 40, (uint8_t) i);
      CHECK_EQ (gf_conn_send (who == &p.cl ? p.sv.c : p.cl.c, tst_now, m, n),
                GF_OK);
      pump (&p, i < 2 ? 0 : 5);
      CHECK_EQ (p.cl.rekeyed, (int) i + 1);
      CHECK_EQ (p.sv.rekeyed, (int) i + 1);
      CHECK_EQ (p.cl.closed + p.sv.closed, 0);
    }
  CHECK_EQ (p.cl.info.session_id_len, sidlen);
  CHECK (memcmp (p.cl.info.session_id, sid, sidlen) == 0);
  CHECK (memcmp (p.sv.info.session_id, sid, sidlen) == 0);
  /* Every message arrived, in order, once.  */
  CHECK_EQ (p.sv.nmsgs + p.cl.nmsgs, 8);
  CHECK_EQ (p.cl.host_key_calls, 1);
  pair_free (&p);
}

/* Limits start rekeys by themselves, and the data keeps flowing.  */
static void
test_automatic_rekey (void)
{
  struct pair p;
  gf_conn_config cc = config (0, 0), sc = config (1, 1);
  size_t i;

  /* By packets.  */
  cc.rekey_packets = sc.rekey_packets = 12;
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  for (i = 0; i < 60; i++)
    {
      traffic (&p, 1, 30, (uint8_t) i);
      pump (&p, 0);
    }
  CHECK (p.cl.rekeyed >= 3);
  CHECK_EQ (p.cl.rekeyed, p.sv.rekeyed);
  CHECK_EQ (p.sv.nmsgs, 60);
  CHECK_EQ (p.cl.nmsgs, 60);
  for (i = 0; i < 60; i++)
    CHECK (msg_is (&p.sv.msgs[i], 120, 30, (uint8_t) i)
           && msg_is (&p.cl.msgs[i], 121, 30, (uint8_t) (i + 1)));
  pair_free (&p);

  /* By bytes.  */
  memset (&cc, 0, sizeof cc);
  cc.rekey_bytes = sc.rekey_bytes = 10000;
  sc.rekey_packets = 0;
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  for (i = 0; i < 20; i++)
    {
      traffic (&p, 1, 2000, (uint8_t) i);
      pump (&p, 0);
    }
  CHECK (p.cl.rekeyed >= 2);
  CHECK_EQ (p.sv.nmsgs, 20);
  pair_free (&p);

  /* By time.  */
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  sc.host_keys = keys;
  sc.nhost_keys = 1;
  cc.rekey_interval_us = sc.rekey_interval_us = 5000000;
  tst_now = 1000000;
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  expect_established (&p);
  CHECK (gf_conn_timeout (p.cl.c) > tst_now);
  CHECK (gf_conn_timeout (p.cl.c) < tst_now + 6000000);
  tst_now += 4000000;
  CHECK_EQ (gf_conn_on_timeout (p.cl.c, tst_now), GF_OK);
  pump (&p, 0);
  CHECK_EQ (p.cl.rekeyed, 0);
  tst_now += 2000000;
  CHECK_EQ (gf_conn_on_timeout (p.cl.c, tst_now), GF_OK);
  pump (&p, 0);
  CHECK_EQ (p.cl.rekeyed, 1);
  CHECK_EQ (p.sv.rekeyed, 1);
  pair_free (&p);
}

static void
test_host_key_refused (void)
{
  struct pair p;
  gf_conn_config cc = config (0, 0), sc = config (1, 1);

  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  p.cl.trust = 0;
  pair_start (&p);
  pump (&p, 0);
  CHECK_EQ (p.cl.established, 0);
  CHECK_EQ (p.cl.closed, 1);
  CHECK_EQ (p.cl.close_error, GF_ERR_HOSTKEY);
  CHECK_EQ (p.cl.close_reason, GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
  CHECK_EQ (p.sv.closed, 1);
  CHECK_EQ (p.sv.close_reason, GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
  CHECK_EQ (gf_conn_receive (p.cl.c, tst_now, (const uint8_t *) "x", 1),
            GF_ERR_HOSTKEY);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, (const uint8_t *) "\x32", 1),
            GF_ERR_CLOSED);
  pair_free (&p);

  /* A client with no callback trusts nothing.  */
  pair_no_host_key_callback = 1;
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_no_host_key_callback = 0;
  pair_start (&p);
  pump (&p, 0);
  CHECK_EQ (p.cl.established, 0);
  CHECK_EQ (p.cl.close_error, GF_ERR_HOSTKEY);
  pair_free (&p);
}

/* An attacker in the middle can alter the (unencrypted) key exchange
   messages, but the server's signature over the exchange hash covers
   everything, and the client must refuse each alteration.  */
static void
test_tampered_exchange (void)
{
  /* Offsets into the REPLY packet: length (4), padding length (1), type
     (1), then K_S, Q_S and the signature, each a string.  */
  static const char *const what[] = { "host key", "server value", "signature" };
  size_t t;

  for (t = 0; t < 3; t++)
    {
      struct pair p;
      gf_conn_config cc = config (0, 0), sc = config (1, 1);
      size_t pl, padlen, off, ks, qs, sg;
      uint8_t *pkt;

      CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
      pair_start (&p);
      /* Deliver the client's messages so that the server answers, but hold
         the server's reply.  */
      deliver (&p.cl, &p.sv, 0);		/* Identification and KEXINIT.  */
      deliver (&p.sv, &p.cl, 0);		/* The server's, and the client's
					   ECDH_INIT is the answer.  */
      deliver (&p.cl, &p.sv, 0);		/* The server replies.  */
      CHECK (p.sv.out.len > 0);
      pkt = p.sv.out.buf;			/* The REPLY comes first.  */
      pl = (size_t) pkt[0] << 24 | pkt[1] << 16 | pkt[2] << 8 | pkt[3];
      padlen = pkt[4];
      CHECK_EQ (pkt[5], 31);
      ks = 6;
      qs = ks + 4 + ((size_t) pkt[ks] << 24 | pkt[ks + 1] << 16
                     | pkt[ks + 2] << 8 | pkt[ks + 3]);
      sg = qs + 4 + ((size_t) pkt[qs] << 24 | pkt[qs + 1] << 16
                     | pkt[qs + 2] << 8 | pkt[qs + 3]);
      off = t == 0 ? ks + 4 + 20 : t == 1 ? qs + 4 + 3 : sg + 4 + 30;
      CHECK (sg + 4 + 10 < 4 + pl - padlen);
      pkt[off] ^= 0x10;
      pump (&p, 0);
      if (p.cl.established)
        fprintf (stderr, "altered %s was accepted\n", what[t]);
      CHECK_EQ (p.cl.established, 0);
      CHECK_EQ (p.cl.closed, 1);
      CHECK (p.cl.close_error == GF_ERR_HOSTKEY
             || p.cl.close_error == GF_ERR_CRYPTO
             || p.cl.close_error == GF_ERR_PROTOCOL);
      CHECK_EQ (p.cl.host_key_calls, 0);	/* Never asked to trust it.  */
      pair_free (&p);
    }
}

/* A rekey must be with the same host key.  */
static void
test_rekey_key_change (void)
{
  struct pair p;
  gf_key *other = NULL, *hk[1];
  gf_conn_config cc = config (0, 0), sc = config (1, 1);

  CHECK_EQ (gf_key_generate (&other, GF_KEY_ED25519, 0), GF_OK);
  hk[0] = keys[0];
  sc.host_keys = hk;
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  expect_established (&p);
  hk[0] = other;			/* The server now signs with another key.  */
  CHECK_EQ (gf_conn_rekey (p.sv.c, tst_now), GF_OK);
  pump (&p, 0);
  CHECK_EQ (p.cl.rekeyed, 0);
  CHECK_EQ (p.cl.closed, 1);
  CHECK_EQ (p.cl.close_error, GF_ERR_HOSTKEY);
  pair_free (&p);
  gf_key_free (other);
}

static void
test_services_and_extensions (void)
{
  struct pair p;
  gf_conn_config cc = config (0, 0), sc = config (1, 1);

  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  expect_established (&p);
  /* EXT_INFO: the server's user key algorithms.  */
  CHECK (strstr (p.cl.extension, "server-sig-algs=") != NULL);
  CHECK (strstr (p.cl.extension, "ssh-ed25519") != NULL);
  CHECK (strstr (p.cl.extension, "rsa-sha2-256") != NULL);
  CHECK (strstr (p.cl.extension, "ssh-rsa,") == NULL);

  CHECK_EQ (gf_conn_request_service (p.sv.c, tst_now, "ssh-userauth"),
            GF_ERR_INVAL);
  CHECK_EQ (gf_conn_request_service (p.cl.c, tst_now, "ssh-userauth"), GF_OK);
  pump (&p, 0);
  CHECK_EQ (p.cl.accepted, 1);
  CHECK (strcmp (p.cl.service, "ssh-userauth") == 0);
  CHECK (strcmp (p.sv.service, "ssh-userauth") == 0);

  /* Traffic helpers.  */
  CHECK_EQ (gf_conn_send_ignore (p.cl.c, tst_now, (const uint8_t *) "pad", 3),
            GF_OK);
  CHECK_EQ (gf_conn_send_debug (p.sv.c, tst_now, 1, "hello"), GF_OK);
  pump (&p, 0);
  CHECK_EQ (p.cl.debug_calls, 1);
  CHECK_EQ (p.sv.nmsgs, 0);

  /* A service we do not offer ends the connection.  */
  CHECK_EQ (gf_conn_request_service (p.cl.c, tst_now, "ssh-connection"),
            GF_OK);
  pump (&p, 0);
  CHECK_EQ (p.sv.closed, 1);
  CHECK_EQ (p.sv.close_reason, GF_DISCONNECT_SERVICE_NOT_AVAILABLE);
  CHECK_EQ (p.cl.closed, 1);
  CHECK_EQ (p.cl.close_reason, GF_DISCONNECT_SERVICE_NOT_AVAILABLE);
  pair_free (&p);
}

static void
test_disconnect (void)
{
  struct pair p;
  gf_conn_config cc = config (0, 0), sc = config (1, 1);

  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  CHECK_EQ (gf_conn_disconnect (p.cl.c, tst_now,
                                GF_DISCONNECT_BY_APPLICATION, "bye"), GF_OK);
  CHECK_EQ (p.cl.closed, 1);
  CHECK_EQ (p.cl.close_error, 0);
  pump (&p, 0);
  CHECK_EQ (p.sv.closed, 1);
  CHECK_EQ (p.sv.close_error, 0);
  CHECK_EQ (p.sv.close_reason, GF_DISCONNECT_BY_APPLICATION);
  CHECK_EQ (gf_conn_disconnect (p.cl.c, tst_now, 11, NULL), GF_ERR_CLOSED);
  pair_free (&p);

  /* A disconnect for another reason is an error to the other side.  */
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  CHECK_EQ (gf_conn_disconnect (p.sv.c, tst_now,
                                GF_DISCONNECT_TOO_MANY_CONNECTIONS, NULL),
            GF_OK);
  pump (&p, 0);
  CHECK_EQ (p.cl.closed, 1);
  CHECK_EQ (p.cl.close_error, GF_ERR_CLOSED);
  CHECK_EQ (p.cl.close_reason, GF_DISCONNECT_TOO_MANY_CONNECTIONS);
  pair_free (&p);
}

static void
test_timeouts (void)
{
  struct pair p;
  gf_conn_config cc = config (0, 0), sc = config (1, 1);

  tst_now = 1000000;
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  CHECK_EQ (gf_conn_timeout (p.cl.c), UINT64_MAX);
  pair_start (&p);
  /* The server never hears from the client.  */
  CHECK_EQ (gf_conn_timeout (p.sv.c), tst_now + 60000000);
  CHECK_EQ (gf_conn_on_timeout (p.sv.c, tst_now + 59000000), GF_OK);
  CHECK_EQ (gf_conn_on_timeout (p.sv.c, tst_now + 60000000), GF_ERR_TIMEOUT);
  CHECK_EQ (p.sv.closed, 1);
  CHECK_EQ (p.sv.close_error, GF_ERR_TIMEOUT);
  CHECK_EQ (gf_conn_timeout (p.sv.c), UINT64_MAX);
  pair_free (&p);

  /* A rekey the peer does not answer.  */
  memset (&cc, 0, sizeof cc);
  cc.kex_timeout_us = 2000000;
  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  pair_start (&p);
  pump (&p, 0);
  expect_established (&p);
  CHECK_EQ (gf_conn_rekey (p.cl.c, tst_now), GF_OK);
  CHECK_EQ (gf_conn_timeout (p.cl.c), tst_now + 2000000);
  p.cl.out.len = 0;			/* Lost.  */
  CHECK_EQ (gf_conn_on_timeout (p.cl.c, tst_now + 2000001), GF_ERR_TIMEOUT);
  CHECK_EQ (p.cl.closed, 1);
  pair_free (&p);
}

static void
test_misuse (void)
{
  struct pair p;
  gf_conn_config cc = config (0, 0), sc = config (1, 1);
  uint8_t m[GF_MAX_PAYLOAD + 10];

  CHECK_EQ (pair_new (&p, &cc, &sc), GF_OK);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, 10), GF_ERR_STATE);
  CHECK_EQ (gf_conn_receive (p.cl.c, tst_now, m, 10), GF_ERR_STATE);
  pair_start (&p);
  CHECK_EQ (gf_conn_start (p.cl.c, tst_now), GF_ERR_STATE);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, 10), GF_ERR_STATE);
  pump (&p, 0);
  expect_established (&p);
  m[0] = 49;
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, 10), GF_ERR_INVAL);
  m[0] = 60;
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, GF_MAX_PAYLOAD + 1),
            GF_ERR_RANGE);
  CHECK_EQ (gf_conn_send (p.cl.c, tst_now, m, GF_MAX_PAYLOAD), GF_OK);
  pair_free (&p);

  /* A server needs host keys; both ends need the write and message
     callbacks.  */
  {
    gf_conn *c;
    gf_conn_events ev;
    struct end e;
    gf_conn_config bare = config (1, 0);

    memset (&e, 0, sizeof e);
    ev = end_events (&e);
    CHECK_EQ (gf_conn_server_new (&c, &bare, &ev), GF_ERR_INVAL);
    ev.message = NULL;
    CHECK_EQ (gf_conn_client_new (&c, &cc, &ev), GF_ERR_INVAL);
  }
}

int
main (void)
{
  gf_crypto_init ();
  make_keys ();
  test_matrix ();
  test_chunks ();
  test_rekey ();
  test_automatic_rekey ();
  test_host_key_refused ();
  test_tampered_exchange ();
  test_rekey_key_change ();
  test_services_and_extensions ();
  test_disconnect ();
  test_timeouts ();
  test_misuse ();
  {
    int i;

    for (i = 0; i < 4; i++)
      gf_key_free (keys[i]);
  }
  TST_DONE ();
}
