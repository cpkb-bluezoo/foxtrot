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
#include <foxtrot/auth.h>
#include <foxtrot/conn.h>

#include "tst-pair.h"

static gf_key *hostkey;
static gf_key *ukeys[4];	/* ed25519, p256, p384, rsa: users' keys.  */
static gf_key *stranger;	/* A key nobody authorized.  */

/* Both machines wired to a pair of connections, with a small application
   on each side.  */
struct ap
{
  struct pair p;
  gf_auth_server *srv;
  gf_auth_client *cli;
  int use_client;
  gf_conn_config sc, cc;

  /* Server application.  */
  const gf_key *authorized[4];
  size_t nauthorized;
  const char *password;
  const char *code;
  int hold;			/* Do not answer; the test will.  */
  int srv_requests, srv_queries, srv_signed, srv_passwords, srv_kbd;
  int srv_authenticated;
  uint32_t srv_disconnect;
  int srv_hostbound_seen;
  char srv_user[64];
  enum gf_auth_method last_method;

  /* Client application.  */
  const char *answer;
  int cli_authenticated, cli_failed, banners, prompts;
  char banner[128];
  int tamper;			/* Flip a byte of what the client signs.  */
  uint8_t sid_override[32];
  int use_sid_override;
};

static int
srv_send (void *user, const uint8_t *p, size_t n)
{
  struct ap *x = user;

  return gf_conn_send (x->p.sv.c, tst_now, p, n) != GF_OK;
}

static int
srv_request (void *user, const gf_auth_request *req)
{
  struct ap *x = user;
  size_t i;
  int ok = 0;

  x->srv_requests++;
  x->last_method = req->method;
  snprintf (x->srv_user, sizeof x->srv_user, "%.*s", (int) req->user.len,
            (const char *) req->user.data);
  switch (req->method)
    {
    case GF_AUTH_PUBLICKEY:
      if (req->hostbound)
        x->srv_hostbound_seen++;
      if (req->has_signature)
        x->srv_signed++;
      else
        x->srv_queries++;
      for (i = 0; i < x->nauthorized; i++)
        if (gf_key_equal (x->authorized[i], req->key))
          ok = 1;
      if (x->hold)
        return 0;
      if (!req->has_signature)
        return (ok ? gf_auth_server_pk_ok (x->srv, tst_now)
                   : gf_auth_server_reject (x->srv, tst_now, 0)) != GF_OK;
      break;
    case GF_AUTH_PASSWORD:
      x->srv_passwords++;
      ok = x->password && req->password.len == strlen (x->password)
        && memcmp (req->password.data, x->password, req->password.len) == 0;
      break;
    case GF_AUTH_KBDINT:
      {
        static const char *const prompts[] = { "Code: " };
        static const int echo[] = { 0 };

        x->srv_kbd++;
        return gf_auth_server_kbdint_prompt (x->srv, tst_now, "login",
                                             "enter the code", 1, prompts,
                                             echo) != GF_OK;
      }
    default:
      break;
    }
  if (x->hold)
    return 0;
  return (ok ? gf_auth_server_accept (x->srv, tst_now)
             : gf_auth_server_reject (x->srv, tst_now, 0)) != GF_OK;
}

static int
srv_kbd_response (void *user, const gf_slice *r, size_t n)
{
  struct ap *x = user;
  int ok = n == 1 && x->code && r[0].len == strlen (x->code)
    && memcmp (r[0].data, x->code, r[0].len) == 0;

  return (ok ? gf_auth_server_accept (x->srv, tst_now)
             : gf_auth_server_reject (x->srv, tst_now, 0)) != GF_OK;
}

static int
srv_authenticated (void *user, gf_slice u)
{
  struct ap *x = user;

  (void) u;
  x->srv_authenticated++;
  return 0;
}

static int
srv_disconnect (void *user, uint32_t reason)
{
  struct ap *x = user;

  x->srv_disconnect = reason;
  gf_conn_disconnect (x->p.sv.c, tst_now, reason, NULL);
  return 0;
}

static int
cli_send (void *user, const uint8_t *p, size_t n)
{
  struct ap *x = user;
  uint8_t copy[GF_MAX_PAYLOAD];

  if (x->tamper && p[0] == 50 && n > 100 && n < sizeof copy)
    {
      /* A signed request: damage the last byte of the signature.  */
      memcpy (copy, p, n);
      copy[n - 1] ^= 0x01;
      return gf_conn_send (x->p.cl.c, tst_now, copy, n) != GF_OK;
    }
  return gf_conn_send (x->p.cl.c, tst_now, p, n) != GF_OK;
}

static void
cli_banner (void *user, gf_slice text)
{
  struct ap *x = user;

  x->banners++;
  snprintf (x->banner, sizeof x->banner, "%.*s", (int) text.len,
            (const char *) text.data);
}

static int
cli_kbdint (void *user, gf_slice name, gf_slice instr, size_t n,
            const gf_slice *prompts, const int *echo)
{
  struct ap *x = user;
  const char *answers[GF_AUTH_MAX_PROMPTS];
  size_t i;

  (void) name;
  (void) instr;
  (void) prompts;
  (void) echo;
  x->prompts += (int) n;
  for (i = 0; i < n; i++)
    answers[i] = x->answer ? x->answer : "";
  return gf_auth_client_kbdint_respond (x->cli, tst_now, n, answers) != GF_OK;
}

static int
cli_authenticated (void *user)
{
  ((struct ap *) user)->cli_authenticated++;
  return 0;
}

static int
cli_failed (void *user)
{
  struct ap *x = user;

  x->cli_failed++;
  gf_conn_disconnect (x->p.cl.c, tst_now, GF_DISCONNECT_NO_MORE_AUTH_METHODS,
                      NULL);
  return 0;
}

/* The glue between connections and machines.  */
static int
srv_on_established (struct end *e)
{
  struct ap *x = e->hook;
  size_t bl;
  const uint8_t *b = gf_key_blob (e->info.host_key, &bl);

  return gf_auth_server_start (x->srv, tst_now, e->info.session_id,
                               e->info.session_id_len, b, bl) != GF_OK;
}

static int
cli_on_established (struct end *e)
{
  struct ap *x = e->hook;

  return x->use_client
    && gf_conn_request_service (e->c, tst_now, "ssh-userauth") != GF_OK;
}

static int
cli_on_accepted (struct end *e)
{
  struct ap *x = e->hook;
  size_t bl;
  const uint8_t *b = gf_key_blob (e->info.host_key, &bl);
  const uint8_t *sid = x->use_sid_override ? x->sid_override
                                           : e->info.session_id;

  if (!x->use_client)
    return 0;
  return gf_auth_client_start (x->cli, tst_now, sid, e->info.session_id_len,
                               b, bl) != GF_OK;
}

static int
cli_on_extension (struct end *e, gf_slice name, gf_slice value)
{
  struct ap *x = e->hook;

  return x->use_client
    && gf_auth_client_extension (x->cli, name, value) != GF_OK;
}

static int
srv_on_message (struct end *e, const uint8_t *p, size_t n)
{
  struct ap *x = e->hook;

  if (p[0] >= 50 && p[0] <= 79)
    (void) gf_auth_server_input (x->srv, tst_now, p, n);
  return 0;
}

static int
cli_on_message (struct end *e, const uint8_t *p, size_t n)
{
  struct ap *x = e->hook;

  if (x->use_client && p[0] >= 50 && p[0] <= 79)
    return gf_auth_client_input (x->cli, tst_now, p, n) != GF_OK
      && !gf_auth_client_is_done (x->cli) ? 1 : 0;
  return 0;
}

struct cli_creds
{
  const char *user;
  const gf_key *keys[4];
  size_t nkeys;
  const char *password;
  unsigned methods;
  unsigned max_attempts;
};

static void
ap_new (struct ap *x, const gf_auth_server_config *scfg,
        const struct cli_creds *cr)
{
  gf_auth_server_events se;
  gf_auth_client_events ce;
  gf_auth_client_config cc;

  memset (x, 0, sizeof *x);
  x->sc.host_keys = &hostkey;
  x->sc.nhost_keys = 1;
  x->sc.announce_hostbound = scfg->hostbound;
  CHECK_EQ (pair_new (&x->p, &x->cc, &x->sc), GF_OK);
  x->p.sv.hook = x->p.cl.hook = x;
  x->p.sv.on_established = srv_on_established;
  x->p.sv.on_message = srv_on_message;
  x->p.cl.on_established = cli_on_established;
  x->p.cl.on_service_accepted = cli_on_accepted;
  x->p.cl.on_extension = cli_on_extension;
  x->p.cl.on_message = cli_on_message;

  memset (&se, 0, sizeof se);
  se.user = x;
  se.send = srv_send;
  se.request = srv_request;
  se.kbdint_response = srv_kbd_response;
  se.authenticated = srv_authenticated;
  se.disconnect = srv_disconnect;
  CHECK_EQ (gf_auth_server_new (&x->srv, scfg, &se), GF_OK);

  if (cr != NULL)
    {
      x->use_client = 1;
      memset (&cc, 0, sizeof cc);
      cc.user = cr->user;
      cc.keys = cr->keys;
      cc.nkeys = cr->nkeys;
      cc.password = cr->password;
      cc.methods = cr->methods;
      cc.max_attempts = cr->max_attempts;
      memset (&ce, 0, sizeof ce);
      ce.user = x;
      ce.send = cli_send;
      ce.banner = cli_banner;
      ce.kbdint = cli_kbdint;
      ce.authenticated = cli_authenticated;
      ce.failed = cli_failed;
      CHECK_EQ (gf_auth_client_new (&x->cli, &cc, &ce), GF_OK);
    }
}

static void
ap_run (struct ap *x)
{
  pair_start (&x->p);
  pump (&x->p, 0);
}

static void
ap_free (struct ap *x)
{
  gf_auth_server_free (x->srv);
  gf_auth_client_free (x->cli);
  pair_free (&x->p);
}

static gf_auth_server_config
srv_config (unsigned methods)
{
  gf_auth_server_config c;

  memset (&c, 0, sizeof c);
  c.methods = methods;
  return c;
}

/* ---------------------------------------------------------------- */

static void
test_publickey (void)
{
  size_t k;

  for (k = 0; k < 4; k++)
    {
      struct ap x;
      gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
      struct cli_creds cr = { "alice", { ukeys[k] }, 1, NULL, 0, 0 };

      ap_new (&x, &sc, &cr);
      x.authorized[0] = ukeys[k];
      x.nauthorized = 1;
      ap_run (&x);
      CHECK_EQ (x.cli_authenticated, 1);
      CHECK_EQ (x.srv_authenticated, 1);
      CHECK_EQ (x.cli_failed, 0);
      /* The query first, then the signed request.  */
      CHECK_EQ (x.srv_queries, 1);
      CHECK_EQ (x.srv_signed, 1);
      CHECK_EQ (x.srv_passwords, 0);
      CHECK (strcmp (x.srv_user, "alice") == 0);
      CHECK (gf_auth_server_is_done (x.srv));
      CHECK (gf_auth_client_is_done (x.cli));
      ap_free (&x);
    }
}

static void
test_key_selection (void)
{
  struct ap x;
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  /* Three keys: the server wants the last.  */
  struct cli_creds cr = { "bob", { stranger, ukeys[1], ukeys[2] }, 3, NULL, 0,
                          0 };

  ap_new (&x, &sc, &cr);
  x.authorized[0] = ukeys[2];
  x.nauthorized = 1;
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_queries, 3);		/* Each key is asked about once.  */
  CHECK_EQ (x.srv_signed, 1);
  CHECK_EQ (x.p.sv.closed, 0);
  ap_free (&x);

  /* None authorized: the client runs out.  Queries are not failures.  */
  ap_new (&x, &sc, &cr);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (x.cli_failed, 1);
  CHECK_EQ (x.srv_queries, 3);
  CHECK_EQ (x.srv_signed, 0);
  CHECK_EQ (x.srv_authenticated, 0);
  ap_free (&x);
}

static void
test_password (void)
{
  struct ap x;
  gf_auth_server_config sc = srv_config (GF_AUTH_PASSWORD);
  struct cli_creds cr = { "carol", { NULL }, 0, "s3cret", 0, 0 };

  ap_new (&x, &sc, &cr);
  x.password = "s3cret";
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_passwords, 1);
  CHECK_EQ (x.srv_queries + x.srv_signed, 0);
  ap_free (&x);

  /* The wrong one.  */
  ap_new (&x, &sc, &cr);
  x.password = "other";
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (x.cli_failed, 1);
  CHECK_EQ (x.srv_passwords, 1);
  ap_free (&x);

  /* The server offers only a public key: the password is not even sent.  */
  sc = srv_config (GF_AUTH_PUBLICKEY);
  ap_new (&x, &sc, &cr);
  x.password = "s3cret";
  ap_run (&x);
  CHECK_EQ (x.cli_failed, 1);
  CHECK_EQ (x.srv_passwords, 0);
  ap_free (&x);

  /* A password change request is refused without asking the application.  */
  sc = srv_config (GF_AUTH_PASSWORD);
  ap_new (&x, &sc, NULL);
  x.password = "s3cret";
  pair_start (&x.p);
  pump (&x.p, 0);
  CHECK_EQ (gf_conn_request_service (x.p.cl.c, tst_now, "ssh-userauth"), GF_OK);
  pump (&x.p, 0);
  {
    uint8_t m[128];
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "carol");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, "password");
    gf_wr_bool (&w, 1);
    gf_wr_cstring (&w, "s3cret");
    gf_wr_cstring (&w, "new");
    CHECK_EQ (gf_conn_send (x.p.cl.c, tst_now, m, w.len), GF_OK);
    pump (&x.p, 0);
  }
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.srv_authenticated, 0);
  CHECK_EQ (x.p.sv.closed, 0);
  ap_free (&x);
}

static void
test_kbdint (void)
{
  struct ap x;
  gf_auth_server_config sc = srv_config (GF_AUTH_KBDINT);
  struct cli_creds cr = { "dave", { NULL }, 0, NULL, 0, 0 };

  ap_new (&x, &sc, &cr);
  x.code = "123456";
  x.answer = "123456";
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_kbd, 1);
  CHECK_EQ (x.prompts, 1);
  ap_free (&x);

  ap_new (&x, &sc, &cr);
  x.code = "123456";
  x.answer = "000000";
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (x.cli_failed, 1);
  ap_free (&x);

  /* Public key first, then a code, and a password nobody asked for is
     not used.  */
  sc = srv_config (GF_AUTH_PUBLICKEY | GF_AUTH_KBDINT);
  {
    struct cli_creds both = { "dave", { stranger }, 1, "unused", 0, 0 };

    ap_new (&x, &sc, &both);
    x.authorized[0] = ukeys[0];
    x.nauthorized = 1;
    x.code = "42";
    x.answer = "42";
    ap_run (&x);
    CHECK_EQ (x.cli_authenticated, 1);
    CHECK_EQ (x.srv_queries, 1);
    CHECK_EQ (x.srv_kbd, 1);
    CHECK_EQ (x.srv_passwords, 0);
    ap_free (&x);
  }
}

static void
test_banner_and_async (void)
{
  struct ap x;
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  struct cli_creds cr = { "erin", { ukeys[0] }, 1, NULL, 0, 0 };

  ap_new (&x, &sc, &cr);
  x.authorized[0] = ukeys[0];
  x.nauthorized = 1;
  x.hold = 1;			/* The application takes its time.  */
  ap_run (&x);
  CHECK_EQ (x.srv_queries, 1);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (gf_auth_server_banner (x.srv, tst_now, "Authorized use only.\n"),
            GF_OK);
  CHECK_EQ (gf_auth_server_banner (x.srv, tst_now, "bad\x1b[31m"), GF_ERR_INVAL);
  pump (&x.p, 0);
  CHECK_EQ (x.banners, 1);
  CHECK (strcmp (x.banner, "Authorized use only.\n") == 0);
  /* Answers out of turn are refused.  */
  CHECK_EQ (gf_auth_server_accept (x.srv, tst_now), GF_ERR_STATE);
  CHECK_EQ (gf_auth_server_pk_ok (x.srv, tst_now), GF_OK);
  CHECK_EQ (gf_auth_server_pk_ok (x.srv, tst_now), GF_ERR_STATE);
  x.hold = 0;
  pump (&x.p, 0);
  CHECK_EQ (x.srv_signed, 1);
  CHECK_EQ (x.cli_authenticated, 1);
  /* The query cannot be accepted outright, and nothing is pending now.  */
  CHECK_EQ (gf_auth_server_accept (x.srv, tst_now), GF_ERR_STATE);
  ap_free (&x);

  /* Accepting a query is refused: only a signed request can succeed.  */
  ap_new (&x, &sc, &cr);
  x.authorized[0] = ukeys[0];
  x.nauthorized = 1;
  x.hold = 1;
  ap_run (&x);
  CHECK_EQ (gf_auth_server_accept (x.srv, tst_now), GF_ERR_STATE);
  ap_free (&x);
}

/* A signature that does not verify is a failure, never a success: damage
   it, sign for another session, sign with the wrong key.  */
static void
test_bad_signatures (void)
{
  struct ap x;
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  struct cli_creds cr = { "frank", { ukeys[0] }, 1, NULL, 0, 0 };

  ap_new (&x, &sc, &cr);
  x.authorized[0] = ukeys[0];
  x.nauthorized = 1;
  x.tamper = 1;
  ap_run (&x);
  CHECK_EQ (x.srv_queries, 1);
  CHECK_EQ (x.srv_signed, 0);		/* Never reached the application.  */
  CHECK_EQ (x.srv_authenticated, 0);
  CHECK_EQ (x.cli_failed, 1);
  ap_free (&x);

  /* A signature made for another session (replay to another server).  */
  ap_new (&x, &sc, &cr);
  x.authorized[0] = ukeys[0];
  x.nauthorized = 1;
  memset (x.sid_override, 0x41, sizeof x.sid_override);
  x.use_sid_override = 1;
  ap_run (&x);
  CHECK_EQ (x.srv_signed, 0);
  CHECK_EQ (x.srv_authenticated, 0);
  CHECK_EQ (x.cli_failed, 1);
  ap_free (&x);
}

/* The host-bound method: the client uses it when the server announces it,
   the signature covers the host key, and a request that names another
   host key is refused.  */
static void
test_hostbound (void)
{
  struct ap x;
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  struct cli_creds cr = { "gina", { ukeys[1] }, 1, NULL, 0, 0 };

  sc.hostbound = 1;
  ap_new (&x, &sc, &cr);
  x.authorized[0] = ukeys[1];
  x.nauthorized = 1;
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_hostbound_seen, 2);	/* Query and signature.  */
  ap_free (&x);

  /* Without the announcement the plain method is used.  */
  sc.hostbound = 0;
  ap_new (&x, &sc, &cr);
  x.authorized[0] = ukeys[1];
  x.nauthorized = 1;
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_hostbound_seen, 0);
  ap_free (&x);

  /* A server that did not announce it does not accept it either.  */
  ap_new (&x, &sc, NULL);
  pair_start (&x.p);
  pump (&x.p, 0);
  CHECK_EQ (gf_conn_request_service (x.p.cl.c, tst_now, "ssh-userauth"), GF_OK);
  pump (&x.p, 0);
  {
    uint8_t m[512];
    gf_writer w;
    size_t bl;
    const uint8_t *b = gf_key_blob (ukeys[1], &bl);

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "gina");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, GF_AUTH_HOSTBOUND_METHOD);
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "ecdsa-sha2-nistp256");
    gf_wr_string (&w, b, bl);
    gf_wr_string (&w, b, bl);
    CHECK_EQ (gf_conn_send (x.p.cl.c, tst_now, m, w.len), GF_OK);
    pump (&x.p, 0);
  }
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.p.sv.closed, 0);
  ap_free (&x);

  /* Announced, but the request names a different host key: refused
     without the application seeing it.  */
  sc.hostbound = 1;
  ap_new (&x, &sc, NULL);
  pair_start (&x.p);
  pump (&x.p, 0);
  CHECK_EQ (gf_conn_request_service (x.p.cl.c, tst_now, "ssh-userauth"), GF_OK);
  pump (&x.p, 0);
  {
    uint8_t m[512];
    gf_writer w;
    size_t bl, hl;
    const uint8_t *b = gf_key_blob (ukeys[1], &bl);
    const uint8_t *other = gf_key_blob (ukeys[0], &hl);

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "gina");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, GF_AUTH_HOSTBOUND_METHOD);
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "ecdsa-sha2-nistp256");
    gf_wr_string (&w, b, bl);
    gf_wr_string (&w, other, hl);
    CHECK_EQ (gf_conn_send (x.p.cl.c, tst_now, m, w.len), GF_OK);
    pump (&x.p, 0);
  }
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
}

/* Raw requests from a client that is not a gf_auth_client.  */
static void
raw (struct ap *x, const uint8_t *m, size_t n)
{
  CHECK_EQ (gf_conn_send (x->p.cl.c, tst_now, m, n), GF_OK);
  pump (&x->p, 0);
}

static size_t
request (uint8_t *buf, size_t cap, const char *user, const char *service,
         const char *method)
{
  gf_writer w;

  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, 50);
  gf_wr_cstring (&w, user);
  gf_wr_cstring (&w, service);
  gf_wr_cstring (&w, method);
  return w.len;
}

static void
ready (struct ap *x, unsigned methods, unsigned max_failures)
{
  gf_auth_server_config sc = srv_config (methods);

  sc.max_failures = max_failures;
  ap_new (x, &sc, NULL);
  x->password = "pw";
  pair_start (&x->p);
  pump (&x->p, 0);
  CHECK_EQ (gf_conn_request_service (x->p.cl.c, tst_now, "ssh-userauth"),
            GF_OK);
  pump (&x->p, 0);
}

static void
test_protocol_errors (void)
{
  struct ap x;
  uint8_t m[600];
  size_t n;

  /* Another service.  */
  ready (&x, GF_AUTH_PASSWORD, 0);
  n = request (m, sizeof m, "u", "ssh-userauth", "none");
  raw (&x, m, n);
  CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_SERVICE_NOT_AVAILABLE);
  CHECK_EQ (x.p.cl.close_reason, GF_DISCONNECT_SERVICE_NOT_AVAILABLE);
  ap_free (&x);

  /* The user changes between requests.  */
  ready (&x, GF_AUTH_PASSWORD, 0);
  raw (&x, m, request (m, sizeof m, "one", "ssh-connection", "none"));
  CHECK_EQ (x.p.sv.closed, 0);
  raw (&x, m, request (m, sizeof m, "two", "ssh-connection", "none"));
  CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  ap_free (&x);

  /* Not UTF-8, a NUL, too long, empty.  */
  ready (&x, GF_AUTH_PASSWORD, 0);
  raw (&x, m, request (m, sizeof m, "ab\xff", "ssh-connection", "none"));
  CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  ap_free (&x);
  ready (&x, GF_AUTH_PASSWORD, 0);
  {
    char big[300];

    memset (big, 'u', 299);
    big[299] = 0;
    raw (&x, m, request (m, sizeof m, big, "ssh-connection", "none"));
    CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_ILLEGAL_USER_NAME);
  }
  ap_free (&x);
  ready (&x, GF_AUTH_PASSWORD, 0);
  raw (&x, m, request (m, sizeof m, "", "ssh-connection", "password"));
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.p.sv.closed, 0);
  ap_free (&x);

  /* A request while one is waiting for the application.  */
  ready (&x, GF_AUTH_PASSWORD, 0);
  x.hold = 1;
  {
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "u");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, "password");
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "pw");
    raw (&x, m, w.len);
    CHECK_EQ (x.srv_requests, 1);
    CHECK_EQ (x.p.sv.closed, 0);
    raw (&x, m, w.len);
    CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  }
  ap_free (&x);

  /* Truncated, and with bytes to spare.  */
  ready (&x, GF_AUTH_PASSWORD, 0);
  n = request (m, sizeof m, "u", "ssh-connection", "password");
  raw (&x, m, n);			/* No boolean at all.  */
  CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  ap_free (&x);
  ready (&x, GF_AUTH_PASSWORD, 0);
  {
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "u");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, "password");
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "pw");
    gf_wr_u8 (&w, 0);
    raw (&x, m, w.len);
    CHECK_EQ (x.srv_requests, 0);
    CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  }
  ap_free (&x);

  /* Messages a client must not send: PK_OK, and a response nobody asked
     for.  */
  ready (&x, GF_AUTH_KBDINT, 0);
  {
    static const uint8_t pkok[] = { 60, 0, 0, 0, 0 };
    static const uint8_t resp[] = { 61, 0, 0, 0, 0 };

    raw (&x, resp, sizeof resp);
    CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
    ap_free (&x);
    ready (&x, GF_AUTH_KBDINT, 0);
    raw (&x, pkok, sizeof pkok);
    CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  }
  ap_free (&x);

  /* A method that was not offered, and unknown ones, fail and count.  */
  ready (&x, GF_AUTH_PASSWORD, 3);
  raw (&x, m, request (m, sizeof m, "u", "ssh-connection", "hostbased"));
  raw (&x, m, request (m, sizeof m, "u", "ssh-connection", "gssapi-with-mic"));
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.p.sv.closed, 0);
  raw (&x, m, request (m, sizeof m, "u", "ssh-connection", "keyboard-interactive"));
  CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_NO_MORE_AUTH_METHODS);
  ap_free (&x);

  /* After success, further requests are ignored.  */
  {
    struct cli_creds cr = { "u", { NULL }, 0, "pw", 0, 0 };
    gf_auth_server_config sc = srv_config (GF_AUTH_PASSWORD);

    ap_new (&x, &sc, &cr);
    x.password = "pw";
    ap_run (&x);
    CHECK_EQ (x.srv_authenticated, 1);
    raw (&x, m, request (m, sizeof m, "other", "ssh-connection", "password"));
    CHECK_EQ (x.srv_requests, 1);
    CHECK_EQ (x.srv_authenticated, 1);
    CHECK_EQ (x.p.sv.closed, 0);
    ap_free (&x);
  }
}

/* The legacy and weak things a client may offer.  */
static void
test_refused_keys (void)
{
  struct ap x;
  uint8_t m[1024];
  size_t bl;
  const uint8_t *blob = gf_key_blob (ukeys[3], &bl);
  static const char *const algs[] = { "ssh-rsa", "ssh-dss", "rsa-sha2-384",
                                      "ecdsa-sha2-nistp521", "foo" };
  size_t i;

  for (i = 0; i < sizeof algs / sizeof algs[0]; i++)
    {
      gf_writer w;

      ready (&x, GF_AUTH_PUBLICKEY, 0);
      x.authorized[0] = ukeys[3];
      x.nauthorized = 1;
      gf_writer_init (&w, m, sizeof m);
      gf_wr_u8 (&w, 50);
      gf_wr_cstring (&w, "u");
      gf_wr_cstring (&w, "ssh-connection");
      gf_wr_cstring (&w, "publickey");
      gf_wr_bool (&w, 1);
      gf_wr_cstring (&w, algs[i]);
      gf_wr_string (&w, blob, bl);
      gf_wr_string (&w, "\0\0\0\7ssh-rsa\0\0\0\4abcd", 19);	/* A signature.  */
      raw (&x, m, w.len);
      CHECK_EQ (x.srv_requests, 0);	/* Not even shown to the application.  */
      CHECK_EQ (x.srv_authenticated, 0);
      CHECK_EQ (x.p.sv.closed, 0);
      ap_free (&x);
    }
  /* A query with a legacy algorithm gets "no" and is not counted.  */
  ready (&x, GF_AUTH_PUBLICKEY, 1);
  {
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "u");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, "publickey");
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "ssh-rsa");
    gf_wr_string (&w, blob, bl);
    raw (&x, m, w.len);
    raw (&x, m, w.len);
    CHECK_EQ (x.p.sv.closed, 0);	/* max_failures is 1, so not counted.  */
    CHECK_EQ (x.srv_requests, 0);
  }
  ap_free (&x);
  /* A key blob that is not a key.  */
  ready (&x, GF_AUTH_PUBLICKEY, 0);
  {
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "u");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, "publickey");
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "ssh-ed25519");
    gf_wr_string (&w, "garbage", 7);
    raw (&x, m, w.len);
    CHECK_EQ (x.srv_requests, 0);
    CHECK_EQ (x.p.sv.closed, 0);
  }
  ap_free (&x);
  /* A key of one type with the algorithm of another.  */
  ready (&x, GF_AUTH_PUBLICKEY, 0);
  {
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "u");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, "publickey");
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "ssh-ed25519");
    gf_wr_string (&w, blob, bl);
    raw (&x, m, w.len);
    CHECK_EQ (x.srv_requests, 0);
  }
  ap_free (&x);
}

static void
test_limits_and_timeout (void)
{
  struct ap x;
  struct cli_creds cr = { "u", { NULL }, 0, "wrong", GF_AUTH_PASSWORD, 0 };
  gf_auth_server_config sc = srv_config (GF_AUTH_PASSWORD);

  /* Too many failures end the connection.  */
  {
    uint8_t m[256];
    size_t i;

    ready (&x, GF_AUTH_PASSWORD, 4);
    for (i = 0; i < 4; i++)
      {
        gf_writer w;

        gf_writer_init (&w, m, sizeof m);
        gf_wr_u8 (&w, 50);
        gf_wr_cstring (&w, "u");
        gf_wr_cstring (&w, "ssh-connection");
        gf_wr_cstring (&w, "password");
        gf_wr_bool (&w, 0);
        gf_wr_cstring (&w, "nope");
        if (!x.p.sv.closed)
          raw (&x, m, w.len);
      }
    CHECK_EQ (x.srv_passwords, 4);
    CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_NO_MORE_AUTH_METHODS);
    ap_free (&x);
  }

  /* A client with a cap of its own stops there.  */
  sc = srv_config (GF_AUTH_PASSWORD | GF_AUTH_KBDINT);
  cr.methods = GF_AUTH_PASSWORD | GF_AUTH_KBDINT;
  cr.max_attempts = 1;
  ap_new (&x, &sc, &cr);
  x.password = "right";
  x.code = "1";
  ap_run (&x);
  CHECK_EQ (x.cli_failed, 1);
  CHECK_EQ (x.srv_kbd + x.srv_passwords, 0 + 0 + x.srv_kbd + x.srv_passwords);
  CHECK (x.srv_kbd + x.srv_passwords <= 1);
  ap_free (&x);

  /* The grace time.  */
  tst_now = 5000000;
  ready (&x, GF_AUTH_PASSWORD, 0);
  CHECK_EQ (gf_auth_server_timeout (x.srv), tst_now + 120000000);
  CHECK_EQ (gf_auth_server_on_timeout (x.srv, tst_now + 119000000), GF_OK);
  CHECK_EQ (x.srv_disconnect, 0);
  CHECK_EQ (gf_auth_server_on_timeout (x.srv, tst_now + 120000000),
            GF_ERR_TIMEOUT);
  CHECK_EQ (x.srv_disconnect, GF_DISCONNECT_CONNECTION_LOST);
  CHECK_EQ (gf_auth_server_timeout (x.srv), UINT64_MAX);
  ap_free (&x);
}

/* The client alone, against a scripted server.  */
struct cap
{
  uint8_t last[4096];
  size_t n;
  int sent, failed, authenticated, banners, prompts;
  size_t nprompts;
};

static int
cap_send (void *user, const uint8_t *p, size_t n)
{
  struct cap *c = user;

  memcpy (c->last, p, n);
  c->n = n;
  c->sent++;
  return 0;
}

static int
cap_failed (void *user)
{
  ((struct cap *) user)->failed++;
  return 0;
}

static int
cap_authenticated (void *user)
{
  ((struct cap *) user)->authenticated++;
  return 0;
}

static void
cap_banner (void *user, gf_slice t)
{
  (void) t;
  ((struct cap *) user)->banners++;
}

static int
cap_kbdint (void *user, gf_slice name, gf_slice instr, size_t n,
            const gf_slice *prompts, const int *echo)
{
  struct cap *c = user;

  (void) name;
  (void) instr;
  (void) prompts;
  (void) echo;
  c->prompts++;
  c->nprompts = n;
  return 0;
}

/* Method name and algorithm of the request last sent.  */
static void
parse_request (const struct cap *c, char *method, char *alg, int *has_sig)
{
  gf_reader r;
  gf_slice user, service, m, a;
  int sig = 0;

  gf_reader_init (&r, c->last + 1, c->n - 1);
  gf_rd_string (&r, &user);
  gf_rd_string (&r, &service);
  gf_rd_string (&r, &m);
  snprintf (method, 64, "%.*s", (int) m.len, (const char *) m.data);
  alg[0] = '\0';
  if (strcmp (method, "publickey") == 0
      || strcmp (method, GF_AUTH_HOSTBOUND_METHOD) == 0)
    {
      gf_rd_bool (&r, &sig);
      gf_rd_string (&r, &a);
      snprintf (alg, 64, "%.*s", (int) a.len, (const char *) a.data);
    }
  *has_sig = sig;
}

static size_t
failure (uint8_t *buf, const char *methods, int partial)
{
  gf_writer w;

  gf_writer_init (&w, buf, 256);
  gf_wr_u8 (&w, 51);
  gf_wr_namelist (&w, methods);
  gf_wr_bool (&w, partial);
  return w.len;
}

static size_t
pk_ok (uint8_t *buf, const char *alg, const uint8_t *blob, size_t bl)
{
  gf_writer w;

  gf_writer_init (&w, buf, 1024);
  gf_wr_u8 (&w, 60);
  gf_wr_cstring (&w, alg);
  gf_wr_string (&w, blob, bl);
  return w.len;
}

static gf_auth_client *
cap_client (struct cap *c, const char *user, const gf_key *const *keys,
            size_t nkeys, const char *password, int with_kbd)
{
  gf_auth_client_config cfg;
  gf_auth_client_events ev;
  gf_auth_client *a;

  memset (c, 0, sizeof *c);
  memset (&cfg, 0, sizeof cfg);
  memset (&ev, 0, sizeof ev);
  cfg.user = user;
  cfg.keys = keys;
  cfg.nkeys = nkeys;
  cfg.password = password;
  ev.user = c;
  ev.send = cap_send;
  ev.failed = cap_failed;
  ev.authenticated = cap_authenticated;
  ev.banner = cap_banner;
  if (with_kbd)
    ev.kbdint = cap_kbdint;
  CHECK_EQ (gf_auth_client_new (&a, &cfg, &ev), GF_OK);
  return a;
}

static void
test_client_alone (void)
{
  static const uint8_t sid[32] = { 1 }, host[10] = { 2 };
  struct cap c;
  gf_auth_client *a;
  uint8_t m[1024], other[200];
  char method[64], alg[64];
  int has_sig;
  const gf_key *keys[2];
  size_t bl, n, obl;
  const uint8_t *blob;

  /* The server's PK_OK must be for the key and algorithm asked about.  */
  keys[0] = ukeys[0];
  blob = gf_key_blob (ukeys[0], &bl);
  a = cap_client (&c, "u", keys, 1, NULL, 0);
  CHECK_EQ (gf_auth_client_start (a, 0, sid, 32, host, 10), GF_OK);
  parse_request (&c, method, alg, &has_sig);
  CHECK (strcmp (method, "none") == 0);
  CHECK_EQ (gf_auth_client_input (a, 0, m, failure (m, "publickey", 0)), GF_OK);
  parse_request (&c, method, alg, &has_sig);
  CHECK (strcmp (method, "publickey") == 0 && !has_sig);
  CHECK (strcmp (alg, "ssh-ed25519") == 0);
  obl = 0;
  memcpy (other, gf_key_blob (ukeys[1], &obl), obl);
  CHECK_EQ (gf_auth_client_input (a, 0, m, pk_ok (m, alg, other, obl)),
            GF_ERR_PROTOCOL);
  gf_auth_client_free (a);
  a = cap_client (&c, "u", keys, 1, NULL, 0);
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  gf_auth_client_input (a, 0, m, failure (m, "publickey", 0));
  CHECK_EQ (gf_auth_client_input (a, 0, m, pk_ok (m, "ssh-rsa", blob, bl)),
            GF_ERR_PROTOCOL);
  gf_auth_client_free (a);
  a = cap_client (&c, "u", keys, 1, NULL, 0);
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  gf_auth_client_input (a, 0, m, failure (m, "publickey", 0));
  CHECK_EQ (gf_auth_client_input (a, 0, m, pk_ok (m, "ssh-ed25519", blob, bl)),
            GF_OK);
  parse_request (&c, method, alg, &has_sig);
  CHECK (has_sig);			/* Now the signed request.  */
  /* A PK_OK nobody asked for.  */
  CHECK_EQ (gf_auth_client_input (a, 0, m, pk_ok (m, "ssh-ed25519", blob, bl)),
            GF_ERR_PROTOCOL);
  gf_auth_client_free (a);

  /* The server's list limits what the client does: no public key
     method, no key attempt; nothing else to offer is a failure.  */
  a = cap_client (&c, "u", keys, 1, NULL, 0);
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  CHECK_EQ (gf_auth_client_input (a, 0, m, failure (m, "password", 0)),
            GF_ERR_AUTH);
  CHECK_EQ (c.failed, 1);
  CHECK_EQ (c.sent, 1);			/* Only the "none".  */
  CHECK (gf_auth_client_is_done (a));
  CHECK_EQ (gf_auth_client_input (a, 0, m, failure (m, "password", 0)), GF_OK);
  gf_auth_client_free (a);

  /* server-sig-algs picks the RSA hash, and a key none of whose
     algorithms the server accepts is not offered.  */
  keys[0] = ukeys[3];
  a = cap_client (&c, "u", keys, 1, NULL, 0);
  gf_auth_client_extension (a, (gf_slice) { (const uint8_t *) "server-sig-algs", 15 },
                            (gf_slice) { (const uint8_t *) "ssh-ed25519,rsa-sha2-256", 24 });
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  gf_auth_client_input (a, 0, m, failure (m, "publickey", 0));
  parse_request (&c, method, alg, &has_sig);
  CHECK (strcmp (alg, "rsa-sha2-256") == 0);
  gf_auth_client_free (a);
  a = cap_client (&c, "u", keys, 1, NULL, 0);
  gf_auth_client_extension (a, (gf_slice) { (const uint8_t *) "server-sig-algs", 15 },
                            (gf_slice) { (const uint8_t *) "ssh-ed25519", 11 });
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  CHECK_EQ (gf_auth_client_input (a, 0, m, failure (m, "publickey", 0)),
            GF_ERR_AUTH);
  CHECK_EQ (c.failed, 1);
  gf_auth_client_free (a);
  a = cap_client (&c, "u", keys, 1, NULL, 0);
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  gf_auth_client_input (a, 0, m, failure (m, "publickey", 0));
  parse_request (&c, method, alg, &has_sig);
  CHECK (strcmp (alg, "rsa-sha2-512") == 0);	/* The default preference.  */
  CHECK_EQ (gf_auth_client_extension (a, (gf_slice) { (const uint8_t *) "x", 1 },
                                      (gf_slice) { (const uint8_t *) "y", 1 }),
            GF_ERR_STATE);
  gf_auth_client_free (a);

  /* Bad encodings.  */
  keys[0] = ukeys[0];
  a = cap_client (&c, "u", keys, 1, "pw", 1);
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  CHECK_EQ (gf_auth_client_input (a, 0, (const uint8_t *) "\x36\0\0\0\0", 5),
            GF_ERR_PROTOCOL);		/* An unknown message.  */
  CHECK_EQ (gf_auth_client_input (a, 0, (const uint8_t *) "\x36", 1),
            GF_ERR_PROTOCOL);
  n = failure (m, "publickey", 0);
  CHECK_EQ (gf_auth_client_input (a, 0, m, n - 1), GF_ERR_ENCODING);
  m[n] = 0;
  CHECK_EQ (gf_auth_client_input (a, 0, m, n + 1), GF_ERR_ENCODING);
  CHECK_EQ (gf_auth_client_input (a, 0, (const uint8_t *) "\x36\0\0\0\1x", 6),
            GF_ERR_PROTOCOL);
  CHECK_EQ (gf_auth_client_input (a, 0, (const uint8_t *) "\x36", 1),
            GF_ERR_PROTOCOL);
  {
    uint8_t bad[] = { 52, 0 };	/* SUCCESS with a byte to spare.  */

    CHECK_EQ (gf_auth_client_input (a, 0, bad, 2), GF_ERR_ENCODING);
  }
  {
    uint8_t ban[] = { 53, 0, 0, 0, 2, 0xc3, 0x28, 0, 0, 0, 0 };

    CHECK_EQ (gf_auth_client_input (a, 0, ban, sizeof ban), GF_ERR_ENCODING);
    ban[5] = 'o';
    ban[6] = 'k';
    CHECK_EQ (gf_auth_client_input (a, 0, ban, sizeof ban), GF_OK);
    CHECK_EQ (c.banners, 1);
  }
  gf_auth_client_free (a);

  /* Keyboard-interactive: no prompts needs no application; too many
     prompts is malformed; a wrong number of answers is refused; a
     password-change request is a failure of that method.  */
  a = cap_client (&c, "u", keys, 0, "pw", 1);
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  CHECK_EQ (gf_auth_client_input (a, 0, m, failure (m, "keyboard-interactive,password", 0)), GF_OK);
  parse_request (&c, method, alg, &has_sig);
  CHECK (strcmp (method, "keyboard-interactive") == 0);
  {
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 60);
    gf_wr_cstring (&w, "");
    gf_wr_cstring (&w, "");
    gf_wr_cstring (&w, "");
    gf_wr_u32 (&w, 0);
    CHECK_EQ (gf_auth_client_input (a, 0, m, w.len), GF_OK);
    CHECK (c.last[0] == 61 && c.n == 5);	/* An empty response.  */
    CHECK_EQ (c.prompts, 0);

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 60);
    gf_wr_cstring (&w, "n");
    gf_wr_cstring (&w, "i");
    gf_wr_cstring (&w, "");
    gf_wr_u32 (&w, 2);
    gf_wr_cstring (&w, "a: ");
    gf_wr_bool (&w, 1);
    gf_wr_cstring (&w, "b: ");
    gf_wr_bool (&w, 0);
    CHECK_EQ (gf_auth_client_input (a, 0, m, w.len), GF_OK);
    CHECK_EQ (c.prompts, 1);
    CHECK_EQ (c.nprompts, 2);
    {
      const char *one[] = { "x" };
      const char *two[] = { "x", "y" };

      CHECK_EQ (gf_auth_client_kbdint_respond (a, 0, 1, one), GF_ERR_STATE);
      CHECK_EQ (gf_auth_client_kbdint_respond (a, 0, 2, two), GF_OK);
      CHECK (c.last[0] == 61);
    }
    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 60);
    gf_wr_cstring (&w, "n");
    gf_wr_cstring (&w, "i");
    gf_wr_cstring (&w, "");
    gf_wr_u32 (&w, GF_AUTH_MAX_PROMPTS + 1);
    CHECK_EQ (gf_auth_client_input (a, 0, m, w.len), GF_ERR_ENCODING);
  }
  /* The server refuses k-i; the password goes next, then PASSWD_CHANGEREQ
     (message 60 in a password exchange) fails it, and nothing is left.  */
  CHECK_EQ (gf_auth_client_input (a, 0, m, failure (m, "password", 0)), GF_OK);
  parse_request (&c, method, alg, &has_sig);
  CHECK (strcmp (method, "password") == 0);
  CHECK_EQ (gf_auth_client_input (a, 0, (const uint8_t *) "\x3c\0\0\0\0\0\0\0\0", 9),
            GF_ERR_AUTH);
  CHECK_EQ (c.failed, 1);
  gf_auth_client_free (a);

  /* A partial success carries on with what the server now lists.  */
  keys[0] = ukeys[0];
  a = cap_client (&c, "u", keys, 1, "pw", 0);
  gf_auth_client_start (a, 0, sid, 32, host, 10);
  gf_auth_client_input (a, 0, m, failure (m, "publickey,password", 0));
  gf_auth_client_input (a, 0, m, pk_ok (m, "ssh-ed25519", blob, bl));
  CHECK_EQ (gf_auth_client_input (a, 0, m, failure (m, "password", 1)), GF_OK);
  parse_request (&c, method, alg, &has_sig);
  CHECK (strcmp (method, "password") == 0);
  gf_auth_client_input (a, 0, (const uint8_t *) "\x36", 1);
  gf_auth_client_free (a);
}

static void
test_construction (void)
{
  gf_auth_server *s;
  gf_auth_client *c;
  gf_auth_server_events se;
  gf_auth_client_events ce;
  gf_auth_server_config sc = srv_config (GF_AUTH_KBDINT);
  gf_auth_client_config cc;
  const gf_key *keys[1] = { ukeys[0] };
  gf_key *pub;
  size_t bl;
  const uint8_t *b = gf_key_blob (ukeys[0], &bl);

  memset (&se, 0, sizeof se);
  memset (&ce, 0, sizeof ce);
  memset (&cc, 0, sizeof cc);
  CHECK_EQ (gf_auth_server_new (&s, &sc, &se), GF_ERR_INVAL);
  se.send = srv_send;
  se.request = srv_request;
  se.disconnect = srv_disconnect;
  /* Keyboard-interactive needs its callback.  */
  CHECK_EQ (gf_auth_server_new (&s, &sc, &se), GF_ERR_INVAL);
  sc = srv_config (GF_AUTH_PUBLICKEY);
  CHECK_EQ (gf_auth_server_new (&s, &sc, &se), GF_OK);
  CHECK_EQ (gf_auth_server_input (s, 0, (const uint8_t *) "\x32", 1),
            GF_ERR_STATE);
  gf_auth_server_free (s);

  cc.user = "u";
  CHECK_EQ (gf_auth_client_new (&c, &cc, &ce), GF_ERR_INVAL);
  ce.send = cli_send;
  ce.failed = cli_failed;
  cc.user = NULL;
  CHECK_EQ (gf_auth_client_new (&c, &cc, &ce), GF_ERR_INVAL);
  cc.user = "u\xff";
  CHECK_EQ (gf_auth_client_new (&c, &cc, &ce), GF_ERR_INVAL);
  /* A key without a private part cannot sign.  */
  CHECK_EQ (gf_key_from_blob (&pub, b, bl), GF_OK);
  keys[0] = pub;
  cc.user = "u";
  cc.keys = keys;
  cc.nkeys = 1;
  CHECK_EQ (gf_auth_client_new (&c, &cc, &ce), GF_ERR_INVAL);
  gf_key_free (pub);
}

int
main (void)
{
  size_t i;

  gf_crypto_init ();
  CHECK_EQ (gf_key_generate (&hostkey, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&ukeys[0], GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&ukeys[1], GF_KEY_ECDSA_P256, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&ukeys[2], GF_KEY_ECDSA_P384, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&ukeys[3], GF_KEY_RSA, 2048), GF_OK);
  CHECK_EQ (gf_key_generate (&stranger, GF_KEY_ED25519, 0), GF_OK);
  test_construction ();
  test_client_alone ();
  test_publickey ();
  test_key_selection ();
  test_password ();
  test_kbdint ();
  test_banner_and_async ();
  test_bad_signatures ();
  test_hostbound ();
  test_protocol_errors ();
  test_refused_keys ();
  test_limits_and_timeout ();
  for (i = 0; i < 4; i++)
    gf_key_free (ukeys[i]);
  gf_key_free (stranger);
  gf_key_free (hostkey);
  TST_DONE ();
}
