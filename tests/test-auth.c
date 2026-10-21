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
#include "vectors-cert.h"
#ifdef HAVE_GNUTLS
# include "vectors-x509.h"
#endif

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
  int accept_certs;		/* Accept any certificate the machine passed.  */
  int srv_cert_seen;		/* Requests with a verified certificate.  */
  int srv_cert_keys;		/* Requests whose key is a certificate.  */
  int srv_verify_required;
  int srv_x509_seen;
  char srv_subject[128];
  enum gf_sigalg srv_sigalg;
  uint8_t srv_sk_flags;
  uint32_t srv_sk_counter;
  char srv_force[64];
  uint64_t unix_now;
  char srv_user[64];
  enum gf_auth_method last_method;

  /* Client application.  */
  const char *answer;
  int cli_authenticated, cli_failed, banners, prompts;
  char banner[128];
  int tamper;			/* Flip a byte of what the client signs.  */
  /* A signer standing in for an agent or a token.  */
  int sign_mode, sign_calls;
  enum gf_sigalg sign_alg;
  const gf_key *signers[8];	/* Private keys, found by their public part.  */
  size_t nsigners;
  const gf_key *wrong_signer;	/* Signs under SIGN_OTHER.  */
  const gf_key *token_plain;	/* The token's key, for SIGN_TOKEN.  */
  uint8_t token_flags;
  const uint8_t *token_handle;	/* SIGN_TOKEN_PACKED: the credential.  */
  size_t token_handle_len;
  uint8_t stash[GF_SIG_MAX];
  size_t stashlen;
  int pending;
  int sent_signed;		/* Signed public key requests the client sent.  */
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
      x->srv_sigalg = req->sigalg;
      if (req->has_signature)
        {
          x->srv_sk_flags = req->sk_flags;
          x->srv_sk_counter = req->sk_counter;
        }
      if (gf_key_is_certificate (req->key))
        x->srv_cert_keys++;
      if (req->x509)
        {
          x->srv_x509_seen++;
          x->srv_subject[0] = '\0';
          (void) gf_x509_subject (req->key, x->srv_subject, sizeof x->srv_subject);
          if (x->accept_certs)
            ok = 1;
        }
      if (req->certificate)
        {
          x->srv_cert_seen++;
          x->srv_verify_required = req->verify_required;
          snprintf (x->srv_force, sizeof x->srv_force, "%.*s",
                    (int) req->force_command.len,
                    (const char *) req->force_command.data);
          if (x->accept_certs)
            ok = 1;
        }
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

static uint64_t
srv_unix_time (void *user)
{
  return ((struct ap *) user)->unix_now;
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

  if (p[0] == 50)
    {
      gf_reader r;
      gf_slice name, service, method;
      int has_sig;

      gf_reader_init (&r, p + 1, n - 1);
      if (gf_rd_string (&r, &name) == GF_OK && gf_rd_string (&r, &service) == GF_OK
          && gf_rd_string (&r, &method) == GF_OK
          && (gf_slice_equals (method, "publickey")
              || gf_slice_equals (method, GF_AUTH_HOSTBOUND_METHOD))
          && gf_rd_bool (&r, &has_sig) == GF_OK && has_sig)
        x->sent_signed++;
    }
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

enum
{
  SIGN_NONE, SIGN_SYNC, SIGN_ASYNC, SIGN_REFUSE, SIGN_FAIL, SIGN_FAIL_ASYNC,
  SIGN_BADSIG, SIGN_WRONGDATA, SIGN_OTHER, SIGN_TOKEN, SIGN_TOKEN_ASYNC,
  SIGN_SYNC_AND_REFUSE,		/* Answers, then says it could not.  */
  SIGN_TOKEN_PACKED		/* A token's raw answer, packed by the library.  */
};

static size_t token_sign (const gf_key *plain, const char *app, const uint8_t *m,
                          size_t ml, uint8_t flags, uint32_t counter,
                          uint8_t *out, size_t cap);

static size_t token_answer_packed (const struct ap *x, const gf_key *key,
                                   enum gf_sigalg alg, gf_slice data,
                                   uint8_t *out, size_t cap);

static int
cli_sign (void *user, const gf_key *key, enum gf_sigalg alg, gf_slice data)
{
  struct ap *x = user;
  uint8_t sig[GF_SIG_MAX], tmp[2048];
  const uint8_t *d = data.data;
  size_t n = 0, i;
  const gf_key *signer = NULL;
  int async = x->sign_mode == SIGN_ASYNC || x->sign_mode == SIGN_TOKEN_ASYNC;

  x->sign_calls++;
  x->sign_alg = alg;
  if (x->sign_mode == SIGN_REFUSE)
    return 1;
  if (x->sign_mode == SIGN_FAIL)
    return gf_auth_client_sign_fail (x->cli, tst_now) != GF_OK;
  if (x->sign_mode == SIGN_FAIL_ASYNC)
    {
      x->pending = 1;
      return 0;
    }
  if (x->sign_mode == SIGN_TOKEN || x->sign_mode == SIGN_TOKEN_ASYNC)
    n = token_sign (x->token_plain, "ssh:", data.data, data.len, x->token_flags,
                    7, sig, sizeof sig);
  else if (x->sign_mode == SIGN_TOKEN_PACKED)
    n = token_answer_packed (x, key, alg, data, sig, sizeof sig);
  else
    {
      for (i = 0; i < x->nsigners; i++)
        if (gf_key_equal (x->signers[i], key))
          signer = x->signers[i];
      CHECK (signer != NULL);
      if (x->sign_mode == SIGN_OTHER)
        signer = x->wrong_signer;
      if (x->sign_mode == SIGN_WRONGDATA)
        {
          CHECK (data.len <= sizeof tmp);
          memcpy (tmp, data.data, data.len);
          tmp[data.len - 1] ^= 1;
          d = tmp;
        }
      CHECK_EQ (gf_key_sign (signer, alg, d, data.len, sig, sizeof sig, &n), GF_OK);
      if (x->sign_mode == SIGN_BADSIG)
        sig[n - 1] ^= 1;
    }
  if (async)
    {
      memcpy (x->stash, sig, n);
      x->stashlen = n;
      x->pending = 1;
      return 0;
    }
  (void) gf_auth_client_sign_respond (x->cli, tst_now, sig, n);
  return x->sign_mode == SIGN_SYNC_AND_REFUSE;
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
  x->unix_now = 1700000000;
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
  se.unix_time = srv_unix_time;
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
      ce.sign = cli_sign;
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

/* ---------------------------------------------------------------- */
/* Certificates                                                       */
/* ---------------------------------------------------------------- */

static gf_key *
blob_key (const char *hex)
{
  static uint8_t b[4096];
  gf_key *k = NULL;
  size_t n = tst_unhex (hex, b, sizeof b);

  CHECK_EQ (gf_key_from_blob (&k, b, n), GF_OK);
  return k;
}

/* The key from the private key text with the certificate attached.  */
static gf_key *
cert_key (const char *priv, const char *cert_hex)
{
  gf_key *plain = NULL, *cert = blob_key (cert_hex), *both = NULL;

  CHECK_EQ (gf_key_from_openssh_private (&plain, priv, strlen (priv)), GF_OK);
  CHECK_EQ (gf_key_with_certificate (plain, cert, &both), GF_OK);
  gf_key_free (plain);
  gf_key_free (cert);
  return both;
}

/* Run a client with the key against a server that trusts CAS, for USER,
   with the peer at ADDRESS.  X is left for the caller to run, look at and
   free.  */
static void
cert_login (struct ap *x, const gf_key *const *cas, size_t ncas,
            const gf_key *key, const char *user, const char *address,
            int hostbound)
{
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  /* The client keeps pointers into this for as long as X lives.  */
  static struct cli_creds cr;

  cr = (struct cli_creds) { user, { key }, 1, NULL, 0, 0 };
  sc.trusted_user_cas = cas;
  sc.ntrusted_user_cas = ncas;
  sc.peer_address = address;
  sc.hostbound = hostbound;
  ap_new (x, &sc, &cr);
  x->accept_certs = 1;
}

static void
test_certificates (void)
{
  gf_key *ca_ed = blob_key (vec_ca_ed_blob), *ca_rsa = blob_key (vec_ca_rsa_blob);
  gf_key *ca_p256 = blob_key (vec_ca_p256_blob);
  const gf_key *both[] = { ca_ed, ca_rsa };
  const gf_key *only_p256[] = { ca_p256 };
  gf_key *ck[4];
  static const enum gf_sigalg want[4][2] = {
    { GF_SIG_ED25519_CERT, 0 }, { GF_SIG_ECDSA_NISTP256_CERT, 0 },
    { GF_SIG_ECDSA_NISTP384_CERT, 0 }, { GF_SIG_RSA_SHA2_512_CERT,
                                         GF_SIG_RSA_SHA2_256_CERT }
  };
  struct ap x;
  gf_slice fc;
  size_t i;

  ck[0] = cert_key (vec_ed_private, vec_ed_user_cert);
  ck[1] = cert_key (vec_p256_private, vec_p256_user_cert);
  ck[2] = cert_key (vec_p384_private, vec_p384_user_cert);
  ck[3] = cert_key (vec_rsa_private, vec_rsa_user_cert);

  /* A certificate of each type gets in, for either principal; the
     application sees a verified certificate and its forced command, and the
     machine keeps the command.  */
  for (i = 0; i < 4; i++)
    {
      static const char *const users[] = { "alice", "bob" };
      size_t u;

      for (u = 0; u < 2; u++)
        {
          cert_login (&x, both, 2, ck[i], users[u], "192.0.2.77", 0);
          ap_run (&x);
          CHECK_EQ (x.cli_authenticated, 1);
          CHECK_EQ (x.srv_authenticated, 1);
          CHECK_EQ (x.srv_queries, 1);
          CHECK_EQ (x.srv_signed, 1);
          CHECK_EQ (x.srv_cert_seen, 2);
          CHECK (strcmp (x.srv_force, "/bin/true") == 0);
          CHECK (x.srv_sigalg == want[i][0] || x.srv_sigalg == want[i][1]);
          CHECK (!x.srv_verify_required);
          CHECK_EQ (gf_auth_server_force_command (x.srv, &fc), GF_OK);
          CHECK (gf_slice_equals (fc, "/bin/true"));
          CHECK_EQ (fc.data[fc.len], 0);
          ap_free (&x);
        }
    }

  /* With the host-bound method as well.  */
  cert_login (&x, both, 2, ck[0], "alice", "192.0.2.77", 1);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_hostbound_seen, 2);
  ap_free (&x);

  /* A user the certificate does not name.  The application is not asked.  */
  cert_login (&x, both, 2, ck[0], "carol", "192.0.2.77", 0);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (x.cli_failed, 1);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  cert_login (&x, both, 2, ck[0], "ali", "192.0.2.77", 0);
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  /* Unless the application says it decides who a certificate is for.  */
  {
    gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
    static struct cli_creds cr;

    cr = (struct cli_creds) { "ali", { ck[0] }, 1, NULL, 0, 0 };
    sc.trusted_user_cas = both;
    sc.ntrusted_user_cas = 2;
    sc.peer_address = "192.0.2.77";
    sc.principals_by_application = 1;
    ap_new (&x, &sc, &cr);
    x.accept_certs = 1;
    ap_run (&x);
    CHECK_EQ (x.srv_cert_seen, 2);
    CHECK_EQ (x.srv_authenticated, 1);
    ap_free (&x);
    /* Which CA, the dates and the address are still the machine's.  */
    sc.trusted_user_cas = NULL;
    sc.ntrusted_user_cas = 0;
    ap_new (&x, &sc, &cr);
    x.accept_certs = 1;
    ap_run (&x);
    CHECK_EQ (x.srv_requests, 0);
    ap_free (&x);
  }

  /* A CA that is not trusted; no CAs at all.  */
  cert_login (&x, only_p256, 1, ck[0], "alice", "192.0.2.77", 0);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  cert_login (&x, NULL, 0, ck[0], "alice", "192.0.2.77", 0);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (x.cli_failed, 1);
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.srv_disconnect, 0);	/* Refused, not an offence.  */
  ap_free (&x);

  /* Before and after the validity period, and at its last second.  */
  cert_login (&x, both, 2, ck[0], "alice", "192.0.2.77", 0);
  x.unix_now = 1500000000;
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.cli_authenticated, 0);
  ap_free (&x);
  cert_login (&x, both, 2, ck[0], "alice", "192.0.2.77", 0);
  x.unix_now = 4102358400u;
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  cert_login (&x, both, 2, ck[0], "alice", "192.0.2.77", 0);
  x.unix_now = 4102358399u;
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  ap_free (&x);

  /* source-address: outside the range, no address known, an IPv4 client
     seen through an IPv6 socket, not an address at all.  */
  cert_login (&x, both, 2, ck[0], "alice", "198.51.100.1", 0);
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  cert_login (&x, both, 2, ck[0], "alice", NULL, 0);
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  cert_login (&x, both, 2, ck[0], "alice", "localhost", 0);
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  cert_login (&x, both, 2, ck[0], "alice", "::ffff:192.0.2.5", 0);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  ap_free (&x);

  /* A certificate with neither option needs no address and forces nothing.  */
  {
    gf_key *free_key = cert_key (vec_ed_private, vec_forever_cert);

    cert_login (&x, both, 2, free_key, "alice", NULL, 0);
    ap_run (&x);
    CHECK_EQ (x.cli_authenticated, 1);
    CHECK_EQ (x.srv_force[0], 0);
    CHECK_EQ (gf_auth_server_force_command (x.srv, &fc), GF_OK);
    CHECK_EQ (fc.len, 0);
    ap_free (&x);
    gf_key_free (free_key);
  }

  /* verify-required is passed on for the application to enforce.  */
  {
    gf_key *k = cert_key (vec_ed_private, vec_verify_cert);

    cert_login (&x, both, 2, k, "alice", NULL, 0);
    ap_run (&x);
    CHECK_EQ (x.cli_authenticated, 1);
    CHECK (x.srv_verify_required);
    ap_free (&x);
    gf_key_free (k);
  }

  /* Certificates that are not usable: an unknown critical
     option, a certificate for hosts, one past its time.  */
  {
    static const struct
    {
      const char *cert;
      uint64_t now;
    } bad[] = {
      { vec_unknown_critical_cert, 1700000000 },
      { vec_expired_cert, 1700000000 },
      { vec_future_cert, 1700000000 },
      { vec_ed_host_cert, 1700000000 }
    };

    for (i = 0; i < 4; i++)
      {
        gf_key *k = cert_key (vec_ed_private, bad[i].cert);

        cert_login (&x, both, 2, k, "alice", "192.0.2.77", 0);
        x.unix_now = bad[i].now;
        ap_run (&x);
        CHECK_EQ (x.cli_authenticated, 0);
        CHECK_EQ (x.srv_requests, 0);
        ap_free (&x);
        gf_key_free (k);
      }
  }

  /* The application can still say no to a good certificate (a revocation
     list, say); the command was set aside by the request, and is gone
     once another request replaces it.  */
  cert_login (&x, both, 2, ck[0], "alice", "192.0.2.77", 0);
  x.accept_certs = 0;
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (x.srv_cert_seen, 1);
  ap_free (&x);

  /* A client with a certificate and a plain key: the server wants the plain
     one, and a command from the certificate it turned down is not kept.  */
  {
    gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
    static struct cli_creds cr;

    cr = (struct cli_creds) { "alice", { ck[0], ukeys[0] }, 2, NULL, 0, 0 };

    sc.trusted_user_cas = both;
    sc.ntrusted_user_cas = 2;
    sc.peer_address = "192.0.2.77";
    ap_new (&x, &sc, &cr);
    x.authorized[0] = ukeys[0];
    x.nauthorized = 1;
    ap_run (&x);
    CHECK_EQ (x.cli_authenticated, 1);
    CHECK_EQ (x.srv_cert_seen, 1);
    CHECK_EQ (gf_auth_server_force_command (x.srv, &fc), GF_OK);
    CHECK_EQ (fc.len, 0);
    ap_free (&x);
  }

  /* What the certificate permits is asked of the machine afterwards, for the
     request that was accepted and not for an earlier one.  */
  {
    gf_key *noperm = cert_key (vec_ed_private, vec_noperm_cert);
    gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
    static struct cli_creds cr;

    sc.trusted_user_cas = both;
    sc.ntrusted_user_cas = 2;
    sc.peer_address = "192.0.2.77";
    /* In through the certificate: only what it has.  */
    cert_login (&x, both, 2, noperm, "alice", "192.0.2.77", 0);
    ap_run (&x);
    CHECK_EQ (x.cli_authenticated, 1);
    CHECK_EQ (gf_auth_server_permits (x.srv, GF_CERT_PERMIT_PTY), 0);
    CHECK_EQ (gf_auth_server_permits (x.srv, GF_CERT_PERMIT_PORT_FORWARDING), 0);
    CHECK_EQ (gf_auth_server_permits (x.srv, NULL), 0);
    ap_free (&x);
    cert_login (&x, both, 2, ck[0], "alice", "192.0.2.77", 0);
    ap_run (&x);
    CHECK_EQ (gf_auth_server_permits (x.srv, GF_CERT_PERMIT_PTY), 1);
    CHECK_EQ (gf_auth_server_permits (x.srv, GF_CERT_PERMIT_USER_RC), 1);
    CHECK_EQ (gf_auth_server_permits (x.srv, "permit-nothing"), 0);
    ap_free (&x);
    /* A restricted certificate that the application turned down, then a
       plain key that it took: nothing restricts the user.  */
    cr = (struct cli_creds) { "alice", { noperm, ukeys[0] }, 2, NULL, 0, 0 };
    ap_new (&x, &sc, &cr);
    x.authorized[0] = ukeys[0];
    x.nauthorized = 1;
    ap_run (&x);
    CHECK_EQ (x.cli_authenticated, 1);
    CHECK_EQ (x.srv_cert_seen, 1);		/* It was tried first.  */
    CHECK_EQ (gf_auth_server_permits (x.srv, GF_CERT_PERMIT_PTY), 1);
    ap_free (&x);
    gf_key_free (noperm);
  }

  /* The wire: a certificate under the algorithm of its plain key is not a
     certificate request at all.  */
  {
    gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
    uint8_t m[2048];
    gf_writer w;
    size_t bl;
    const uint8_t *b = gf_key_blob (ck[0], &bl);

    sc.trusted_user_cas = both;
    sc.ntrusted_user_cas = 2;
    sc.peer_address = "192.0.2.77";
    ap_new (&x, &sc, NULL);
    pair_start (&x.p);
    pump (&x.p, 0);
    CHECK_EQ (gf_conn_request_service (x.p.cl.c, tst_now, "ssh-userauth"), GF_OK);
    pump (&x.p, 0);
    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "alice");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, "publickey");
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "ssh-ed25519");
    gf_wr_string (&w, b, bl);
    CHECK_EQ (gf_conn_send (x.p.cl.c, tst_now, m, w.len), GF_OK);
    pump (&x.p, 0);
    CHECK_EQ (x.srv_requests, 0);
    /* And the same request under the right name does reach it.  */
    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 50);
    gf_wr_cstring (&w, "alice");
    gf_wr_cstring (&w, "ssh-connection");
    gf_wr_cstring (&w, "publickey");
    gf_wr_bool (&w, 0);
    gf_wr_cstring (&w, "ssh-ed25519-cert-v01@openssh.com");
    gf_wr_string (&w, b, bl);
    CHECK_EQ (gf_conn_send (x.p.cl.c, tst_now, m, w.len), GF_OK);
    pump (&x.p, 0);
    CHECK_EQ (x.srv_requests, 1);
    CHECK_EQ (x.srv_cert_seen, 1);
    ap_free (&x);
  }

  /* Configuration: a trusted CA must be a plain key.  */
  {
    gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
    gf_auth_server_events se;
    gf_auth_server *a = NULL;
    const gf_key *bad_cas[] = { ck[0] };
    const gf_key *null_ca[] = { NULL };

    memset (&se, 0, sizeof se);
    se.send = srv_send;
    se.request = srv_request;
    se.disconnect = srv_disconnect;
    sc.trusted_user_cas = bad_cas;
    sc.ntrusted_user_cas = 1;
    CHECK_EQ (gf_auth_server_new (&a, &sc, &se), GF_ERR_INVAL);
    sc.trusted_user_cas = null_ca;
    CHECK_EQ (gf_auth_server_new (&a, &sc, &se), GF_ERR_INVAL);
    sc.trusted_user_cas = NULL;
    CHECK_EQ (gf_auth_server_new (&a, &sc, &se), GF_ERR_INVAL);
    sc.ntrusted_user_cas = 0;
    CHECK_EQ (gf_auth_server_new (&a, &sc, &se), GF_OK);
    gf_auth_server_free (a);
  }

  for (i = 0; i < 4; i++)
    gf_key_free (ck[i]);
  gf_key_free (ca_ed);
  gf_key_free (ca_rsa);
  gf_key_free (ca_p256);
}

/* ---------------------------------------------------------------- */
/* Security keys                                                      */
/* ---------------------------------------------------------------- */

/* A token in software: a plain Ed25519 key stands in for the hardware, and
   the security key has its public key and an application.  */
static gf_key *
soft_sk_public (const gf_key *plain, const char *app)
{
  uint8_t b[256];
  size_t pl;
  const uint8_t *pb = gf_key_blob (plain, &pl);
  gf_writer w;
  gf_key *k = NULL;

  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
  gf_wr_string (&w, pb + 4 + 11 + 4, 32);
  gf_wr_string (&w, app, strlen (app));
  CHECK_EQ (gf_key_from_blob (&k, b, w.len), GF_OK);
  return k;
}

/* What the token signs for MSG, as a signature blob. */
static size_t
token_sign (const gf_key *plain, const char *app, const uint8_t *m, size_t ml,
            uint8_t flags, uint32_t counter, uint8_t *out, size_t cap)
{
  uint8_t buf[69], sig[GF_SIG_MAX];
  size_t sl;
  gf_reader r;
  gf_slice name, raw;
  gf_writer w;

  CHECK_EQ (gf_hash_compute (GF_HASH_SHA256, app, strlen (app), buf, 32), GF_OK);
  buf[32] = flags;
  buf[33] = (uint8_t) (counter >> 24);
  buf[34] = (uint8_t) (counter >> 16);
  buf[35] = (uint8_t) (counter >> 8);
  buf[36] = (uint8_t) counter;
  CHECK_EQ (gf_hash_compute (GF_HASH_SHA256, m, ml, buf + 37, 32), GF_OK);
  CHECK_EQ (gf_key_sign (plain, GF_SIG_ED25519, buf, sizeof buf, sig, sizeof sig,
                         &sl), GF_OK);
  gf_reader_init (&r, sig, sl);
  CHECK_EQ (gf_rd_string (&r, &name), GF_OK);
  CHECK_EQ (gf_rd_string (&r, &raw), GF_OK);
  gf_writer_init (&w, out, cap);
  gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
  gf_wr_string (&w, raw.data, raw.len);
  gf_wr_u8 (&w, flags);
  gf_wr_u32 (&w, counter);
  return w.len;
}

/* A security key for a P-256 token key.  */
static gf_key *
soft_sk_public_p256 (const gf_key *plain, const char *app)
{
  uint8_t b[256];
  size_t pl;
  const uint8_t *pb = gf_key_blob (plain, &pl);
  gf_reader r;
  gf_slice s, q;
  gf_writer w;
  gf_key *k = NULL;

  gf_reader_init (&r, pb, pl);
  CHECK_EQ (gf_rd_string (&r, &s), GF_OK);
  CHECK_EQ (gf_rd_string (&r, &s), GF_OK);
  CHECK_EQ (gf_rd_string (&r, &q), GF_OK);
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ecdsa-sha2-nistp256@openssh.com");
  gf_wr_cstring (&w, "nistp256");
  gf_wr_string (&w, q.data, q.len);
  gf_wr_string (&w, app, strlen (app));
  CHECK_EQ (gf_key_from_blob (&k, b, w.len), GF_OK);
  return k;
}

/* What a FIDO library hands back for an assertion: the signature over
   SHA256(application) || flags || counter || SHA256(data) as the token
   makes it, with Ed25519's 64 bytes raw and ECDSA's integers in DER.  The
   token is asked for the application and key handle of KEY, and the library
   packs the answer.  */
static size_t
token_answer_packed (const struct ap *x, const gf_key *key, enum gf_sigalg alg,
                     gf_slice data, uint8_t *out, size_t cap)
{
  uint8_t buf[69], sig[GF_SIG_MAX], raw[80];
  const uint8_t *app, *h;
  size_t al, hl, sl, rl, n = 0;
  gf_reader r, rr;
  gf_slice name, body, ri, si;
  int ed = gf_key_type (x->token_plain) == GF_KEY_ED25519;

  app = gf_key_application (key, &al);
  h = gf_key_sk_handle (key, &hl);
  CHECK (app != NULL && h != NULL);
  CHECK (hl == x->token_handle_len && memcmp (h, x->token_handle, hl) == 0);
  CHECK_EQ (gf_hash_compute (GF_HASH_SHA256, app, al, buf, 32), GF_OK);
  buf[32] = x->token_flags;
  buf[33] = 0;
  buf[34] = 0;
  buf[35] = 0;
  buf[36] = 7;
  CHECK_EQ (gf_hash_compute (GF_HASH_SHA256, data.data, data.len, buf + 37, 32),
            GF_OK);
  CHECK_EQ (gf_key_sign (x->token_plain, ed ? GF_SIG_ED25519 : GF_SIG_ECDSA_NISTP256,
                         buf, sizeof buf, sig, sizeof sig, &sl), GF_OK);
  gf_reader_init (&r, sig, sl);
  CHECK_EQ (gf_rd_string (&r, &name), GF_OK);
  CHECK_EQ (gf_rd_string (&r, &body), GF_OK);
  if (ed)
    {
      memcpy (raw, body.data, body.len);
      rl = body.len;
    }
  else
    {
      /* The mpints of the SSH signature are the contents of DER integers. */
      gf_reader_init (&rr, body.data, body.len);
      CHECK_EQ (gf_rd_string (&rr, &ri), GF_OK);
      CHECK_EQ (gf_rd_string (&rr, &si), GF_OK);
      raw[0] = 0x30;
      raw[1] = (uint8_t) (4 + ri.len + si.len);
      raw[2] = 0x02;
      raw[3] = (uint8_t) ri.len;
      memcpy (raw + 4, ri.data, ri.len);
      raw[4 + ri.len] = 0x02;
      raw[5 + ri.len] = (uint8_t) si.len;
      memcpy (raw + 6 + ri.len, si.data, si.len);
      rl = 6 + ri.len + si.len;
    }
  CHECK_EQ (gf_sk_signature_pack (key, alg, raw, rl, x->token_flags, 7, out, cap, &n),
            GF_OK);
  return n;
}

/* A user certificate for the security key, signed by CA.  */
static gf_key *
soft_sk_cert (gf_key *ca, const gf_key *plain, const char *app,
              const char *principal, int verify_required)
{
  uint8_t b[1024], sig[GF_SIG_MAX], pr[64], crit[64];
  size_t pl, cl, sl, signed_len, cabl;
  const uint8_t *pb = gf_key_blob (plain, &pl), *cab = gf_key_blob (ca, &cabl);
  gf_writer w, pw, cw;
  uint8_t nonce[32];
  gf_key *k = NULL;

  memset (nonce, 0x17, sizeof nonce);
  gf_writer_init (&pw, pr, sizeof pr);
  gf_wr_string (&pw, principal, strlen (principal));
  gf_writer_init (&cw, crit, sizeof crit);
  if (verify_required)
    {
      gf_wr_cstring (&cw, "verify-required");
      gf_wr_string (&cw, "", 0);
    }
  cl = cw.len;
  gf_writer_init (&w, b, sizeof b);
  gf_wr_cstring (&w, "sk-ssh-ed25519-cert-v01@openssh.com");
  gf_wr_string (&w, nonce, sizeof nonce);
  gf_wr_string (&w, pb + 4 + 11 + 4, 32);
  gf_wr_string (&w, app, strlen (app));
  gf_wr_u64 (&w, 3);
  gf_wr_u32 (&w, GF_CERT_USER);
  gf_wr_cstring (&w, "sk-test");
  gf_wr_string (&w, pr, pw.len);
  gf_wr_u64 (&w, 0);
  gf_wr_u64 (&w, UINT64_MAX);
  gf_wr_string (&w, crit, cl);
  gf_wr_string (&w, "", 0);
  gf_wr_string (&w, "", 0);
  gf_wr_string (&w, cab, cabl);
  signed_len = w.len;
  CHECK_EQ (gf_key_sign (ca, GF_SIG_ED25519, b, signed_len, sig, sizeof sig, &sl),
            GF_OK);
  gf_wr_string (&w, sig, sl);
  CHECK_EQ (gf_key_from_blob (&k, b, w.len), GF_OK);
  return k;
}

/* A public key request from nobody in particular: the client end is not
   used, and the message is written by hand.  KEY is what is offered (a
   security key or its certificate), PLAIN and APP are the token's.  */
static void
sk_request (struct ap *x, const char *user, const gf_key *key,
            const gf_key *plain, const char *app, const char *algname,
            int with_sig, uint8_t flags, uint32_t counter)
{
  uint8_t m[2048], sd[2048], sig[256];
  size_t bl, sl;
  const uint8_t *b = gf_key_blob (key, &bl);
  const gf_conn_info *in = &x->p.sv.info;
  gf_writer w, d;

  gf_writer_init (&w, m, sizeof m);
  gf_wr_u8 (&w, 50);
  gf_wr_cstring (&w, user);
  gf_wr_cstring (&w, "ssh-connection");
  gf_wr_cstring (&w, "publickey");
  gf_wr_bool (&w, with_sig);
  gf_wr_cstring (&w, algname);
  gf_wr_string (&w, b, bl);
  if (with_sig)
    {
      gf_writer_init (&d, sd, sizeof sd);
      gf_wr_string (&d, in->session_id, in->session_id_len);
      gf_wr_u8 (&d, 50);
      gf_wr_cstring (&d, user);
      gf_wr_cstring (&d, "ssh-connection");
      gf_wr_cstring (&d, "publickey");
      gf_wr_bool (&d, 1);
      gf_wr_cstring (&d, algname);
      gf_wr_string (&d, b, bl);
      sl = token_sign (plain, app, sd, d.len, flags, counter, sig, sizeof sig);
      gf_wr_string (&w, sig, sl);
    }
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  CHECK_EQ (gf_conn_send (x->p.cl.c, tst_now, m, w.len), GF_OK);
  pump (&x->p, 0);
}

static void
sk_server (struct ap *x, const gf_auth_server_config *sc)
{
  ap_new (x, sc, NULL);
  pair_start (&x->p);
  pump (&x->p, 0);
  CHECK_EQ (gf_conn_request_service (x->p.cl.c, tst_now, "ssh-userauth"), GF_OK);
  pump (&x->p, 0);
}

static void
test_security_keys (void)
{
  gf_key *plain = NULL, *sk, *ca = NULL, *cert, *other_app;
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  const gf_key *cas[1];
  struct ap x;

  CHECK_EQ (gf_key_generate (&plain, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&ca, GF_KEY_ED25519, 0), GF_OK);
  sk = soft_sk_public (plain, "ssh:");
  other_app = soft_sk_public (plain, "ssh:other");

  /* The query, then the signature; the application sees the token's flags
     and counter, and the algorithm.  */
  sk_server (&x, &sc);
  x.authorized[0] = sk;
  x.nauthorized = 1;
  sk_request (&x, "dave", sk, plain, "ssh:", "sk-ssh-ed25519@openssh.com", 0, 0, 0);
  CHECK_EQ (x.srv_queries, 1);
  sk_request (&x, "dave", sk, plain, "ssh:", "sk-ssh-ed25519@openssh.com", 1,
              GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED, 0x01020304);
  CHECK_EQ (x.srv_signed, 1);
  CHECK_EQ (x.srv_authenticated, 1);
  CHECK_EQ (x.srv_sigalg, GF_SIG_SK_ED25519);
  CHECK_EQ (x.srv_sk_flags, GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED);
  CHECK_EQ (x.srv_sk_counter, 0x01020304);
  CHECK_EQ (x.srv_cert_keys, 0);
  ap_free (&x);

  /* The token not touched: genuine, refused before the application is asked,
     and a failed attempt, not an offence.  */
  sk_server (&x, &sc);
  x.authorized[0] = sk;
  x.nauthorized = 1;
  sk_request (&x, "dave", sk, plain, "ssh:", "sk-ssh-ed25519@openssh.com", 1, 0, 1);
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.srv_authenticated, 0);
  CHECK_EQ (x.srv_disconnect, 0);
  /* And then it is touched.  */
  sk_request (&x, "dave", sk, plain, "ssh:", "sk-ssh-ed25519@openssh.com", 1,
              GF_SK_USER_PRESENT, 2);
  CHECK_EQ (x.srv_authenticated, 1);
  ap_free (&x);

  /* A signature for another application is not a signature for this key. */
  sk_server (&x, &sc);
  x.authorized[0] = sk;
  x.nauthorized = 1;
  sk_request (&x, "dave", sk, plain, "ssh:other", "sk-ssh-ed25519@openssh.com", 1, 1, 1);
  CHECK_EQ (x.srv_requests, 0);
  sk_request (&x, "dave", other_app, plain, "ssh:", "sk-ssh-ed25519@openssh.com", 1, 1, 1);
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.srv_authenticated, 0);
  ap_free (&x);

  /* Under the plain algorithm name the key is not an Ed25519 key. */
  sk_server (&x, &sc);
  x.authorized[0] = sk;
  x.nauthorized = 1;
  sk_request (&x, "dave", sk, plain, "ssh:", "ssh-ed25519", 0, 0, 0);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);

  /* Certificates for the security key: a trusted CA, and verify-required
     which only a token that verified its user satisfies.  */
  cas[0] = ca;
  sc.trusted_user_cas = cas;
  sc.ntrusted_user_cas = 1;
  cert = soft_sk_cert (ca, plain, "ssh:", "erin", 0);
  sk_server (&x, &sc);
  x.accept_certs = 1;
  sk_request (&x, "erin", cert, plain, "ssh:", "sk-ssh-ed25519-cert-v01@openssh.com", 1, 1, 9);
  CHECK_EQ (x.srv_authenticated, 1);
  CHECK_EQ (x.srv_cert_seen, 1);
  CHECK_EQ (x.srv_cert_keys, 1);
  CHECK_EQ (x.srv_sigalg, GF_SIG_SK_ED25519_CERT);
  CHECK_EQ (x.srv_sk_counter, 9);
  CHECK (!x.srv_verify_required);
  ap_free (&x);
  /* Not for this user. */
  sk_server (&x, &sc);
  x.accept_certs = 1;
  sk_request (&x, "dave", cert, plain, "ssh:", "sk-ssh-ed25519-cert-v01@openssh.com", 1, 1, 9);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  gf_key_free (cert);
  cert = soft_sk_cert (ca, plain, "ssh:", "erin", 1);
  sk_server (&x, &sc);
  x.accept_certs = 1;
  sk_request (&x, "erin", cert, plain, "ssh:", "sk-ssh-ed25519-cert-v01@openssh.com", 1,
              GF_SK_USER_PRESENT, 9);
  CHECK_EQ (x.srv_authenticated, 0);
  CHECK_EQ (x.srv_requests, 0);
  sk_request (&x, "erin", cert, plain, "ssh:", "sk-ssh-ed25519-cert-v01@openssh.com", 1,
              GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED, 10);
  CHECK_EQ (x.srv_authenticated, 1);
  CHECK (x.srv_verify_required);
  ap_free (&x);
  gf_key_free (cert);

  gf_key_free (sk);
  gf_key_free (other_app);
  gf_key_free (plain);
  gf_key_free (ca);
}

/* ---------------------------------------------------------------- */
/* Keys that are somewhere else                                       */
/* ---------------------------------------------------------------- */

static gf_key *
public_of (const gf_key *k)
{
  size_t n;
  const uint8_t *b = gf_key_blob (k, &n);
  gf_key *p = NULL;

  CHECK_EQ (gf_key_from_blob (&p, b, n), GF_OK);
  return p;
}

static void
test_external_signer (void)
{
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  static struct cli_creds cr;
  gf_key *pub[4], *spare = NULL, *plain = NULL, *sk, *certpub, *certpriv;
  gf_key *ca = blob_key (vec_ca_ed_blob);
  const gf_key *cas[1];
  struct ap x;
  size_t k;

  cas[0] = ca;
  for (k = 0; k < 4; k++)
    pub[k] = public_of (ukeys[k]);
  CHECK_EQ (gf_key_generate (&spare, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&plain, GF_KEY_ED25519, 0), GF_OK);
  sk = soft_sk_public (plain, "ssh:");

  /* Each kind of key, signed for by whoever has the private part: inside
     the call, and later.  */
  for (k = 0; k < 4; k++)
    {
      static const int answers[] = { SIGN_SYNC, SIGN_ASYNC, SIGN_SYNC_AND_REFUSE };
      size_t am;

      for (am = 0; am < sizeof answers / sizeof answers[0]; am++)
        {
          int mode = answers[am];

          cr = (struct cli_creds) { "alice", { pub[k] }, 1, NULL, 0, 0 };
          ap_new (&x, &sc, &cr);
          x.sign_mode = mode;
          x.signers[0] = ukeys[k];
          x.nsigners = 1;
          x.authorized[0] = pub[k];
          x.nauthorized = 1;
          ap_run (&x);
          CHECK_EQ (x.sign_calls, 1);
          CHECK_EQ (x.srv_queries, 1);
          if (mode == SIGN_ASYNC)
            {
              /* Nothing has gone to the server while the token thinks.  */
              CHECK (x.pending);
              CHECK_EQ (x.srv_signed, 0);
              CHECK_EQ (x.cli_authenticated, 0);
              CHECK_EQ (gf_auth_client_sign_respond (x.cli, tst_now, x.stash,
                                                     x.stashlen), GF_OK);
              pump (&x.p, 0);
              /* It was answered once.  */
              CHECK_EQ (gf_auth_client_sign_respond (x.cli, tst_now, x.stash,
                                                     x.stashlen), GF_ERR_STATE);
              CHECK_EQ (gf_auth_client_sign_fail (x.cli, tst_now), GF_ERR_STATE);
            }
          CHECK_EQ (x.cli_authenticated, 1);
          CHECK_EQ (x.srv_signed, 1);
          ap_free (&x);
        }
    }
  /* With the host-bound method; and the key asked about is the one that
     signs.  */
  sc.hostbound = 1;
  cr = (struct cli_creds) { "alice", { pub[1] }, 1, NULL, 0, 0 };
  ap_new (&x, &sc, &cr);
  x.sign_mode = SIGN_SYNC;
  x.signers[0] = ukeys[1];
  x.nsigners = 1;
  x.authorized[0] = pub[1];
  x.nauthorized = 1;
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_hostbound_seen, 2);
  CHECK_EQ (x.sign_alg, GF_SIG_ECDSA_NISTP256);
  ap_free (&x);
  sc.hostbound = 0;

  /* Nothing to ask when there is no private part to be had: a key without
     one and no function is a mistake.  */
  {
    gf_auth_client_config cc;
    gf_auth_client_events ce;
    gf_auth_client *c = NULL;
    const gf_key *keys[1];

    memset (&cc, 0, sizeof cc);
    memset (&ce, 0, sizeof ce);
    keys[0] = pub[0];
    cc.user = "alice";
    cc.keys = keys;
    cc.nkeys = 1;
    ce.send = cli_send;
    ce.failed = cli_failed;
    CHECK_EQ (gf_auth_client_new (&c, &cc, &ce), GF_ERR_INVAL);
    ce.sign = cli_sign;
    CHECK_EQ (gf_auth_client_new (&c, &cc, &ce), GF_OK);
    CHECK_EQ (gf_auth_client_sign_respond (c, 0, (const uint8_t *) "x", 1), GF_ERR_STATE);
    CHECK_EQ (gf_auth_client_sign_fail (c, 0), GF_ERR_STATE);
    CHECK_EQ (gf_auth_client_sign_respond (NULL, 0, (const uint8_t *) "x", 1), GF_ERR_INVAL);
    CHECK_EQ (gf_auth_client_sign_respond (c, 0, NULL, 1), GF_ERR_INVAL);
    gf_auth_client_free (c);
  }

  /* A signer that cannot, that fails, or that answers wrongly costs its key
     and no more: the next one is tried.  Wrong answers never reach the
     server.  */
  {
    static const int modes[] = { SIGN_REFUSE, SIGN_FAIL, SIGN_FAIL_ASYNC,
                                 SIGN_BADSIG, SIGN_WRONGDATA, SIGN_OTHER };
    size_t m;

    for (m = 0; m < sizeof modes / sizeof modes[0]; m++)
      {
        /* The only key.  */
        cr = (struct cli_creds) { "alice", { pub[0] }, 1, NULL, 0, 0 };
        ap_new (&x, &sc, &cr);
        x.sign_mode = modes[m];
        x.signers[0] = ukeys[0];
        x.nsigners = 1;
        x.wrong_signer = spare;
        x.authorized[0] = pub[0];
        x.nauthorized = 1;
        ap_run (&x);
        if (modes[m] == SIGN_FAIL_ASYNC)
          {
            CHECK (x.pending);
            /* Nothing is left to try: the answer a failure always gets.  */
            CHECK_EQ (gf_auth_client_sign_fail (x.cli, tst_now), GF_ERR_AUTH);
            pump (&x.p, 0);
          }
        CHECK_EQ (x.sign_calls, 1);
        CHECK_EQ (x.cli_authenticated, 0);
        CHECK_EQ (x.cli_failed, 1);
        CHECK_EQ (x.srv_signed, 0);
        CHECK_EQ (x.sent_signed, 0);		/* Not even sent.  */
        CHECK_EQ (x.srv_disconnect, 0);
        ap_free (&x);
        /* A second key, which is local and signs itself.  */
        cr = (struct cli_creds) { "alice", { pub[0], ukeys[1] }, 2, NULL, 0, 0 };
        ap_new (&x, &sc, &cr);
        x.sign_mode = modes[m];
        x.signers[0] = ukeys[0];
        x.nsigners = 1;
        x.wrong_signer = spare;
        x.authorized[0] = pub[0];
        x.authorized[1] = ukeys[1];
        x.nauthorized = 2;
        ap_run (&x);
        if (modes[m] == SIGN_FAIL_ASYNC)
          {
            CHECK_EQ (gf_auth_client_sign_fail (x.cli, tst_now), GF_OK);
            pump (&x.p, 0);
          }
        CHECK_EQ (x.sign_calls, 1);		/* Only for the key that needs it. */
        CHECK_EQ (x.cli_authenticated, 1);
        CHECK_EQ (x.srv_signed, 1);
        CHECK_EQ (x.sent_signed, 1);		/* Just the good one.  */
        ap_free (&x);
      }
  }

  /* A certificate whose key is elsewhere.  */
  certpub = blob_key (vec_ed_user_cert);
  certpriv = cert_key (vec_ed_private, vec_ed_user_cert);
  sc.trusted_user_cas = cas;
  sc.ntrusted_user_cas = 1;
  sc.peer_address = "192.0.2.77";
  cr = (struct cli_creds) { "alice", { certpub }, 1, NULL, 0, 0 };
  ap_new (&x, &sc, &cr);
  x.sign_mode = SIGN_SYNC;
  x.signers[0] = certpriv;
  x.nsigners = 1;
  x.accept_certs = 1;
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.sign_alg, GF_SIG_ED25519_CERT);
  CHECK_EQ (x.srv_cert_seen, 2);
  ap_free (&x);
  sc.trusted_user_cas = NULL;
  sc.ntrusted_user_cas = 0;
  sc.peer_address = NULL;

  /* A security key, which only a token can sign for, and only if it was
     touched: an answer without the user presence flag is not sent.  */
  cr = (struct cli_creds) { "alice", { sk }, 1, NULL, 0, 0 };
  ap_new (&x, &sc, &cr);
  x.sign_mode = SIGN_TOKEN;
  x.token_plain = plain;
  x.token_flags = GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED;
  x.authorized[0] = sk;
  x.nauthorized = 1;
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.sign_alg, GF_SIG_SK_ED25519);
  CHECK_EQ (x.srv_sk_flags, GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED);
  CHECK_EQ (x.srv_sk_counter, 7);
  ap_free (&x);
  ap_new (&x, &sc, &cr);
  x.sign_mode = SIGN_TOKEN_ASYNC;		/* The user takes a while. */
  x.token_plain = plain;
  x.token_flags = GF_SK_USER_PRESENT;
  x.authorized[0] = sk;
  x.nauthorized = 1;
  ap_run (&x);
  CHECK (x.pending && x.cli_authenticated == 0);
  CHECK_EQ (gf_auth_client_sign_respond (x.cli, tst_now, x.stash, x.stashlen), GF_OK);
  pump (&x.p, 0);
  CHECK_EQ (x.cli_authenticated, 1);
  ap_free (&x);
  ap_new (&x, &sc, &cr);
  x.sign_mode = SIGN_TOKEN;
  x.token_plain = plain;
  x.token_flags = 0;				/* Not touched.  */
  x.authorized[0] = sk;
  x.nauthorized = 1;
  ap_run (&x);
  CHECK_EQ (x.srv_signed, 0);			/* Refused here, not there.  */
  CHECK_EQ (x.sent_signed, 0);
  CHECK_EQ (x.cli_authenticated, 0);
  ap_free (&x);

  for (k = 0; k < 4; k++)
    gf_key_free (pub[k]);
  gf_key_free (spare);
  gf_key_free (plain);
  gf_key_free (sk);
  gf_key_free (certpub);
  gf_key_free (certpriv);
  gf_key_free (ca);
}

/* A client signing with a security key through a token: the application
   gives the token the key handle and application the file or the token
   holds, and the library packs what it answers.  Ed25519 and P-256, the
   answer checked by the client and then by the server.  */
static void
test_security_key_client (void)
{
  static const uint8_t handle[70] = { 0x11, 0x22, 0x33, 0x44 };
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  int t;

  for (t = 0; t < 2; t++)
    {
      gf_key *plain = NULL, *sk;
      struct cli_creds cr;
      struct ap x;

      CHECK_EQ (gf_key_generate (&plain, t ? GF_KEY_ECDSA_P256 : GF_KEY_ED25519, 0),
                GF_OK);
      sk = t ? soft_sk_public_p256 (plain, "ssh:") : soft_sk_public (plain, "ssh:");
      CHECK_EQ (gf_key_sk_attach_handle (sk, GF_SK_USER_PRESENT, handle, sizeof handle),
                GF_OK);
      cr = (struct cli_creds) { "alice", { sk }, 1, NULL, 0, 0 };

      ap_new (&x, &sc, &cr);
      x.sign_mode = SIGN_TOKEN_PACKED;
      x.token_plain = plain;
      x.token_flags = GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED;
      x.token_handle = handle;
      x.token_handle_len = sizeof handle;
      x.authorized[0] = sk;
      x.nauthorized = 1;
      ap_run (&x);
      CHECK_EQ (x.cli_authenticated, 1);
      CHECK_EQ (x.sign_calls, 1);
      CHECK_EQ (x.sign_alg, t ? GF_SIG_SK_ECDSA_NISTP256 : GF_SIG_SK_ED25519);
      CHECK_EQ (x.srv_sk_flags, GF_SK_USER_PRESENT | GF_SK_USER_VERIFIED);
      CHECK_EQ (x.srv_sk_counter, 7);
      ap_free (&x);

      /* A token that was not touched: its answer packs, and the client's
         own check, which is the server's policy, refuses it.  */
      ap_new (&x, &sc, &cr);
      x.sign_mode = SIGN_TOKEN_PACKED;
      x.token_plain = plain;
      x.token_flags = 0;
      x.token_handle = handle;
      x.token_handle_len = sizeof handle;
      x.authorized[0] = sk;
      x.nauthorized = 1;
      ap_run (&x);
      CHECK_EQ (x.sent_signed, 0);
      CHECK_EQ (x.cli_authenticated, 0);
      ap_free (&x);

      gf_key_free (sk);
      gf_key_free (plain);
    }
}

#ifdef HAVE_GNUTLS
/* ---------------------------------------------------------------- */
/* X.509 chains                                                       */
/* ---------------------------------------------------------------- */

static gf_key *
x509_user_key (const char *priv_pem, const char *blob_hex)
{
  static uint8_t b[16384];
  gf_key *priv = NULL, *chain = NULL, *k = NULL;
  const uint8_t *cd[8];
  size_t cl[8], i, n;

  CHECK_EQ (gf_key_from_openssh_private (&priv, priv_pem, strlen (priv_pem)), GF_OK);
  n = tst_unhex (blob_hex, b, sizeof b);
  CHECK_EQ (gf_key_from_blob (&chain, b, n), GF_OK);
  n = gf_x509_chain_length (chain);
  for (i = 0; i < n; i++)
    CHECK_EQ (gf_x509_chain_cert (chain, i, &cd[i], &cl[i]), GF_OK);
  CHECK_EQ (gf_key_with_x509 (priv, cd, cl, n, &k), GF_OK);
  gf_key_free (priv);
  gf_key_free (chain);
  return k;
}

static gf_x509_trust *
x509_trust_of (const char *der_hex)
{
  static uint8_t d[8192];
  gf_x509_trust *t = NULL;

  CHECK_EQ (gf_x509_trust_new (&t), GF_OK);
  CHECK_EQ (gf_x509_trust_add_ca (t, d, tst_unhex (der_hex, d, sizeof d)), GF_OK);
  return t;
}

static void
x509_login (struct ap *x, const gf_x509_trust *trust, const gf_key *key,
            int hostbound)
{
  gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
  static struct cli_creds cr;

  cr = (struct cli_creds) { "alice", { key }, 1, NULL, 0, 0 };
  sc.x509_trust = trust;
  sc.hostbound = hostbound;
  ap_new (x, &sc, &cr);
  x->accept_certs = 1;
}

static void
test_x509 (void)
{
  gf_x509_trust *root = x509_trust_of (vec_x_root), *other = x509_trust_of (vec_x_ca2);
  gf_key *user = x509_user_key (vec_x_client_private, vec_x_client_blob);
  gf_key *server = x509_user_key (vec_x_p256_private, vec_x_p256_blob);
  struct ap x;

  /* A user with a chain the server's trust vouches for: the application sees
     the subject, the algorithm is the chain's, and (when the server
     announced the host-bound method) the signature is bound to the host.  */
  x509_login (&x, root, user, 0);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_authenticated, 1);
  CHECK_EQ (x.srv_x509_seen, 2);		/* The query, then the signed request. */
  CHECK (strcmp (x.srv_subject, "CN=alice") == 0);
  CHECK_EQ (x.srv_sigalg, GF_SIG_X509_ECDSA_NISTP256);
  CHECK_EQ (x.srv_cert_keys, 0);		/* Not an OpenSSH certificate.  */
  ap_free (&x);
  x509_login (&x, root, user, 1);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 1);
  CHECK_EQ (x.srv_hostbound_seen, 2);
  ap_free (&x);

  /* No trust configured: no chain is a user. */
  x509_login (&x, NULL, user, 0);
  ap_run (&x);
  CHECK_EQ (x.cli_authenticated, 0);
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.srv_disconnect, 0);
  ap_free (&x);
  /* A trust that is another CA's. */
  x509_login (&x, other, user, 0);
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.cli_authenticated, 0);
  ap_free (&x);
  /* A host's chain is not a user's. */
  x509_login (&x, root, server, 0);
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  CHECK_EQ (x.cli_authenticated, 0);
  ap_free (&x);
  /* By the server's clock: before the certificates and after them. */
  x509_login (&x, root, user, 0);
  x.unix_now = 1500000000;
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  x509_login (&x, root, user, 0);
  x.unix_now = 4200000000u;
  ap_run (&x);
  CHECK_EQ (x.srv_requests, 0);
  ap_free (&x);
  /* The application can still say no. */
  x509_login (&x, root, user, 0);
  x.accept_certs = 0;
  ap_run (&x);
  CHECK_EQ (x.srv_x509_seen, 1);
  CHECK_EQ (x.cli_authenticated, 0);
  ap_free (&x);

  gf_key_free (user);
  gf_key_free (server);
  gf_x509_trust_free (root);
  gf_x509_trust_free (other);
}
#endif /* HAVE_GNUTLS */

/* A revocation list in the configuration: revoked keys and certificates get
   no further than the machine, the others are unaffected.  */
static void
krl_file (uint8_t *out, size_t cap, size_t *len, int what, const gf_key *key,
          uint64_t serial, const gf_key *ca)
{
  gf_writer w;
  size_t m, b;
  const uint8_t *blob;
  size_t bl;

  gf_writer_init (&w, out, cap);
  gf_wr_bytes (&w, "SSHKRL\n", 8);
  gf_wr_u32 (&w, 1);
  gf_wr_u64 (&w, 1);
  gf_wr_u64 (&w, 1700000000);
  gf_wr_u64 (&w, 0);
  gf_wr_string (&w, "", 0);
  gf_wr_string (&w, "", 0);
  if (what == 0)		/* The key itself.  */
    {
      blob = gf_key_plain_blob (key, &bl);
      gf_wr_u8 (&w, 2);
      m = gf_wr_string_begin (&w);
      gf_wr_string (&w, blob, bl);
      gf_wr_string_end (&w, m);
    }
  else				/* A serial of a CA.  */
    {
      blob = gf_key_blob (ca, &bl);
      gf_wr_u8 (&w, 1);
      m = gf_wr_string_begin (&w);
      gf_wr_string (&w, blob, bl);
      gf_wr_string (&w, "", 0);
      gf_wr_u8 (&w, 0x20);
      b = gf_wr_string_begin (&w);
      gf_wr_u64 (&w, serial);
      gf_wr_string_end (&w, b);
      gf_wr_string_end (&w, m);
    }
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  *len = w.len;
}

static void
test_krl (void)
{
  uint8_t f[512];
  size_t fl, k;
  gf_krl *list;
  gf_key *ca = blob_key (vec_ca_ed_blob);
  gf_key *ck[2];
  const gf_key *cas[1];
  gf_cert_info ci;
  struct ap x;

  CHECK_EQ (gf_krl_new (&list), GF_OK);
  krl_file (f, sizeof f, &fl, 0, ukeys[0], 0, NULL);
  CHECK_EQ (gf_krl_load (list, f, fl), GF_OK);
  for (k = 0; k < 2; k++)
    {
      gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
      struct cli_creds cr = { "alice", { ukeys[k] }, 1, NULL, 0, 0 };

      sc.krl = list;
      ap_new (&x, &sc, &cr);
      x.authorized[0] = ukeys[k];
      x.nauthorized = 1;
      ap_run (&x);
      /* The revoked key never reaches the application; the other does.  */
      CHECK_EQ (x.srv_authenticated, k);
      CHECK_EQ (x.srv_requests > 0, k);
      CHECK_EQ (x.cli_authenticated, k);
      CHECK_EQ (x.srv_disconnect, 0);	/* Refused, not an offence.  */
      ap_free (&x);
    }
  gf_krl_free (list);

  /* Certificates: one serial of the CA.  */
  ck[0] = cert_key (vec_ed_private, vec_ed_user_cert);
  ck[1] = cert_key (vec_p256_private, vec_p256_user_cert);
  cas[0] = ca;
  CHECK_EQ (gf_key_certificate_info (ck[0], &ci), GF_OK);
  CHECK (ci.serial != 0);
  CHECK_EQ (gf_key_certificate_info (ck[1], &ci), GF_OK);
  {
    uint64_t other = ci.serial;
    gf_cert_info c0;

    CHECK_EQ (gf_key_certificate_info (ck[0], &c0), GF_OK);
    CHECK (other != c0.serial);
    CHECK_EQ (gf_krl_new (&list), GF_OK);
    krl_file (f, sizeof f, &fl, 1, NULL, c0.serial, ca);
    CHECK_EQ (gf_krl_load (list, f, fl), GF_OK);
    for (k = 0; k < 3; k++)
      {
        /* The revoked serial, another serial, and the revoked serial with
           no list.  */
        static const int which[3] = { 0, 1, 0 }, use_list[3] = { 1, 1, 0 };
        gf_auth_server_config sc = srv_config (GF_AUTH_PUBLICKEY);
        static struct cli_creds cr;

        cr = (struct cli_creds) { "alice", { ck[which[k]] }, 1, NULL, 0, 0 };
        sc.trusted_user_cas = cas;
        sc.ntrusted_user_cas = 1;
        sc.peer_address = "192.0.2.77";
        sc.krl = use_list[k] ? list : NULL;
        ap_new (&x, &sc, &cr);
        x.accept_certs = 1;
        ap_run (&x);
        CHECK_EQ (x.srv_authenticated, k != 0);
        CHECK_EQ (x.srv_disconnect, 0);
        ap_free (&x);
      }
    gf_krl_free (list);
  }
  gf_key_free (ck[0]);
  gf_key_free (ck[1]);
  gf_key_free (ca);
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
  test_krl ();
  test_key_selection ();
  test_password ();
  test_kbdint ();
  test_banner_and_async ();
  test_bad_signatures ();
  test_hostbound ();
  test_protocol_errors ();
  test_refused_keys ();
  test_limits_and_timeout ();
  test_certificates ();
  test_security_keys ();
  test_security_key_client ();
  test_external_signer ();
#ifdef HAVE_GNUTLS
  test_x509 ();
#endif
  for (i = 0; i < 4; i++)
    gf_key_free (ukeys[i]);
  gf_key_free (stranger);
  gf_key_free (hostkey);
  TST_DONE ();
}
