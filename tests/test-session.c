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
#include <foxtrot/session.h>

#include "tst-util.h"
#include "vectors-cert.h"
#ifdef HAVE_GNUTLS
# include <foxtrot/x509.h>
# include "vectors-x509.h"
#endif

/* Two sessions wired to each other on a virtual clock, with a small
   application on each side.  */

static uint64_t now = 1000000;
static uint32_t chan_window;	/* For channels this test opens or accepts.  */
static gf_key *hostkey, *userkey, *otherkey;

struct pipe
{
  uint8_t *buf;
  size_t len, cap;
};

struct node
{
  gf_session *s;
  struct node *peer;
  struct pipe out;
  int is_server;

  /* Server policy.  */
  const gf_key *authorized;
  const char *password, *code;
  int hold_auth;		/* Do not answer authentication requests.  */
  int no_open_cb;
  int deny_global;
  int accept_cert;		/* Accept a certificate the library verified.  */
  int host_was_cert, host_cert_ok;
  int host_was_x509, host_x509_ok;
#ifdef HAVE_GNUTLS
  const gf_x509_trust *x509_trust;
#endif

  /* Events seen.  */
  int established, authenticated, auth_failed, banners, closed;
  int close_error;
  uint32_t close_reason;
  int host_key_calls, trust;
  int opens, confirmed, failed, requests, eofs, channel_closed;
  uint32_t fail_reason, last_id;
  uint8_t *rx;
  size_t rxn, rxcap;
  uint32_t exit_status;
  int exited;
  int global_requests, global_replies, global_ok;
  uint32_t global_port;
  int unimpl;
  uint32_t unimpl_seq;
  char exec[64];
  int auto_exec;		/* Client: run "echo hi" once authenticated.  */
  int auto_serve;		/* Server: serve exec "echo hi".  */
  uint32_t chan;
  int consume;			/* Consume data as it comes.  */
  int kbd_prompts;
  const char *kbd_answer;
};

static int
w_write (void *u, const uint8_t *d, size_t n)
{
  struct node *x = u;
  struct pipe *p = &x->out;

  if (p->len + n > p->cap)
    {
      p->cap = (p->len + n) * 2;
      p->buf = realloc (p->buf, p->cap);
    }
  memcpy (p->buf + p->len, d, n);
  p->len += n;
  return 0;
}

static int
w_host_key (void *u, const gf_key *k)
{
  struct node *x = u;

  x->host_key_calls++;
  /* What a client does with a host certificate: it is for a host, it is good
     now, and it names the host we meant to reach.  */
  x->host_was_cert = gf_key_is_certificate (k);
  x->host_cert_ok = x->host_was_cert
    && gf_cert_check (k, GF_CERT_HOST, 1700000000, NULL) == GF_OK
    && gf_cert_has_principal (k, "www.example.org", 15, 1);
#ifdef HAVE_GNUTLS
  /* A chain is trusted when the store vouches for it as a server, by name. */
  if (gf_x509_chain_length (k) > 0)
    {
      x->host_was_x509 = 1;
      x->host_x509_ok = x->x509_trust != NULL
        && gf_x509_verify (x->x509_trust, k, GF_X509_SERVER, "host.example.org",
                           1700000000, NULL) == GF_OK;
      return x->trust && x->host_x509_ok ? 0 : 1;
    }
#endif
  return x->trust ? 0 : 1;
}

static int
w_established (void *u, const gf_conn_info *i)
{
  struct node *x = u;

  (void) i;
  x->established++;
  return 0;
}

static void
w_unimpl (void *u, uint32_t seq)
{
  struct node *x = u;

  x->unimpl++;
  x->unimpl_seq = seq;
}

static int
w_auth_request (void *u, const gf_auth_request *r)
{
  struct node *x = u;
  int ok = 0;

  if (x->hold_auth)
    return 0;
  switch (r->method)
    {
    case GF_AUTH_PUBLICKEY:
      ok = (x->authorized && gf_key_equal (x->authorized, r->key))
        || (x->accept_cert && r->certificate);
      if (!r->has_signature)
        return (ok ? gf_session_auth_pk_ok (x->s)
                   : gf_session_auth_reject (x->s, 0)) != GF_OK;
      break;
    case GF_AUTH_PASSWORD:
      ok = x->password && r->password.len == strlen (x->password)
        && memcmp (r->password.data, x->password, r->password.len) == 0;
      break;
    case GF_AUTH_KBDINT:
      {
        static const char *const pr[] = { "Code: " };
        static const int echo[] = { 0 };

        return gf_session_auth_kbdint_prompt (x->s, "", "", 1, pr, echo)
          != GF_OK;
      }
    default:
      break;
    }
  return (ok ? gf_session_auth_accept (x->s)
             : gf_session_auth_reject (x->s, 0)) != GF_OK;
}

static int
w_kbd_response (void *u, const gf_slice *r, size_t n)
{
  struct node *x = u;
  int ok = n == 1 && x->code && r[0].len == strlen (x->code)
    && memcmp (r[0].data, x->code, r[0].len) == 0;

  return (ok ? gf_session_auth_accept (x->s)
             : gf_session_auth_reject (x->s, 0)) != GF_OK;
}

static void
w_banner (void *u, gf_slice t)
{
  (void) t;
  ((struct node *) u)->banners++;
}

static int
w_kbdint (void *u, gf_slice name, gf_slice instr, size_t n,
          const gf_slice *prompts, const int *echo)
{
  struct node *x = u;
  const char *a[4];
  size_t i;

  (void) name;
  (void) instr;
  (void) prompts;
  (void) echo;
  x->kbd_prompts += (int) n;
  for (i = 0; i < n && i < 4; i++)
    a[i] = x->kbd_answer ? x->kbd_answer : "";
  return gf_session_auth_kbdint_respond (x->s, n, a) != GF_OK;
}

static int
w_auth_failed (void *u)
{
  ((struct node *) u)->auth_failed++;
  return 0;
}

static int
w_authenticated (void *u, gf_slice user)
{
  struct node *x = u;

  (void) user;
  x->authenticated++;
  if (x->auto_exec)
    {
      gf_chans_config dummy;

      (void) dummy;
      return gf_chans_open_session (gf_session_channels (x->s), &x->chan,
                                    chan_window, 0) != GF_OK;
    }
  return 0;
}

static int
w_channel_open (void *u, const gf_chan_open *o)
{
  struct node *x = u;

  x->opens++;
  x->last_id = o->id;
  return gf_session_channel_accept (x->s, o->id, chan_window, 0) != GF_OK;
}

static int
w_confirmed (void *u, uint32_t id)
{
  struct node *x = u;

  x->confirmed++;
  if (x->auto_exec)
    return gf_chans_request_exec (gf_session_channels (x->s), id, "echo hi", 1)
      != GF_OK;
  return 0;
}

static int
w_failed (void *u, uint32_t id, uint32_t reason, gf_slice text)
{
  struct node *x = u;

  (void) id;
  (void) text;
  x->failed++;
  x->fail_reason = reason;
  return 0;
}

static int
w_data (void *u, uint32_t id, const uint8_t *d, size_t n)
{
  struct node *x = u;

  if (x->rxn + n > x->rxcap)
    {
      x->rxcap = (x->rxn + n) * 2;
      x->rx = realloc (x->rx, x->rxcap);
    }
  memcpy (x->rx + x->rxn, d, n);
  x->rxn += n;
  return gf_chans_consumed (gf_session_channels (x->s), id, n) != GF_OK;
}

static int
w_request (void *u, const gf_chan_request *q)
{
  struct node *x = u;
  gf_chans *ch = gf_session_channels (x->s);

  x->requests++;
  if (q->type == GF_REQ_EXIT_STATUS)
    {
      x->exit_status = q->status;
      x->exited = 1;
      return 0;
    }
  if (x->is_server && q->type == GF_REQ_EXEC && x->auto_serve)
    {
      snprintf (x->exec, sizeof x->exec, "%.*s", (int) q->command.len,
                (const char *) q->command.data);
      if (gf_chans_reply (ch, q->id, 1) != GF_OK)
        return 1;
      if (gf_chans_send_data (ch, q->id, (const uint8_t *) "hi\n", 3) != 3)
        return 1;
      return gf_chans_request_exit_status (ch, q->id, 0) != GF_OK
        || gf_chans_send_eof (ch, q->id) != GF_OK
        || gf_chans_close (ch, q->id) != GF_OK;
    }
  return q->want_reply ? gf_chans_reply (ch, q->id, 0) != GF_OK : 0;
}

static int
w_eof (void *u, uint32_t id)
{
  (void) id;
  ((struct node *) u)->eofs++;
  return 0;
}

static int
w_chan_closed (void *u, uint32_t id)
{
  (void) id;
  ((struct node *) u)->channel_closed++;
  return 0;
}

static int
w_global (void *u, const gf_global_request *r)
{
  struct node *x = u;

  x->global_requests++;
  if (!r->want_reply)
    return 0;
  return gf_chans_global_reply (gf_session_channels (x->s), !x->deny_global,
                                r->port == 0 ? 7000 : 0) != GF_OK;
}

static int
w_global_reply (void *u, int ok, uint32_t port)
{
  struct node *x = u;

  x->global_replies++;
  x->global_ok = ok;
  x->global_port = port;
  return 0;
}

static void
w_closed (void *u, int error, uint32_t reason, gf_slice text)
{
  struct node *x = u;

  (void) text;
  x->closed++;
  x->close_error = error;
  x->close_reason = reason;
}

struct world
{
  struct node c, sv;
};

struct opts
{
  int client_trusts;
  const gf_key *client_key;
  const char *password;
  const char *authorized_pw;
  unsigned methods;
  unsigned max_sessions;
  uint32_t window;
  uint64_t rekey_bytes;
  int hostbound;
  int no_channel_cb;
  int kbd;
  gf_key *host_key;		/* Instead of the plain one.  */
#ifdef HAVE_GNUTLS
  const gf_x509_trust *x509_trust;	/* The client's.  */
#endif
  const gf_key *const *cas;	/* The server's trusted user CAs.  */
  size_t ncas;
  const char *peer_address;
};

static void
world_new (struct world *w, const struct opts *o)
{
  gf_session_config cc, sc;
  gf_session_events ce, se;
  static const gf_key *keys[1];	/* Must outlive the session.  */
  static gf_key *host_keys[1];

  memset (w, 0, sizeof *w);
  w->c.peer = &w->sv;
  w->sv.peer = &w->c;
  w->sv.is_server = 1;
  w->c.trust = o->client_trusts;
#ifdef HAVE_GNUTLS
  w->c.x509_trust = o->x509_trust;
#endif
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  host_keys[0] = o->host_key ? o->host_key : hostkey;
  sc.conn.host_keys = host_keys;
  sc.conn.nhost_keys = 1;
  sc.server_auth.trusted_user_cas = o->cas;
  sc.server_auth.ntrusted_user_cas = o->ncas;
  sc.server_auth.peer_address = o->peer_address;
  sc.conn.rekey_bytes = cc.conn.rekey_bytes = o->rekey_bytes;
  sc.server_auth.methods = o->methods ? o->methods : GF_AUTH_PUBLICKEY;
  sc.server_auth.hostbound = o->hostbound;
  sc.max_sessions = o->max_sessions;
  cc.client_auth.user = "alice";
  if (o->client_key)
    {
      keys[0] = o->client_key;
      cc.client_auth.keys = keys;
      cc.client_auth.nkeys = 1;
    }
  cc.client_auth.password = o->password;
  if (o->window)
    {
      /* Not used by the library config; windows come with each open.  */
    }

  memset (&ce, 0, sizeof ce);
  memset (&se, 0, sizeof se);
  ce.user = &w->c;
  ce.write = w_write;
  ce.host_key = w_host_key;
  ce.established = w_established;
  ce.unimplemented = w_unimpl;
  ce.auth_banner = w_banner;
  ce.auth_kbdint = o->kbd ? w_kbdint : NULL;
  ce.auth_failed = w_auth_failed;
  ce.authenticated = w_authenticated;
  ce.channel_confirmed = w_confirmed;
  ce.channel_failed = w_failed;
  ce.channel_data = w_data;
  ce.channel_request = w_request;
  ce.channel_eof = w_eof;
  ce.channel_closed = w_chan_closed;
  ce.global_reply = w_global_reply;
  ce.closed = w_closed;
  ce.channel_open = o->no_channel_cb ? NULL : w_channel_open;
  ce.global_request = w_global;

  se.user = &w->sv;
  se.write = w_write;
  se.established = w_established;
  se.unimplemented = w_unimpl;
  se.auth_request = w_auth_request;
  se.auth_kbdint_response = w_kbd_response;
  se.authenticated = w_authenticated;
  se.channel_open = o->no_channel_cb ? NULL : w_channel_open;
  se.channel_confirmed = w_confirmed;
  se.channel_failed = w_failed;
  se.channel_data = w_data;
  se.channel_request = w_request;
  se.channel_eof = w_eof;
  se.channel_closed = w_chan_closed;
  se.global_request = o->no_channel_cb ? NULL : w_global;
  se.global_reply = w_global_reply;
  se.closed = w_closed;

  CHECK_EQ (gf_session_client_new (&w->c.s, &cc, &ce), GF_OK);
  CHECK_EQ (gf_session_server_new (&w->sv.s, &sc, &se), GF_OK);
  w->sv.authorized = userkey;
  w->sv.accept_cert = o->ncas > 0;
  w->sv.password = o->authorized_pw;
  w->sv.code = "4711";
  w->c.kbd_answer = "4711";
  w->c.auto_exec = 1;
  w->sv.auto_serve = 1;
}

static void
node_free (struct node *x)
{
  gf_session_free (x->s);
  free (x->out.buf);
  free (x->rx);
}

static void
world_free (struct world *w)
{
  node_free (&w->c);
  node_free (&w->sv);
}

static void
deliver (struct node *from, struct node *to, size_t chunk)
{
  while (from->out.len > 0)
    {
      size_t n = chunk && chunk < from->out.len ? chunk : from->out.len;
      uint8_t *copy = malloc (n);

      memcpy (copy, from->out.buf, n);
      memmove (from->out.buf, from->out.buf + n, from->out.len - n);
      from->out.len -= n;
      if (gf_session_phase (to->s) != GF_PHASE_CLOSED)
        (void) gf_session_receive (to->s, now, copy, n);
      free (copy);
    }
}

static void
pump (struct world *w, size_t chunk)
{
  int guard = 0;

  while ((w->c.out.len || w->sv.out.len) && guard++ < 1000000)
    {
      deliver (&w->c, &w->sv, chunk);
      deliver (&w->sv, &w->c, chunk);
    }
}

static void
run (struct world *w)
{
  CHECK_EQ (gf_session_start (w->c.s, now), GF_OK);
  CHECK_EQ (gf_session_start (w->sv.s, now), GF_OK);
  pump (w, 0);
}

/* ---------------------------------------------------------------- */

static void
test_full_flow (void)
{
  static const size_t chunks[] = { 0, 1, 7, 1000 };
  size_t i;

  for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++)
    {
      struct world w;
      struct opts o;

      memset (&o, 0, sizeof o);
      o.client_trusts = 1;
      o.client_key = userkey;
      o.methods = GF_AUTH_PUBLICKEY;

      world_new (&w, &o);
      CHECK_EQ (gf_session_phase (w.c.s), GF_PHASE_HANDSHAKE);
      CHECK_EQ (gf_session_start (w.c.s, now), GF_OK);
      CHECK_EQ (gf_session_start (w.sv.s, now), GF_OK);
      pump (&w, chunks[i]);
      CHECK_EQ (w.c.established, 1);
      CHECK_EQ (w.sv.established, 1);
      CHECK_EQ (w.c.host_key_calls, 1);
      CHECK_EQ (w.c.authenticated, 1);
      CHECK_EQ (w.sv.authenticated, 1);
      CHECK_EQ (gf_session_phase (w.c.s), GF_PHASE_READY);
      CHECK_EQ (gf_session_phase (w.sv.s), GF_PHASE_READY);
      CHECK (w.sv.s && strcmp (gf_session_user (w.sv.s), "alice") == 0);
      CHECK (gf_session_user (w.c.s) == NULL);
      CHECK (gf_session_info (w.c.s) != NULL);
      /* The command ran: output, exit status, EOF, both closes.  */
      CHECK_EQ (w.sv.opens, 1);
      CHECK_EQ (w.c.confirmed, 1);
      CHECK_EQ (strcmp (w.sv.exec, "echo hi"), 0);
      CHECK (w.c.rxn == 3 && memcmp (w.c.rx, "hi\n", 3) == 0);
      CHECK (w.c.exited && w.c.exit_status == 0);
      CHECK_EQ (w.c.eofs, 1);
      CHECK_EQ (w.c.channel_closed, 1);
      CHECK_EQ (w.sv.channel_closed, 1);
      CHECK_EQ (gf_chans_count (gf_session_channels (w.c.s)), 0);
      /* An orderly end.  */
      CHECK_EQ (gf_session_disconnect (w.c.s, now, GF_DISCONNECT_BY_APPLICATION,
                                       "bye"), GF_OK);
      pump (&w, chunks[i]);
      CHECK_EQ (w.c.closed, 1);
      CHECK_EQ (w.c.close_error, 0);
      CHECK_EQ (w.sv.closed, 1);
      CHECK_EQ (w.sv.close_error, 0);
      CHECK_EQ (gf_session_phase (w.sv.s), GF_PHASE_CLOSED);
      world_free (&w);
    }
}

static void
test_auth_variants (void)
{
  struct world w;
  struct opts o;

  /* Password.  */
  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.password = "s3cret";
  o.authorized_pw = "s3cret";
  o.methods = GF_AUTH_PASSWORD;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 1);
  CHECK_EQ (w.sv.authenticated, 1);
  world_free (&w);

  /* The wrong password: the client runs out of methods and the session
     ends with the matching reason on both sides.  */
  o.authorized_pw = "other";
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 0);
  CHECK_EQ (w.c.auth_failed, 1);
  CHECK_EQ (w.c.closed, 1);
  CHECK_EQ (w.sv.closed, 1);
  CHECK_EQ (w.sv.close_reason, GF_DISCONNECT_NO_MORE_AUTH_METHODS);
  CHECK_EQ (gf_session_phase (w.c.s), GF_PHASE_CLOSED);
  world_free (&w);

  /* Keyboard-interactive.  */
  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.methods = GF_AUTH_KBDINT;
  o.kbd = 1;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 1);
  CHECK_EQ (w.c.kbd_prompts, 1);
  world_free (&w);
  o.kbd = 0;			/* No callback: the method is not tried.  */
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 0);
  CHECK_EQ (w.c.auth_failed, 1);
  world_free (&w);

  /* A key the server does not know, then the password.  */
  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = otherkey;
  o.password = "pw";
  o.authorized_pw = "pw";
  o.methods = GF_AUTH_PUBLICKEY | GF_AUTH_PASSWORD;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 1);
  world_free (&w);

  /* Host-bound public keys through the session.  */
  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = userkey;
  o.hostbound = 1;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 1);
  world_free (&w);

  /* A client with no host key callback trusts nothing.  */
  memset (&o, 0, sizeof o);
  o.client_trusts = 0;
  o.client_key = userkey;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 0);
  CHECK_EQ (w.c.closed, 1);
  CHECK_EQ (w.c.close_error, GF_ERR_HOSTKEY);
  CHECK_EQ (gf_session_phase (w.c.s), GF_PHASE_CLOSED);
  world_free (&w);
}

/* The server holds its answer, so the session is in AUTH on both ends.  */
static void
test_routing (void)
{
  struct world w;
  struct opts o;
  uint8_t m[64];
  gf_writer wr;

  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = userkey;

  /* A client that opens a channel before it is authenticated.  */
  world_new (&w, &o);
  w.sv.hold_auth = 1;
  w.c.auto_exec = 0;
  run (&w);
  CHECK_EQ (gf_session_phase (w.c.s), GF_PHASE_AUTH);
  CHECK_EQ (gf_session_phase (w.sv.s), GF_PHASE_AUTH);
  gf_writer_init (&wr, m, sizeof m);
  gf_wr_u8 (&wr, GF_MSG_CHANNEL_OPEN);
  gf_wr_cstring (&wr, "session");
  gf_wr_u32 (&wr, 0);
  gf_wr_u32 (&wr, 1000);
  gf_wr_u32 (&wr, 500);
  CHECK_EQ (gf_conn_send (gf_session_conn (w.c.s), now, m, wr.len), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.sv.opens, 0);
  CHECK_EQ (w.sv.closed, 1);
  CHECK_EQ (w.sv.close_reason, GF_DISCONNECT_PROTOCOL_ERROR);
  world_free (&w);

  /* A server that sends one to a client that is not authenticated.  */
  world_new (&w, &o);
  w.sv.hold_auth = 1;
  w.c.auto_exec = 0;
  run (&w);
  CHECK_EQ (gf_conn_send (gf_session_conn (w.sv.s), now, m, wr.len), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.c.closed, 1);
  CHECK_EQ (w.c.close_reason, GF_DISCONNECT_PROTOCOL_ERROR);
  world_free (&w);

  /* An unknown message number is answered, not fatal; authentication
     messages after success are ignored.  */
  world_new (&w, &o);
  w.c.auto_exec = 0;
  run (&w);
  CHECK_EQ (gf_session_phase (w.c.s), GF_PHASE_READY);
  m[0] = 200;
  CHECK_EQ (gf_conn_send (gf_session_conn (w.c.s), now, m, 1), GF_OK);
  m[0] = 101;
  CHECK_EQ (gf_conn_send (gf_session_conn (w.c.s), now, m, 1), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.c.unimpl, 2);
  CHECK_EQ (w.sv.closed, 0);
  gf_writer_init (&wr, m, sizeof m);
  gf_wr_u8 (&wr, GF_MSG_USERAUTH_REQUEST);
  gf_wr_cstring (&wr, "alice");
  gf_wr_cstring (&wr, "ssh-connection");
  gf_wr_cstring (&wr, "none");
  CHECK_EQ (gf_conn_send (gf_session_conn (w.c.s), now, m, wr.len), GF_OK);
  m[0] = GF_MSG_USERAUTH_PK_OK;
  CHECK_EQ (gf_conn_send (gf_session_conn (w.c.s), now, m, 1), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.sv.closed, 0);
  CHECK_EQ (w.c.closed, 0);
  world_free (&w);

  /* A malformed channel message after authentication ends the session.  */
  world_new (&w, &o);
  w.c.auto_exec = 0;
  run (&w);
  m[0] = GF_MSG_CHANNEL_DATA;
  CHECK_EQ (gf_conn_send (gf_session_conn (w.c.s), now, m, 1), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.sv.closed, 1);
  CHECK_EQ (w.sv.close_reason, GF_DISCONNECT_PROTOCOL_ERROR);
  world_free (&w);
}

static void
test_policy (void)
{
  struct world w;
  struct opts o;
  uint32_t a, b, c, id;
  gf_chans *ch;

  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = userkey;

  /* no-more-sessions: acknowledged, then every new session is refused
     without the application hearing of it.  */
  world_new (&w, &o);
  w.c.auto_exec = 0;
  run (&w);
  ch = gf_session_channels (w.c.s);
  CHECK_EQ (gf_chans_open_session (ch, &a, 0, 0), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.sv.opens, 1);
  CHECK_EQ (gf_chans_request_no_more_sessions (ch), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.c.global_replies, 1);
  CHECK (w.c.global_ok);
  CHECK_EQ (w.sv.global_requests, 0);		/* Not shown to the application.  */
  CHECK_EQ (gf_chans_open_session (ch, &b, 0, 0), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.c.failed, 1);
  CHECK_EQ (w.c.fail_reason, GF_OPEN_ADMINISTRATIVELY_PROHIBITED);
  CHECK_EQ (w.sv.opens, 1);
  /* Channels other than sessions are the application's call.  */
  CHECK_EQ (gf_chans_open_direct_tcpip (ch, &c, "h", 1, "o", 2, 0, 0), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.sv.opens, 2);
  world_free (&w);

  /* A limit on session channels, counted from the acceptance and freed at
     the close.  */
  o.max_sessions = 2;
  world_new (&w, &o);
  w.c.auto_exec = 0;
  run (&w);
  ch = gf_session_channels (w.c.s);
  CHECK_EQ (gf_chans_open_session (ch, &a, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_open_session (ch, &b, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_open_session (ch, &c, 0, 0), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.c.confirmed, 2);
  CHECK_EQ (w.c.failed, 1);
  CHECK_EQ (w.c.fail_reason, GF_OPEN_RESOURCE_SHORTAGE);
  CHECK_EQ (w.sv.opens, 2);
  CHECK_EQ (gf_chans_close (ch, a), GF_OK);
  pump (&w, 0);
  CHECK_EQ (gf_chans_open_session (ch, &id, 0, 0), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.c.confirmed, 3);
  world_free (&w);

  /* With no callbacks, everything is refused.  */
  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = userkey;
  o.no_channel_cb = 1;
  world_new (&w, &o);
  w.c.auto_exec = 0;
  run (&w);
  ch = gf_session_channels (w.c.s);
  CHECK_EQ (gf_chans_open_session (ch, &a, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_request_tcpip_forward (ch, "0.0.0.0", 8080), GF_OK);
  pump (&w, 0);
  CHECK_EQ (w.c.failed, 1);
  CHECK_EQ (w.c.fail_reason, GF_OPEN_ADMINISTRATIVELY_PROHIBITED);
  CHECK_EQ (w.c.global_replies, 1);
  CHECK (!w.c.global_ok);
  CHECK_EQ (w.sv.closed, 0);
  world_free (&w);

  /* The application can refuse a tcpip-forward, or grant it.  */
  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = userkey;
  world_new (&w, &o);
  w.c.auto_exec = 0;
  run (&w);
  ch = gf_session_channels (w.c.s);
  CHECK_EQ (gf_chans_request_tcpip_forward (ch, "0.0.0.0", 0), GF_OK);
  pump (&w, 0);
  CHECK (w.c.global_ok && w.c.global_port == 7000);
  w.sv.deny_global = 1;
  CHECK_EQ (gf_chans_request_tcpip_forward (ch, "0.0.0.0", 99), GF_OK);
  pump (&w, 0);
  CHECK (!w.c.global_ok);
  /* A server's own wrong-state answers.  */
  CHECK_EQ (gf_session_channel_accept (w.sv.s, 77, 0, 0), GF_ERR_STATE);
  CHECK_EQ (gf_session_channel_reject (w.sv.s, 77, 1, "no"), GF_ERR_STATE);
  CHECK_EQ (gf_session_auth_accept (w.c.s), GF_ERR_STATE);
  CHECK_EQ (gf_session_auth_kbdint_respond (w.sv.s, 0, NULL), GF_ERR_STATE);
  world_free (&w);
}

static void
test_deadlines (void)
{
  struct world w;
  struct opts o;

  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = userkey;
  now = 1000000;
  world_new (&w, &o);
  w.sv.hold_auth = 1;
  w.c.auto_exec = 0;
  CHECK_EQ (gf_session_timeout (w.sv.s), UINT64_MAX);
  run (&w);
  /* The earliest of the transport's rekey time and the grace time.  */
  CHECK_EQ (gf_session_timeout (w.sv.s), now + 120000000);
  CHECK_EQ (gf_session_on_timeout (w.sv.s, now + 119000000), GF_OK);
  CHECK_EQ (w.sv.closed, 0);
  CHECK_EQ (gf_session_on_timeout (w.sv.s, now + 120000000), GF_OK);
  CHECK_EQ (w.sv.closed, 1);
  pump (&w, 0);
  CHECK_EQ (w.c.closed, 1);
  CHECK_EQ (w.c.close_reason, GF_DISCONNECT_CONNECTION_LOST);
  CHECK_EQ (gf_session_timeout (w.sv.s), UINT64_MAX);
  world_free (&w);
}

static void
test_construction (void)
{
  gf_session *s;
  gf_session_config cfg;
  gf_session_events ev;

  memset (&cfg, 0, sizeof cfg);
  memset (&ev, 0, sizeof ev);
  cfg.conn.host_keys = &hostkey;
  cfg.conn.nhost_keys = 1;
  cfg.client_auth.user = "u";
  CHECK_EQ (gf_session_server_new (&s, &cfg, &ev), GF_ERR_INVAL);
  ev.write = w_write;
  CHECK_EQ (gf_session_server_new (&s, &cfg, &ev), GF_ERR_INVAL);	/* No auth. */
  ev.auth_request = w_auth_request;
  cfg.server_auth.methods = GF_AUTH_KBDINT;
  CHECK_EQ (gf_session_server_new (&s, &cfg, &ev), GF_ERR_INVAL);	/* No k-i.  */
  cfg.server_auth.methods = 0;
  CHECK_EQ (gf_session_server_new (&s, &cfg, &ev), GF_OK);
  gf_session_free (s);
  cfg.client_auth.user = NULL;
  CHECK_EQ (gf_session_client_new (&s, &cfg, &ev), GF_ERR_INVAL);
  cfg.client_auth.user = "u";
  CHECK_EQ (gf_session_client_new (&s, &cfg, &ev), GF_OK);
  gf_session_free (s);
}

/* ---------------------------------------------------------------- */
/* SFTP through the session                                          */
/* ---------------------------------------------------------------- */

struct fsx
{
  struct world *w;
  uint8_t *data;
  size_t len, cap;
  int server_requests;
  gf_sftp_server *srv;
  /* Client.  */
  gf_sftp_client *cli;
  uint8_t handle[8];
  size_t hlen;
  uint64_t pos, total;
  unsigned outstanding;
  int phase;			/* 0 open, 1 upload, 2 reopen, 3 download, 4 done */
  uint8_t *down;
  size_t downn;
  int ready, failed;
  const uint8_t *src;
};

static struct fsx fsx;

static int
fs_request (void *u, const gf_sftp_request *q)
{
  struct fsx *f = u;
  gf_sftp_server *s = f->srv;

  f->server_requests++;
  switch (q->type)
    {
    case GF_FXP_OPEN:
      if ((q->pflags & GF_FXF_TRUNC))
        f->len = 0;
      return gf_sftp_server_handle (s, q->id, (const uint8_t *) "H1", 2) != GF_OK;
    case GF_FXP_WRITE:
      if (q->offset + q->data.len > f->cap)
        {
          f->cap = (size_t) (q->offset + q->data.len) * 2;
          f->data = realloc (f->data, f->cap);
        }
      memcpy (f->data + q->offset, q->data.data, q->data.len);
      if (q->offset + q->data.len > f->len)
        f->len = (size_t) (q->offset + q->data.len);
      return gf_sftp_server_status (s, q->id, GF_FX_OK, "ok") != GF_OK;
    case GF_FXP_READ:
      if (q->offset >= f->len)
        return gf_sftp_server_status (s, q->id, GF_FX_EOF, "eof") != GF_OK;
      {
        size_t n = f->len - (size_t) q->offset;

        if (n > q->length)
          n = q->length;
        return gf_sftp_server_data (s, q->id, f->data + q->offset, n) != GF_OK;
      }
    case GF_FXP_CLOSE:
      return gf_sftp_server_status (s, q->id, GF_FX_OK, "ok") != GF_OK;
    default:
      return gf_sftp_server_status (s, q->id, GF_FX_OP_UNSUPPORTED, "no")
        != GF_OK;
    }
}

static int
fs_pump (struct fsx *f)
{
  uint8_t buf[32768];

  if (f->phase == 1)
    {
      while (f->pos < f->total && f->outstanding < 60)
        {
          size_t n = f->total - f->pos < sizeof buf ? (size_t) (f->total - f->pos)
                                                    : sizeof buf;
          int r;

          memcpy (buf, f->src + f->pos, n);
          r = gf_sftp_client_write (f->cli, f->handle, f->hlen, f->pos, buf, n,
                                    NULL, NULL);
          if (r == GF_ERR_AGAIN)
            return 0;
          if (r != GF_OK)
            return 1;
          f->pos += n;
          f->outstanding++;
        }
      if (f->pos >= f->total && f->outstanding == 0)
        {
          f->phase = 2;
          return gf_sftp_client_close (f->cli, f->handle, f->hlen, NULL, NULL)
            != GF_OK;
        }
    }
  else if (f->phase == 3)
    {
      while (f->pos < f->total + 32768 && f->outstanding < 60)
        {
          if (gf_sftp_client_read (f->cli, f->handle, f->hlen, f->pos, 32768,
                                   NULL, NULL) != GF_OK)
            return 0;
          f->pos += 32768;
          f->outstanding++;
        }
    }
  return 0;
}

static int
fc_ready (void *u)
{
  struct fsx *f = u;
  gf_sftp_attrs a;

  f->ready = 1;
  memset (&a, 0, sizeof a);
  return gf_sftp_client_open (f->cli, "file", GF_FXF_WRITE | GF_FXF_CREAT
                              | GF_FXF_TRUNC, &a, NULL, NULL) != GF_OK;
}

static int
fc_response (void *u, const gf_sftp_response *r)
{
  struct fsx *f = u;
  gf_sftp_attrs a;

  memset (&a, 0, sizeof a);
  if (r->type == GF_FXP_HANDLE)
    {
      memcpy (f->handle, r->handle.data, r->handle.len);
      f->hlen = r->handle.len;
      f->pos = 0;
      f->outstanding = 0;
      if (f->phase == 0)
        f->phase = 1;
      else if (f->phase == 2)
        f->phase = 3;
      return fs_pump (f);
    }
  if (f->phase == 1)
    {
      f->outstanding--;
      if (r->status != GF_FX_OK)
        f->failed = 1;
      return fs_pump (f);
    }
  if (f->phase == 2)
    {
      /* The close; reopen to read.  */
      return gf_sftp_client_open (f->cli, "file", GF_FXF_READ, &a, NULL, NULL)
        != GF_OK;
    }
  if (f->phase == 3)
    {
      f->outstanding--;
      if (r->type == GF_FXP_DATA)
        {
          memcpy (f->down + f->downn, r->data.data, r->data.len);
          f->downn += r->data.len;
        }
      else if (f->outstanding == 0)
        {
          f->phase = 4;
          return 0;
        }
      return fs_pump (f);
    }
  return 0;
}

static int
sftp_confirmed (void *u, uint32_t id)
{
  struct node *x = u;

  return gf_chans_request_subsystem (gf_session_channels (x->s), id, "sftp", 1)
    != GF_OK;
}

static int
sftp_reply (void *u, uint32_t id, int ok)
{
  struct node *x = u;
  gf_sftp_client_config cc;
  gf_sftp_client_events ce;

  if (!ok)
    return 1;
  memset (&cc, 0, sizeof cc);
  memset (&ce, 0, sizeof ce);
  ce.user = &fsx;
  ce.ready = fc_ready;
  ce.response = fc_response;
  return gf_session_sftp_client (x->s, id, &cc, &ce, &fsx.cli) != GF_OK;
}

static int
sftp_srv_request (void *u, const gf_chan_request *q)
{
  struct node *x = u;
  gf_sftp_server_config sc;
  gf_sftp_server_events se;
  gf_chans *ch = gf_session_channels (x->s);

  if (q->type != GF_REQ_SUBSYSTEM)
    return gf_chans_reply (ch, q->id, 0) != GF_OK;
  if (gf_chans_reply (ch, q->id, 1) != GF_OK)
    return 1;
  memset (&sc, 0, sizeof sc);
  memset (&se, 0, sizeof se);
  se.user = &fsx;
  se.request = fs_request;
  return gf_session_sftp_server (x->s, q->id, &sc, &se, &fsx.srv) != GF_OK;
}

static void
test_sftp (uint64_t rekey)
{
  struct world w;
  struct opts o;
  static uint8_t up[2500000], down[2600000];
  size_t i;

  for (i = 0; i < sizeof up; i++)
    up[i] = (uint8_t) (i * 13 + (i >> 9));
  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = userkey;
  o.rekey_bytes = rekey;
  memset (&fsx, 0, sizeof fsx);
  /* Windows far bigger than the transport will hold during a key exchange
     (1 MiB), so that sends are refused for a while and must be resumed.  */
  chan_window = 8 * 1024 * 1024;
  world_new (&w, &o);
  w.c.auto_exec = 0;
  w.c.auto_serve = 0;
  w.sv.auto_serve = 0;
  w.sv.authorized = userkey;
  /* Channels: a client that asks for the subsystem when its session channel
     opens, and a server that serves it.  */
  fsx.w = &w;
  fsx.src = up;
  fsx.total = sizeof up;
  fsx.down = down;
  {
    /* Replace the callbacks of the two nodes' sessions by building them
       again would be heavy; the nodes' callbacks are generic, so route
       through globals for this test.  */
  }
  node_free (&w.c);
  node_free (&w.sv);
  {
    gf_session_config cc, sc;
    gf_session_events ce, se;
    const gf_key *keys[1] = { userkey };

    memset (&cc, 0, sizeof cc);
    memset (&sc, 0, sizeof sc);
    memset (&ce, 0, sizeof ce);
    memset (&se, 0, sizeof se);
    sc.conn.host_keys = &hostkey;
    sc.conn.nhost_keys = 1;
    sc.conn.rekey_bytes = cc.conn.rekey_bytes = rekey;
    cc.client_auth.user = "alice";
    cc.client_auth.keys = keys;
    cc.client_auth.nkeys = 1;
    /* A big window so that more is in flight than the transport will
       hold during a key exchange.  */
    memset (&w.c, 0, sizeof w.c);
    memset (&w.sv, 0, sizeof w.sv);
    w.c.peer = &w.sv;
    w.sv.peer = &w.c;
    w.sv.is_server = 1;
    w.c.trust = 1;
    w.sv.authorized = userkey;
    ce.user = &w.c;
    ce.write = w_write;
    ce.host_key = w_host_key;
    ce.authenticated = w_authenticated;
    ce.channel_confirmed = sftp_confirmed;
    ce.channel_request_reply = sftp_reply;
    ce.closed = w_closed;
    se.user = &w.sv;
    se.write = w_write;
    se.auth_request = w_auth_request;
    se.channel_open = w_channel_open;
    se.channel_request = sftp_srv_request;
    se.closed = w_closed;
    w.c.auto_exec = 1;
    CHECK_EQ (gf_session_client_new (&w.c.s, &cc, &ce), GF_OK);
    CHECK_EQ (gf_session_server_new (&w.sv.s, &sc, &se), GF_OK);
  }
  /* The client's authenticated callback opens the session channel and
     requests exec; replace that by requesting the subsystem: sftp_confirmed
     does it.  The authenticated callback only opens the channel.  */
  run (&w);
  CHECK_EQ (w.c.authenticated, 1);
  CHECK (fsx.ready);
  CHECK_EQ (fsx.phase, 4);
  CHECK_EQ (fsx.failed, 0);
  CHECK_EQ (fsx.len, sizeof up);
  CHECK (fsx.len == sizeof up && memcmp (fsx.data, up, sizeof up) == 0);
  CHECK_EQ (fsx.downn, sizeof up);
  CHECK (fsx.downn == sizeof up && memcmp (down, up, sizeof up) == 0);
  CHECK_EQ (w.c.closed + w.sv.closed, 0);
  /* The client says it is finished: the server side closes the channel,
     which frees its SFTP object, and the client answers the close.  */
  CHECK_EQ (gf_chans_send_eof (gf_session_channels (w.c.s), w.c.chan), GF_OK);
  pump (&w, 0);
  CHECK_EQ (gf_chans_count (gf_session_channels (w.sv.s)), 0);
  CHECK_EQ (gf_chans_count (gf_session_channels (w.c.s)), 0);
  /* Binding again is refused: there is no such channel now.  */
  {
    gf_sftp_server_config sc;
    gf_sftp_server_events se;

    memset (&sc, 0, sizeof sc);
    memset (&se, 0, sizeof se);
    se.request = fs_request;
    CHECK_EQ (gf_session_sftp_server (w.sv.s, w.c.chan, &sc, &se, NULL),
              GF_ERR_STATE);
    CHECK_EQ (gf_session_sftp_server (w.sv.s, w.c.chan, &sc, NULL, NULL),
              GF_ERR_INVAL);
  }
  free (fsx.data);
  chan_window = 0;
  world_free (&w);
}

/* Sends the transport holds back during a key exchange: with a window much
   bigger than its queue, the sender is told to wait, and must be told when
   to go on.  */
static uint64_t pushed, ptotal;
static int resume_confirmed;

static int
push_data (struct node *x)
{
  static uint8_t buf[16384];
  gf_chans *ch = gf_session_channels (x->s);

  while (pushed < ptotal)
    {
      size_t n = sizeof buf, i;
      long r;

      if (n > ptotal - pushed)
        n = (size_t) (ptotal - pushed);
      for (i = 0; i < n; i++)
        buf[i] = (uint8_t) ((pushed + i) * 7);
      r = gf_chans_send_data (ch, x->chan, buf, n);
      if (r == GF_ERR_AGAIN || r == 0)
        return 0;
      if (r < 0)
        return 1;
      pushed += (uint64_t) r;
      if ((size_t) r < n)
        return 0;
    }
  return 0;
}

static int
rs_authenticated (void *u, gf_slice user)
{
  struct node *x = u;

  (void) user;
  return gf_chans_open_session (gf_session_channels (x->s), &x->chan,
                                chan_window, 0) != GF_OK;
}

static int
rs_confirmed (void *u, uint32_t id)
{
  struct node *x = u;

  (void) id;
  resume_confirmed = 1;
  if (gf_conn_rekey (gf_session_conn (x->s), now) != GF_OK)
    return 1;
  return push_data (x);
}

static int
rs_writable (void *u, uint32_t id)
{
  (void) id;
  return push_data (u);
}

static void
test_resume (void)
{
  struct world w;
  gf_session_config cc, sc;
  gf_session_events ce, se;
  static const gf_key *keys[1];
  size_t i;

  keys[0] = userkey;
  pushed = 0;
  ptotal = 5 * 1024 * 1024;
  chan_window = 8 * 1024 * 1024;
  resume_confirmed = 0;
  memset (&w, 0, sizeof w);
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  memset (&ce, 0, sizeof ce);
  memset (&se, 0, sizeof se);
  w.c.peer = &w.sv;
  w.sv.peer = &w.c;
  w.sv.is_server = 1;
  w.c.trust = 1;
  w.sv.authorized = userkey;
  sc.conn.host_keys = &hostkey;
  sc.conn.nhost_keys = 1;
  cc.client_auth.user = "alice";
  cc.client_auth.keys = keys;
  cc.client_auth.nkeys = 1;
  ce.user = &w.c;
  ce.write = w_write;
  ce.host_key = w_host_key;
  ce.authenticated = rs_authenticated;
  ce.channel_confirmed = rs_confirmed;
  ce.channel_writable = rs_writable;
  se.user = &w.sv;
  se.write = w_write;
  se.auth_request = w_auth_request;
  se.channel_open = w_channel_open;
  se.channel_data = w_data;
  CHECK_EQ (gf_session_client_new (&w.c.s, &cc, &ce), GF_OK);
  CHECK_EQ (gf_session_server_new (&w.sv.s, &sc, &se), GF_OK);
  run (&w);
  CHECK (resume_confirmed);
  CHECK_EQ (pushed, ptotal);
  CHECK_EQ (w.sv.rxn, ptotal);
  for (i = 0; i < w.sv.rxn; i += 4093)
    if (w.sv.rx[i] != (uint8_t) (i * 7))
      {
        CHECK (0);
        break;
      }
  chan_window = 0;
  world_free (&w);
}

/* Certificates, through the session: a user certificate (the server learns
   its forced command), and a server whose host key is a certificate.  */
static gf_key *
cert_of (const char *priv, const char *cert_hex)
{
  static uint8_t b[4096];
  gf_key *plain = NULL, *cert = NULL, *both = NULL;
  size_t n = tst_unhex (cert_hex, b, sizeof b);

  CHECK_EQ (gf_key_from_openssh_private (&plain, priv, strlen (priv)), GF_OK);
  CHECK_EQ (gf_key_from_blob (&cert, b, n), GF_OK);
  CHECK_EQ (gf_key_with_certificate (plain, cert, &both), GF_OK);
  gf_key_free (plain);
  gf_key_free (cert);
  return both;
}

static void
test_certificates (void)
{
  struct world w;
  struct opts o;
  gf_key *ca = NULL, *ukey, *hkey;
  const gf_key *cas[1];
  static uint8_t cab[256];
  size_t n = tst_unhex (vec_ca_ed_blob, cab, sizeof cab);

  CHECK_EQ (gf_key_from_blob (&ca, cab, n), GF_OK);
  cas[0] = ca;
  ukey = cert_of (vec_ed_private, vec_ed_user_cert);
  hkey = cert_of (vec_ed_private, vec_ed_host_cert);

  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = ukey;
  o.cas = cas;
  o.ncas = 1;
  o.peer_address = "192.0.2.50";
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 1);
  CHECK_EQ (w.sv.authenticated, 1);
  CHECK (!w.c.host_was_cert);
  CHECK (gf_session_force_command (w.sv.s) != NULL
         && strcmp (gf_session_force_command (w.sv.s), "/bin/true") == 0);
  CHECK (gf_session_force_command (w.c.s) == NULL);
  CHECK (strcmp (gf_session_user (w.sv.s), "alice") == 0);
  world_free (&w);

  /* The wrong address: the certificate is not taken.  */
  o.peer_address = "198.51.100.9";
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 0);
  CHECK_EQ (w.sv.authenticated, 0);
  CHECK (gf_session_force_command (w.sv.s) == NULL);
  world_free (&w);

  /* No CAs: the same client is not let in, and no command is invented.  */
  o.peer_address = "192.0.2.50";
  o.cas = NULL;
  o.ncas = 0;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.sv.authenticated, 0);
  world_free (&w);

  /* A host certificate: the client is shown the certificate, and the key
     exchange and everything after it work as with a plain key.  */
  memset (&o, 0, sizeof o);
  o.client_trusts = 1;
  o.client_key = userkey;
  o.host_key = hkey;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.host_key_calls, 1);
  CHECK (w.c.host_was_cert);
  CHECK (w.c.host_cert_ok);
  CHECK_EQ (w.c.authenticated, 1);
  CHECK (gf_session_force_command (w.sv.s) == NULL);
  world_free (&w);
  /* With the host-bound public key method, which signs over the host key
     blob: the certificate's.  */
  o.hostbound = 1;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.authenticated, 1);
  world_free (&w);
  /* The client, not trusting it, ends the connection.  */
  o.client_trusts = 0;
  world_new (&w, &o);
  run (&w);
  CHECK_EQ (w.c.host_key_calls, 1);
  CHECK_EQ (w.c.authenticated, 0);
  world_free (&w);

  gf_key_free (ukey);
  gf_key_free (hkey);
  gf_key_free (ca);
}

#ifdef HAVE_GNUTLS
/* An X.509 chain as the host key: the transport signs with the chain's key
   under the RFC 6187 algorithm and the client decides with the store.  */
static gf_key *
x509_host_key (const char *priv_pem, const char *blob_hex)
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

static void
test_x509_host_keys (void)
{
  static const struct
  {
    const char *priv, *blob;
    enum gf_sigalg alg;
  } v[] = {
    { vec_x_p256_private, vec_x_p256_blob, GF_SIG_X509_ECDSA_NISTP256 },
    { vec_x_p384_private, vec_x_p384_blob, GF_SIG_X509_ECDSA_NISTP384 },
    { vec_x_rsa_private, vec_x_rsa_blob, GF_SIG_X509_RSA2048_SHA256 }
  };
  static uint8_t d[8192];
  gf_x509_trust *root = NULL, *other = NULL;
  size_t i;

  CHECK_EQ (gf_x509_trust_new (&root), GF_OK);
  CHECK_EQ (gf_x509_trust_add_ca (root, d, tst_unhex (vec_x_root, d, sizeof d)), GF_OK);
  CHECK_EQ (gf_x509_trust_new (&other), GF_OK);
  CHECK_EQ (gf_x509_trust_add_ca (other, d, tst_unhex (vec_x_ca2, d, sizeof d)), GF_OK);
  for (i = 0; i < 3; i++)
    {
      struct world w;
      struct opts o;
      gf_key *hk = x509_host_key (v[i].priv, v[i].blob);

      memset (&o, 0, sizeof o);
      o.client_trusts = 1;
      o.client_key = userkey;
      o.host_key = hk;
      o.x509_trust = root;
      world_new (&w, &o);
      run (&w);
      CHECK_EQ (w.c.host_key_calls, 1);
      CHECK (w.c.host_was_x509 && w.c.host_x509_ok);
      CHECK_EQ (gf_session_info (w.c.s)->hostkey_alg, v[i].alg);
      CHECK_EQ (w.c.authenticated, 1);
      CHECK_EQ (w.sv.authenticated, 1);
      world_free (&w);
      /* Another CA's store: the callback refuses, nothing goes further.  */
      o.x509_trust = other;
      world_new (&w, &o);
      run (&w);
      CHECK (w.c.host_was_x509 && !w.c.host_x509_ok);
      CHECK_EQ (w.c.authenticated, 0);
      CHECK_EQ (w.sv.authenticated, 0);
      world_free (&w);
      /* Host-bound authentication signs over the chain's blob. */
      o.x509_trust = root;
      o.hostbound = 1;
      world_new (&w, &o);
      run (&w);
      CHECK_EQ (w.c.authenticated, 1);
      world_free (&w);
      gf_key_free (hk);
    }
  gf_x509_trust_free (root);
  gf_x509_trust_free (other);
}
#endif /* HAVE_GNUTLS */

int
main (void)
{
  gf_crypto_init ();
  CHECK_EQ (gf_key_generate (&hostkey, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&userkey, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&otherkey, GF_KEY_ECDSA_P256, 0), GF_OK);
  test_construction ();
  test_full_flow ();
  test_auth_variants ();
  test_routing ();
  test_policy ();
  test_deadlines ();
  test_resume ();
  test_sftp (0);
  test_sftp (400000);
  test_certificates ();
#ifdef HAVE_GNUTLS
  test_x509_host_keys ();
#endif
  gf_key_free (hostkey);
  gf_key_free (userkey);
  gf_key_free (otherkey);
  TST_DONE ();
}
