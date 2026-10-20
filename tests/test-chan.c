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
#include <foxtrot/chan.h>

#include "tst-util.h"

/* Two channel managers wired to each other; what one sends is queued for
   the other, so that a test can look at, change and inject messages.  */

#define MAXREQ 32

static void slice_str (char *out, size_t cap, gf_slice s);

struct reqlog
{
  enum gf_req_type type;
  uint32_t id;
  int want;
  char name[64], value[64], command[64], message[64];
  uint32_t a, b, c, d, status;
  int core;
  size_t modes;
};

struct node
{
  gf_chans *m;
  struct node *peer;
  uint8_t *q;
  size_t qn, qcap;
  int fail_send;		/* Make the send callback fail.  */
  int again_send;		/* Make the send callback say "try later".  */

  int auto_accept, open_requests, confirmed, failed, eofs, closed;
  int writable_calls, writable_consume;
  uint32_t fail_reason, last_open_id, closed_id;
  gf_chan_open open;
  char host[64], orig[64];
  char path[GF_MAX_SOCKET_PATH + 8];
  uint32_t accept_window, accept_packet;
  uint8_t *rx;
  size_t rxn, rxcap, rx_err;
  int consume_now;
  uint32_t disconnect;
  struct reqlog reqs[MAXREQ];
  size_t nreqs;
  int replies[MAXREQ];
  size_t nreplies;
  int answer_now;		/* Answer requests at once with success.  */
  struct { gf_global_request r; char addr[64]; char path[GF_MAX_SOCKET_PATH + 8]; } globals[MAXREQ];
  size_t nglobals;
  int global_replies[MAXREQ];
  uint32_t global_ports[MAXREQ];
  size_t ngreplies;
  gf_chans *self;
};

static int
n_send (void *user, const uint8_t *p, size_t n)
{
  struct node *x = user;
  struct node *y = x->peer;

  if (x->fail_send)
    return 1;
  if (x->again_send)
    return GF_ERR_AGAIN;
  if (y->qn + n + 4 > y->qcap)
    {
      y->qcap = (y->qn + n + 4) * 2;
      y->q = realloc (y->q, y->qcap);
    }
  y->q[y->qn] = (uint8_t) (n >> 24);
  y->q[y->qn + 1] = (uint8_t) (n >> 16);
  y->q[y->qn + 2] = (uint8_t) (n >> 8);
  y->q[y->qn + 3] = (uint8_t) n;
  memcpy (y->q + y->qn + 4, p, n);
  y->qn += n + 4;
  return 0;
}

static int
n_open_request (void *user, const gf_chan_open *o)
{
  struct node *x = user;

  x->open_requests++;
  x->open = *o;
  x->last_open_id = o->id;
  snprintf (x->host, sizeof x->host, "%.*s", (int) o->host.len,
            (const char *) o->host.data);
  snprintf (x->orig, sizeof x->orig, "%.*s", (int) o->orig_host.len,
            (const char *) o->orig_host.data);
  slice_str (x->path, sizeof x->path, o->path);
  x->open.host.data = (const uint8_t *) x->host;
  x->open.orig_host.data = (const uint8_t *) x->orig;
  x->open.path.data = (const uint8_t *) x->path;
  if (x->auto_accept)
    return gf_chans_open_accept (x->m, o->id, x->accept_window,
                                 x->accept_packet) != GF_OK;
  return 0;
}

static int
n_confirmed (void *user, uint32_t id)
{
  (void) id;
  ((struct node *) user)->confirmed++;
  return 0;
}

static int
n_failed (void *user, uint32_t id, uint32_t reason, gf_slice text)
{
  struct node *x = user;

  (void) id;
  (void) text;
  x->failed++;
  x->fail_reason = reason;
  return 0;
}

static int
n_data (void *user, uint32_t id, const uint8_t *d, size_t n)
{
  struct node *x = user;

  if (x->rxn + n > x->rxcap)
    {
      x->rxcap = (x->rxn + n) * 2;
      x->rx = realloc (x->rx, x->rxcap);
    }
  memcpy (x->rx + x->rxn, d, n);
  x->rxn += n;
  if (x->consume_now)
    return gf_chans_consumed (x->m, id, n) != GF_OK;
  return 0;
}

static int
n_ext (void *user, uint32_t id, uint32_t type, const uint8_t *d, size_t n)
{
  struct node *x = user;

  (void) type;
  (void) d;
  x->rx_err += n;
  return gf_chans_consumed (x->m, id, n) != GF_OK;
}

static int
n_eof (void *user, uint32_t id)
{
  (void) id;
  ((struct node *) user)->eofs++;
  return 0;
}

static int
n_writable (void *user, uint32_t id)
{
  struct node *x = user;

  (void) id;
  x->writable_calls++;
  return 0;
}

static int
n_closed (void *user, uint32_t id)
{
  struct node *x = user;

  x->closed++;
  x->closed_id = id;
  return 0;
}

static void
slice_str (char *out, size_t cap, gf_slice s)
{
  snprintf (out, cap, "%.*s", (int) s.len, (const char *) s.data);
}

static int
n_request (void *user, const gf_chan_request *q)
{
  struct node *x = user;
  struct reqlog *r;

  if (x->nreqs >= MAXREQ)
    return 1;
  r = &x->reqs[x->nreqs++];
  memset (r, 0, sizeof *r);
  r->type = q->type;
  r->id = q->id;
  r->want = q->want_reply;
  slice_str (r->name, sizeof r->name, q->name);
  slice_str (r->value, sizeof r->value, q->value);
  slice_str (r->command, sizeof r->command, q->command);
  slice_str (r->message, sizeof r->message, q->message);
  r->a = q->cols;
  r->b = q->rows;
  r->c = q->width;
  r->d = q->height;
  r->status = q->status;
  r->core = q->core_dumped;
  r->modes = q->modes.len;
  if (q->want_reply && x->answer_now)
    return gf_chans_reply (x->m, q->id, 1) != GF_OK;
  return 0;
}

static int
n_reply (void *user, uint32_t id, int ok)
{
  struct node *x = user;

  (void) id;
  if (x->nreplies < MAXREQ)
    x->replies[x->nreplies++] = ok;
  return 0;
}

static int
n_global (void *user, const gf_global_request *r)
{
  struct node *x = user;

  if (x->nglobals >= MAXREQ)
    return 1;
  x->globals[x->nglobals].r = *r;
  slice_str (x->globals[x->nglobals].addr, 64, r->addr);
  slice_str (x->globals[x->nglobals].path, sizeof x->globals[0].path, r->path);
  x->globals[x->nglobals].r.path.data = (const uint8_t *) x->globals[x->nglobals].path;
  x->nglobals++;
  return 0;
}

static int
n_global_reply (void *user, int ok, uint32_t port)
{
  struct node *x = user;

  if (x->ngreplies < MAXREQ)
    {
      x->global_replies[x->ngreplies] = ok;
      x->global_ports[x->ngreplies++] = port;
    }
  return 0;
}

static int
n_disconnect (void *user, uint32_t reason)
{
  ((struct node *) user)->disconnect = reason;
  return 0;
}

struct net
{
  struct node a, b;
};

static gf_chans_config
cfg (unsigned channels, unsigned requests, int auto_window)
{
  gf_chans_config c;

  c.max_channels = channels;
  c.max_requests = requests;
  c.auto_window = auto_window;
  return c;
}

static void
net_new (struct net *n, const gf_chans_config *ca, const gf_chans_config *cb)
{
  gf_chans_events ev;
  struct node *x;
  int i;

  memset (n, 0, sizeof *n);
  n->a.peer = &n->b;
  n->b.peer = &n->a;
  for (i = 0; i < 2; i++)
    {
      x = i ? &n->b : &n->a;
      memset (&ev, 0, sizeof ev);
      ev.user = x;
      ev.send = n_send;
      ev.open_request = n_open_request;
      ev.open_confirmed = n_confirmed;
      ev.open_failed = n_failed;
      ev.data = n_data;
      ev.extended_data = n_ext;
      ev.eof = n_eof;
      ev.writable = n_writable;
      ev.request = n_request;
      ev.request_reply = n_reply;
      ev.global_request = n_global;
      ev.global_reply = n_global_reply;
      ev.closed = n_closed;
      ev.disconnect = n_disconnect;
      CHECK_EQ (gf_chans_new (&x->m, i ? cb : ca, &ev), GF_OK);
      x->auto_accept = 1;
      x->consume_now = 1;
    }
}

static void
net_free (struct net *n)
{
  size_t i;

  gf_chans_free (n->a.m);
  gf_chans_free (n->b.m);
  free (n->a.q);
  free (n->b.q);
  free (n->a.rx);
  free (n->b.rx);
  (void) i;
}

/* Deliver the messages queued FOR X (sent by its peer), one by one, until
   nothing is left anywhere.  */
static void
pump (struct net *n)
{
  int guard = 0;

  while ((n->a.qn || n->b.qn) && guard++ < 1000000)
    {
      struct node *x = n->a.qn ? &n->a : &n->b;
      size_t len = (size_t) x->q[0] << 24 | x->q[1] << 16 | x->q[2] << 8 | x->q[3];
      uint8_t *msg = malloc (len);

      memcpy (msg, x->q + 4, len);
      memmove (x->q, x->q + 4 + len, x->qn - 4 - len);
      x->qn -= 4 + len;
      (void) gf_chans_input (x->m, msg, len);
      free (msg);
    }
}

/* The type of the first message queued for X, 0 if none; and deliver
   (or just drop) that message.  */
static int
first_type (const struct node *x)
{
  return x->qn ? x->q[4] : 0;
}

static void
take_one (struct node *x, int deliver_it)
{
  size_t len = (size_t) x->q[0] << 24 | x->q[1] << 16 | x->q[2] << 8 | x->q[3];
  uint8_t *msg = malloc (len);

  memcpy (msg, x->q + 4, len);
  memmove (x->q, x->q + 4 + len, x->qn - 4 - len);
  x->qn -= 4 + len;
  if (deliver_it)
    (void) gf_chans_input (x->m, msg, len);
  free (msg);
}

/* Open a session channel from A and return A's id; B's is in
   b.last_open_id.  */
static uint32_t
open_session (struct net *n, uint32_t window, uint32_t packet)
{
  uint32_t id = 99;

  n->b.accept_window = window;
  n->b.accept_packet = packet;
  CHECK_EQ (gf_chans_open_session (n->a.m, &id, window, packet), GF_OK);
  pump (n);
  CHECK_EQ (n->a.confirmed >= 1, 1);
  return id;
}

/* Feed a hand-made message to X.  */
static int
inject (struct node *x, const uint8_t *p, size_t n)
{
  return gf_chans_input (x->m, p, n);
}

static size_t
msg_u32 (uint8_t *buf, uint8_t type, uint32_t a, uint32_t b, int nb)
{
  gf_writer w;

  gf_writer_init (&w, buf, 64);
  gf_wr_u8 (&w, type);
  gf_wr_u32 (&w, a);
  if (nb)
    gf_wr_u32 (&w, b);
  return w.len;
}

static size_t
msg_data (uint8_t *buf, size_t cap, uint8_t type, uint32_t id, uint32_t xtype,
          size_t len)
{
  gf_writer w;

  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, type);
  gf_wr_u32 (&w, id);
  if (type == GF_MSG_CHANNEL_EXTENDED_DATA)
    gf_wr_u32 (&w, xtype);
  gf_wr_u32 (&w, (uint32_t) len);
  while (len--)
    gf_wr_u8 (&w, 'x');
  return w.len;
}

/* ---------------------------------------------------------------- */

static void
test_open_data_close (void)
{
  struct net n;
  uint32_t a, b;
  const uint8_t hello[] = "hello, channel";
  long r;

  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 0, 0);
  b = n.b.last_open_id;
  CHECK_EQ (n.b.open_requests, 1);
  CHECK_EQ (n.b.open.type, GF_CHAN_SESSION);
  CHECK_EQ (n.b.open.window, GF_CHAN_DEFAULT_WINDOW);
  CHECK_EQ (n.b.open.max_packet, GF_CHAN_DEFAULT_PACKET);
  CHECK_EQ (gf_chans_writable (n.a.m, a), GF_CHAN_DEFAULT_WINDOW);
  CHECK_EQ (gf_chans_remote_max_packet (n.a.m, a), GF_CHAN_DEFAULT_PACKET);
  CHECK_EQ (gf_chans_count (n.a.m), 1);

  r = gf_chans_send_data (n.a.m, a, hello, sizeof hello - 1);
  CHECK_EQ (r, (long) sizeof hello - 1);
  r = gf_chans_send_extended (n.b.m, b, 1, hello, 5);
  CHECK_EQ (r, 5);
  CHECK_EQ (gf_chans_send_extended (n.b.m, b, 2, hello, 5), GF_ERR_INVAL);
  pump (&n);
  CHECK (n.b.rxn == sizeof hello - 1 && memcmp (n.b.rx, hello, n.b.rxn) == 0);
  CHECK_EQ (n.a.rx_err, 5);

  CHECK_EQ (gf_chans_send_eof (n.a.m, a), GF_OK);
  CHECK_EQ (gf_chans_send_eof (n.a.m, a), GF_ERR_STATE);
  CHECK_EQ (gf_chans_send_data (n.a.m, a, hello, 1), GF_ERR_STATE);
  pump (&n);
  CHECK_EQ (n.b.eofs, 1);
  /* B can still talk after A's EOF.  */
  CHECK_EQ (gf_chans_send_data (n.b.m, b, hello, 3), 3);
  pump (&n);
  CHECK_EQ (n.a.rxn, 3);

  CHECK_EQ (gf_chans_close (n.a.m, a), GF_OK);
  CHECK_EQ (n.a.closed, 0);		/* Not until B has closed too.  */
  pump (&n);
  CHECK_EQ (n.b.closed, 1);
  CHECK_EQ (n.a.closed, 1);
  CHECK_EQ (n.a.closed_id, a);
  CHECK_EQ (gf_chans_count (n.a.m), 0);
  CHECK_EQ (gf_chans_count (n.b.m), 0);
  CHECK_EQ (n.a.disconnect + n.b.disconnect, 0);
  /* Gone: nothing can be done with it, and the number is free.  */
  CHECK_EQ (gf_chans_send_data (n.a.m, a, hello, 1), GF_ERR_STATE);
  CHECK_EQ (gf_chans_close (n.a.m, a), GF_ERR_STATE);
  net_free (&n);
}

/* A big transfer through a small window with a slow reader: the window is
   never exceeded, nothing is lost or reordered, and it finishes.  */
static void
test_flow_control (void)
{
  struct net n;
  uint32_t a, b;
  static uint8_t src[300000];
  size_t sent = 0, i, consumed = 0, rounds = 0;

  for (i = 0; i < sizeof src; i++)
    src[i] = (uint8_t) (i * 31 + (i >> 8));
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  n.b.consume_now = 0;			/* B reads when it likes.  */
  a = open_session (&n, 20000, 1000);
  b = n.b.last_open_id;
  CHECK_EQ (gf_chans_writable (n.a.m, a), 20000);
  CHECK_EQ (gf_chans_remote_max_packet (n.a.m, a), 1000);

  while ((sent < sizeof src || consumed < sizeof src) && rounds++ < 100000)
    {
      size_t take;

      if (sent < sizeof src)
        {
          long r = gf_chans_send_data (n.a.m, a, src + sent, sizeof src - sent);

          CHECK (r >= 0);
          if (r < 0)
            break;
          sent += (size_t) r;
        }
      pump (&n);
      /* B's reader deals with a few bytes at a time.  */
      take = n.b.rxn - consumed;
      if (take > 3000)
        take = 3000;
      if (take)
        CHECK_EQ (gf_chans_consumed (n.b.m, b, take), GF_OK);
      consumed += take;
      pump (&n);
    }
  CHECK_EQ (sent, sizeof src);
  CHECK_EQ (n.b.rxn, sizeof src);
  CHECK (memcmp (n.b.rx, src, sizeof src) == 0);
  CHECK_EQ (n.a.disconnect + n.b.disconnect, 0);
  CHECK (n.a.writable_calls > 0);	/* The sender was told when to retry.  */
  net_free (&n);
}

/* The sender fills the window and stops; consuming reopens it.  */
static void
test_window_stall (void)
{
  struct net n;
  uint32_t a, b;
  static uint8_t big[100000];
  long r;

  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  n.b.consume_now = 0;
  a = open_session (&n, 5000, 1000);
  b = n.b.last_open_id;
  r = gf_chans_send_data (n.a.m, a, big, sizeof big);
  CHECK_EQ (r, 5000);
  CHECK_EQ (gf_chans_writable (n.a.m, a), 0);
  CHECK_EQ (gf_chans_send_data (n.a.m, a, big, 10), 0);
  pump (&n);
  CHECK_EQ (n.b.rxn, 5000);
  CHECK_EQ (n.a.writable_calls, 0);
  /* A small amount consumed is held back (batched); half the window opens it.  */
  CHECK_EQ (gf_chans_consumed (n.b.m, b, 100), GF_OK);
  pump (&n);
  CHECK_EQ (gf_chans_writable (n.a.m, a), 0);
  CHECK_EQ (gf_chans_consumed (n.b.m, b, 2400), GF_OK);
  pump (&n);
  CHECK_EQ (gf_chans_writable (n.a.m, a), 2500);
  CHECK_EQ (n.a.writable_calls, 1);
  /* Consuming more than was received is a bug of the caller.  */
  CHECK_EQ (gf_chans_consumed (n.b.m, b, 1000000), GF_ERR_INVAL);
  CHECK_EQ (n.b.disconnect, 0);
  net_free (&n);

  /* With auto_window the library gives the window back itself.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 1 }, &(gf_chans_config) { 0, 0, 1 });
  n.b.consume_now = 0;
  a = open_session (&n, 5000, 1000);
  {
    size_t total = 0;
    int guard = 0;

    while (total < 60000 && guard++ < 1000)
      {
        r = gf_chans_send_data (n.a.m, a, big, 60000 - total);
        CHECK (r >= 0);
        total += (size_t) r;
        pump (&n);
      }
    CHECK_EQ (total, 60000);
    CHECK_EQ (n.b.rxn, 60000);
  }
  net_free (&n);
}

/* Everything a peer may not do ends the connection.  */
static void
test_violations (void)
{
  struct net n;
  uint32_t a, b;
  uint8_t m[2048];
  size_t len, i;

  /* Data over the window, over the packet size, to nowhere.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 1000, 500);
  b = n.b.last_open_id;
  (void) a;
  len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, b, 0, 501);
  CHECK (inject (&n.b, m, len) != GF_OK);	/* Over max packet.  */
  CHECK_EQ (n.b.disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  CHECK_EQ (inject (&n.b, m, len), GF_ERR_CLOSED);
  net_free (&n);

  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 1000, 500);
  b = n.b.last_open_id;
  n.b.consume_now = 0;
  len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, b, 0, 500);
  CHECK_EQ (inject (&n.b, m, len), GF_OK);
  CHECK_EQ (inject (&n.b, m, len), GF_OK);	/* 1000: exactly the window.  */
  CHECK_EQ (n.b.disconnect, 0);
  len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, b, 0, 1);
  CHECK (inject (&n.b, m, len) != GF_OK);	/* One byte more.  */
  CHECK_EQ (n.b.disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  net_free (&n);

  static const struct
  {
    const char *what;
    int kind;
  } cases[] = {
    { "data to a channel that does not exist", 0 },
    { "data after EOF", 1 },
    { "second EOF", 2 },
    { "extended data of an unknown type", 3 },
    { "window adjust beyond 2^32 - 1", 4 },
    { "close of a channel that does not exist", 5 },
    { "success with no request waiting", 6 },
    { "failure with no request waiting", 7 },
    { "confirmation of nothing", 8 },
    { "open failure of nothing", 9 },
    { "unknown message number", 10 },
    { "truncated data", 11 },
    { "data with a trailing byte", 12 },
    { "request on a channel that does not exist", 13 },
    { "global success with no request waiting", 14 },
    { "message in the wrong state: data to a channel not yet accepted", 15 },
    { "second close", 16 },
    { "open with port over 65535", 17 },
    { "open with a duplicate sender number", 18 },
    { "data after close", 19 },
    { "request after close", 20 },
    { "window adjust of a missing channel", 21 },
    { "confirmation of a channel that is already open", 22 }
  };

  for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
    {
      int rc;

      net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
      a = open_session (&n, 1000, 500);
      b = n.b.last_open_id;
      switch (cases[i].kind)
        {
        case 0:
          len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, 40, 0, 4);
          break;
        case 1:
          CHECK_EQ (gf_chans_send_eof (n.a.m, a), GF_OK);
          pump (&n);
          len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, b, 0, 4);
          break;
        case 2:
          CHECK_EQ (gf_chans_send_eof (n.a.m, a), GF_OK);
          pump (&n);
          len = msg_u32 (m, GF_MSG_CHANNEL_EOF, b, 0, 0);
          break;
        case 3:
          len = msg_data (m, sizeof m, GF_MSG_CHANNEL_EXTENDED_DATA, b, 2, 4);
          break;
        case 4:
          len = msg_u32 (m, GF_MSG_CHANNEL_WINDOW_ADJUST, a, 0xffffffffu, 1);
          /* A's peer window is 1000: adding 2^32 - 1 overflows.  */
          rc = inject (&n.a, m, len);
          CHECK (rc != GF_OK);
          CHECK_EQ (n.a.disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
          net_free (&n);
          continue;
        case 5:
          len = msg_u32 (m, GF_MSG_CHANNEL_CLOSE, 30, 0, 0);
          break;
        case 6:
          len = msg_u32 (m, GF_MSG_CHANNEL_SUCCESS, b, 0, 0);
          break;
        case 7:
          len = msg_u32 (m, GF_MSG_CHANNEL_FAILURE, b, 0, 0);
          break;
        case 8:
          len = msg_u32 (m, GF_MSG_CHANNEL_OPEN_CONFIRMATION, 3, 7, 1);
          m[len++] = 0, m[len++] = 0, m[len++] = 0, m[len++] = 5;
          m[len++] = 0, m[len++] = 0, m[len++] = 1, m[len++] = 0;
          break;
        case 9:
          len = msg_u32 (m, GF_MSG_CHANNEL_OPEN_FAILURE, 3, 1, 1);
          memset (m + len, 0, 8);
          len += 8;
          break;
        case 10:
          m[0] = 101;
          len = 1;
          break;
        case 11:
          len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, b, 0, 4);
          len -= 2;
          break;
        case 12:
          len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, b, 0, 4);
          m[len++] = 0;
          break;
        case 13:
          {
            gf_writer w;

            gf_writer_init (&w, m, sizeof m);
            gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
            gf_wr_u32 (&w, 50);
            gf_wr_cstring (&w, "shell");
            gf_wr_bool (&w, 0);
            len = w.len;
          }
          break;
        case 14:
          m[0] = GF_MSG_REQUEST_SUCCESS;
          len = 1;
          break;
        case 15:
          {
            uint32_t id2 = 0;

            n.b.auto_accept = 0;
            CHECK_EQ (gf_chans_open_session (n.a.m, &id2, 0, 0), GF_OK);
            pump (&n);
            /* B has not accepted: A has no remote number, but a
               confused B receives data for the pending channel.  */
            len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, n.b.last_open_id,
                            0, 4);
            rc = inject (&n.b, m, len);
            CHECK (rc != GF_OK);
            CHECK_EQ (n.b.disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
            net_free (&n);
            continue;
          }
        case 16:
          CHECK_EQ (gf_chans_close (n.a.m, a), GF_OK);
          pump (&n);
          len = msg_u32 (m, GF_MSG_CHANNEL_CLOSE, b, 0, 0);
          /* Gone on both sides: it names nothing.  */
          break;
        case 17:
          {
            gf_writer w;

            gf_writer_init (&w, m, sizeof m);
            gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
            gf_wr_cstring (&w, "direct-tcpip");
            gf_wr_u32 (&w, 77);
            gf_wr_u32 (&w, 1000);
            gf_wr_u32 (&w, 500);
            gf_wr_cstring (&w, "localhost");
            gf_wr_u32 (&w, 70000);
            gf_wr_cstring (&w, "origin");
            gf_wr_u32 (&w, 1);
            len = w.len;
          }
          break;
        case 18:
          {
            gf_writer w;

            /* The peer's own number for the first channel is a's id.  */
            gf_writer_init (&w, m, sizeof m);
            gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
            gf_wr_cstring (&w, "session");
            gf_wr_u32 (&w, a);
            gf_wr_u32 (&w, 1000);
            gf_wr_u32 (&w, 500);
            len = w.len;
          }
          break;
        case 19:
          CHECK_EQ (gf_chans_close (n.a.m, a), GF_OK);
          pump (&n);
          len = msg_data (m, sizeof m, GF_MSG_CHANNEL_DATA, b, 0, 4);
          break;
        case 20:
          {
            gf_writer w;

            CHECK_EQ (gf_chans_close (n.a.m, a), GF_OK);
            pump (&n);
            gf_writer_init (&w, m, sizeof m);
            gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
            gf_wr_u32 (&w, b);
            gf_wr_cstring (&w, "shell");
            gf_wr_bool (&w, 0);
            len = w.len;
          }
          break;
        case 22:
          len = msg_u32 (m, GF_MSG_CHANNEL_OPEN_CONFIRMATION, a, 9, 1);
          m[len++] = 0, m[len++] = 0, m[len++] = 3, m[len++] = 232;
          m[len++] = 0, m[len++] = 0, m[len++] = 1, m[len++] = 244;
          rc = inject (&n.a, m, len);
          CHECK (rc != GF_OK);
          CHECK_EQ (n.a.disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
          net_free (&n);
          continue;
        default:
          len = msg_u32 (m, GF_MSG_CHANNEL_WINDOW_ADJUST, 60, 5, 1);
          break;
        }
      rc = inject (&n.b, m, len);
      if (rc == GF_OK)
        fprintf (stderr, "accepted: %s\n", cases[i].what);
      CHECK (rc != GF_OK);
      CHECK_EQ (n.b.disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
      net_free (&n);
    }
}

/* Each kind of request arrives with its fields, and replies come back in
   the order the requests were made, whether the application or the
   library answers.  */
static void
test_requests (void)
{
  struct net n;
  uint32_t a, b;
  static const uint8_t modes[] = { 53, 0, 0, 0, 1, 0 };

  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  n.b.answer_now = 1;
  a = open_session (&n, 0, 0);
  b = n.b.last_open_id;

  CHECK_EQ (gf_chans_request_env (n.a.m, a, "LANG", "C.UTF-8", 1), GF_OK);
  CHECK_EQ (gf_chans_request_pty (n.a.m, a, "xterm", 80, 24, 640, 480, modes,
                                  sizeof modes, 1), GF_OK);
  CHECK_EQ (gf_chans_request_exec (n.a.m, a, "echo hello", 1), GF_OK);
  CHECK_EQ (gf_chans_request_shell (n.a.m, a, 1), GF_OK);
  CHECK_EQ (gf_chans_request_subsystem (n.a.m, a, "sftp", 1), GF_OK);
  CHECK_EQ (gf_chans_request_window_change (n.a.m, a, 100, 50, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_request_signal (n.a.m, a, "INT"), GF_OK);
  pump (&n);
  CHECK_EQ (n.b.nreqs, 7);
  CHECK_EQ (n.b.reqs[0].type, GF_REQ_ENV);
  CHECK (strcmp (n.b.reqs[0].name, "LANG") == 0
         && strcmp (n.b.reqs[0].value, "C.UTF-8") == 0);
  CHECK_EQ (n.b.reqs[1].type, GF_REQ_PTY);
  CHECK (strcmp (n.b.reqs[1].name, "xterm") == 0);
  CHECK (n.b.reqs[1].a == 80 && n.b.reqs[1].b == 24 && n.b.reqs[1].c == 640
         && n.b.reqs[1].d == 480 && n.b.reqs[1].modes == sizeof modes);
  CHECK_EQ (n.b.reqs[2].type, GF_REQ_EXEC);
  CHECK (strcmp (n.b.reqs[2].command, "echo hello") == 0 && n.b.reqs[2].want);
  CHECK_EQ (n.b.reqs[3].type, GF_REQ_SHELL);
  CHECK_EQ (n.b.reqs[4].type, GF_REQ_SUBSYSTEM);
  CHECK (strcmp (n.b.reqs[4].command, "sftp") == 0);
  CHECK_EQ (n.b.reqs[5].type, GF_REQ_WINDOW_CHANGE);
  CHECK (n.b.reqs[5].a == 100 && n.b.reqs[5].b == 50 && !n.b.reqs[5].want);
  CHECK_EQ (n.b.reqs[6].type, GF_REQ_SIGNAL);
  CHECK (strcmp (n.b.reqs[6].name, "INT") == 0);
  CHECK_EQ (n.a.nreplies, 5);		/* The five that wanted one.  */
  CHECK (n.a.replies[0] && n.a.replies[4]);

  CHECK_EQ (gf_chans_request_exit_status (n.b.m, b, 3), GF_OK);
  CHECK_EQ (gf_chans_request_exit_signal (n.b.m, b, "SEGV", 1, "boom"), GF_OK);
  CHECK_EQ (gf_chans_request_exit_status (n.b.m, b, 0), GF_OK);
  pump (&n);
  CHECK_EQ (n.a.nreqs, 3);
  CHECK_EQ (n.a.reqs[0].type, GF_REQ_EXIT_STATUS);
  CHECK_EQ (n.a.reqs[0].status, 3);
  CHECK_EQ (n.a.reqs[1].type, GF_REQ_EXIT_SIGNAL);
  CHECK (strcmp (n.a.reqs[1].name, "SEGV") == 0 && n.a.reqs[1].core
         && strcmp (n.a.reqs[1].message, "boom") == 0);

  /* Bad arguments.  */
  CHECK_EQ (gf_chans_request_exec (n.a.m, a, NULL, 1), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_request_exit_signal (n.b.m, b, "X", 0, "\xff"), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_request_env (n.a.m, 55, "A", "b", 0), GF_ERR_STATE);
  net_free (&n);

  /* Order: the application answers the first request late; the library
     refuses the next two (types it does not know) but must send that
     behind the first.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 0, 0);
  b = n.b.last_open_id;
  CHECK_EQ (gf_chans_request_exec (n.a.m, a, "one", 1), GF_OK);
  pump (&n);
  {
    uint8_t m[256];
    gf_writer w;
    size_t i;

    /* x11-req and an agent request, from a client that wants a reply.  */
    for (i = 0; i < 2; i++)
      {
        gf_writer_init (&w, m, sizeof m);
        gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
        gf_wr_u32 (&w, b);
        gf_wr_cstring (&w, i ? "auth-agent-req@openssh.com" : "x11-req");
        gf_wr_bool (&w, 1);
        gf_wr_bool (&w, 0);
        gf_wr_cstring (&w, "MIT-MAGIC-COOKIE-1");
        gf_wr_cstring (&w, "00");
        gf_wr_u32 (&w, 0);
        CHECK_EQ (inject (&n.b, m, w.len), GF_OK);
      }
  }
  CHECK_EQ (gf_chans_request_exec (n.a.m, a, "two", 1), GF_OK);
  pump (&n);
  CHECK_EQ (n.b.nreqs, 2);		/* "one" and "two"; not the others.  */
  CHECK_EQ (n.a.qn, 0);			/* Nothing answered yet.  */
  CHECK_EQ (gf_chans_reply (n.b.m, b, 1), GF_OK);
  /* "one" first, then the two refusals that were behind it.  */
  CHECK_EQ (first_type (&n.a), GF_MSG_CHANNEL_SUCCESS);
  take_one (&n.a, 1);
  CHECK_EQ (first_type (&n.a), GF_MSG_CHANNEL_FAILURE);
  take_one (&n.a, 0);
  CHECK_EQ (first_type (&n.a), GF_MSG_CHANNEL_FAILURE);
  take_one (&n.a, 0);
  CHECK_EQ (n.a.qn, 0);
  CHECK_EQ (gf_chans_reply (n.b.m, b, 0), GF_OK);
  CHECK_EQ (first_type (&n.a), GF_MSG_CHANNEL_FAILURE);
  take_one (&n.a, 1);
  CHECK_EQ (n.a.nreplies, 2);
  CHECK (n.a.replies[0] == 1 && n.a.replies[1] == 0);
  CHECK_EQ (gf_chans_reply (n.b.m, b, 1), GF_ERR_STATE);	/* None owed.  */
  CHECK_EQ (n.a.disconnect + n.b.disconnect, 0);
  net_free (&n);

  /* An unknown request nobody waits on is dropped, and one on its own is
     refused at once.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 0, 0);
  b = n.b.last_open_id;
  {
    uint8_t m[64];
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
    gf_wr_u32 (&w, b);
    gf_wr_cstring (&w, "keepalive@openssh.com");
    gf_wr_bool (&w, 0);
    CHECK_EQ (inject (&n.b, m, w.len), GF_OK);
    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
    gf_wr_u32 (&w, b);
    gf_wr_cstring (&w, "keepalive@openssh.com");
    gf_wr_bool (&w, 1);
    CHECK_EQ (inject (&n.b, m, w.len), GF_OK);
  }
  CHECK_EQ (n.b.nreqs, 0);
  /* Only the one that asked for a reply got one: a failure.  */
  CHECK_EQ (first_type (&n.a), GF_MSG_CHANNEL_FAILURE);
  take_one (&n.a, 0);
  CHECK_EQ (n.a.qn, 0);
  CHECK_EQ (n.b.qn, 0);
  net_free (&n);

  /* Too many requests waiting for the application.  */
  {
    gf_chans_config c4 = cfg (0, 4, 0);

    net_new (&n, &c4, &c4);
  }
  a = open_session (&n, 0, 0);
  b = n.b.last_open_id;
  {
    int i, rc = GF_OK;

    for (i = 0; i < 4; i++)
      CHECK_EQ (gf_chans_request_exec (n.a.m, a, "x", 1), GF_OK);
    CHECK_EQ (gf_chans_request_exec (n.a.m, a, "x", 1), GF_ERR_AGAIN);
    pump (&n);
    /* A peer that ignores the limit is disconnected.  */
    for (i = 0; i < 2 && rc == GF_OK; i++)
      {
        uint8_t m[64];
        gf_writer w;

        gf_writer_init (&w, m, sizeof m);
        gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
        gf_wr_u32 (&w, b);
        gf_wr_cstring (&w, "shell");
        gf_wr_bool (&w, 1);
        rc = inject (&n.b, m, w.len);
      }
    CHECK (rc != GF_OK);
    CHECK_EQ (n.b.disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
  }
  net_free (&n);
}

static void
test_malformed_requests (void)
{
  static const char *const bad[] = {
    "exec", "subsystem", "pty-req", "env", "window-change", "exit-status",
    "exit-signal", "break", "signal"
  };
  size_t i;

  for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      struct net n;
      uint8_t m[64];
      gf_writer w;
      uint32_t b;

      net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
      open_session (&n, 0, 0);
      b = n.b.last_open_id;
      gf_writer_init (&w, m, sizeof m);
      gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
      gf_wr_u32 (&w, b);
      gf_wr_cstring (&w, bad[i]);
      gf_wr_bool (&w, 0);		/* No arguments at all.  */
      CHECK (inject (&n.b, m, w.len) != GF_OK);
      CHECK_EQ (n.b.disconnect, GF_DISCONNECT_PROTOCOL_ERROR);
      CHECK_EQ (n.b.nreqs, 0);
      net_free (&n);
    }
  /* Arguments where there are none, and a NUL in a name.  */
  {
    struct net n;
    uint8_t m[64];
    gf_writer w;

    net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
    open_session (&n, 0, 0);
    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
    gf_wr_u32 (&w, n.b.last_open_id);
    gf_wr_cstring (&w, "shell");
    gf_wr_bool (&w, 0);
    gf_wr_u8 (&w, 1);
    CHECK (inject (&n.b, m, w.len) != GF_OK);
    net_free (&n);
    net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
    open_session (&n, 0, 0);
    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
    gf_wr_u32 (&w, n.b.last_open_id);
    gf_wr_cstring (&w, "exec");
    gf_wr_bool (&w, 0);
    gf_wr_string (&w, "a\0b", 3);
    CHECK (inject (&n.b, m, w.len) != GF_OK);
    net_free (&n);
  }
}

static void
test_global_requests (void)
{
  struct net n;
  uint8_t m[64];
  gf_writer w;

  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  CHECK_EQ (gf_chans_request_tcpip_forward (n.a.m, "0.0.0.0", 0), GF_OK);
  CHECK_EQ (gf_chans_request_tcpip_forward (n.a.m, "localhost", 8080), GF_OK);
  CHECK_EQ (gf_chans_request_cancel_tcpip_forward (n.a.m, "localhost", 8080),
            GF_OK);
  CHECK_EQ (gf_chans_request_no_more_sessions (n.a.m), GF_OK);
  pump (&n);
  CHECK_EQ (n.b.nglobals, 4);
  CHECK_EQ (n.b.globals[0].r.type, GF_GLOBAL_TCPIP_FORWARD);
  CHECK (strcmp (n.b.globals[0].addr, "0.0.0.0") == 0
         && n.b.globals[0].r.port == 0 && n.b.globals[0].r.want_reply);
  CHECK_EQ (n.b.globals[1].r.port, 8080);
  CHECK_EQ (n.b.globals[2].r.type, GF_GLOBAL_CANCEL_TCPIP_FORWARD);
  CHECK_EQ (n.b.globals[3].r.type, GF_GLOBAL_NO_MORE_SESSIONS);
  /* An unknown one in the middle, from the peer, is refused behind the
     owed answers.  */
  gf_writer_init (&w, m, sizeof m);
  gf_wr_u8 (&w, GF_MSG_GLOBAL_REQUEST);
  gf_wr_cstring (&w, "hostkeys-prove-00@openssh.com");
  gf_wr_bool (&w, 1);
  gf_wr_u32 (&w, 0);
  CHECK_EQ (inject (&n.b, m, w.len), GF_OK);
  CHECK_EQ (n.a.ngreplies, 0);
  CHECK_EQ (gf_chans_global_reply (n.b.m, 1, 40000), GF_OK);	/* Port 0: bound.  */
  CHECK_EQ (gf_chans_global_reply (n.b.m, 1, 0), GF_OK);
  CHECK_EQ (gf_chans_global_reply (n.b.m, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_global_reply (n.b.m, 1, 0), GF_OK);
  /* Four answers, and behind them the refusal of the unknown request
     (which A never made, so it is dropped here).  */
  {
    int i;

    for (i = 0; i < 4; i++)
      take_one (&n.a, 1);
  }
  CHECK_EQ (first_type (&n.a), GF_MSG_REQUEST_FAILURE);
  take_one (&n.a, 0);
  CHECK_EQ (n.a.qn, 0);
  CHECK_EQ (n.a.ngreplies, 4);
  CHECK (n.a.global_replies[0] && n.a.global_ports[0] == 40000);
  CHECK (n.a.global_replies[1] && n.a.global_ports[1] == 0);
  CHECK (!n.a.global_replies[2] && n.a.global_replies[3]);
  /* Nobody is owed any more.  */
  CHECK_EQ (gf_chans_global_reply (n.b.m, 1, 0), GF_ERR_STATE);
  CHECK_EQ (n.a.disconnect + n.b.disconnect, 0);
  net_free (&n);

  /* Port beyond 65535, a reply nobody asked for, a success with a port
     when none was wanted.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  gf_writer_init (&w, m, sizeof m);
  gf_wr_u8 (&w, GF_MSG_GLOBAL_REQUEST);
  gf_wr_cstring (&w, "tcpip-forward");
  gf_wr_bool (&w, 1);
  gf_wr_cstring (&w, "x");
  gf_wr_u32 (&w, 99999);
  CHECK (inject (&n.b, m, w.len) != GF_OK);
  net_free (&n);
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  CHECK_EQ (gf_chans_request_tcpip_forward (n.a.m, "localhost", 22), GF_OK);
  pump (&n);
  {
    uint8_t ok[8] = { GF_MSG_REQUEST_SUCCESS, 0, 0, 0, 5 };

    CHECK (inject (&n.a, ok, 5) != GF_OK);	/* No port was asked for.  */
  }
  net_free (&n);
}

static void
test_open_types_and_limits (void)
{
  struct net n;
  uint32_t id, id2, id3;
  uint8_t m[256];
  gf_writer w;

  /* direct-tcpip and forwarded-tcpip carry their addresses.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  CHECK_EQ (gf_chans_open_direct_tcpip (n.a.m, &id, "db.example.org", 5432,
                                        "10.0.0.7", 51000, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_open_forwarded_tcpip (n.a.m, &id2, "0.0.0.0", 8080,
                                           "198.51.100.9", 4444, 0, 0), GF_OK);
  pump (&n);
  CHECK_EQ (n.b.open_requests, 2);
  CHECK_EQ (n.a.confirmed, 2);
  CHECK_EQ (n.b.open.type, GF_CHAN_FORWARDED_TCPIP);
  CHECK (strcmp (n.b.host, "0.0.0.0") == 0 && n.b.open.port == 8080);
  CHECK (strcmp (n.b.orig, "198.51.100.9") == 0 && n.b.open.orig_port == 4444);
  CHECK_EQ (gf_chans_open_direct_tcpip (n.a.m, &id3, NULL, 1, "x", 1, 0, 0),
            GF_ERR_INVAL);
  net_free (&n);

  /* The application refuses, with a reason.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  n.b.auto_accept = 0;
  CHECK_EQ (gf_chans_open_session (n.a.m, &id, 0, 0), GF_OK);
  pump (&n);
  CHECK_EQ (n.b.open_requests, 1);
  CHECK_EQ (gf_chans_count (n.b.m), 1);		/* Pending: counts.  */
  CHECK_EQ (gf_chans_open_reject (n.b.m, n.b.last_open_id,
                                  GF_OPEN_ADMINISTRATIVELY_PROHIBITED, "no"),
            GF_OK);
  CHECK_EQ (gf_chans_open_reject (n.b.m, n.b.last_open_id, 1, "no"),
            GF_ERR_STATE);
  CHECK_EQ (gf_chans_count (n.b.m), 0);
  pump (&n);
  CHECK_EQ (n.a.failed, 1);
  CHECK_EQ (n.a.fail_reason, GF_OPEN_ADMINISTRATIVELY_PROHIBITED);
  CHECK_EQ (gf_chans_count (n.a.m), 0);
  /* Accept later, then again.  */
  CHECK_EQ (gf_chans_open_session (n.a.m, &id, 0, 0), GF_OK);
  pump (&n);
  CHECK_EQ (gf_chans_open_accept (n.b.m, n.b.last_open_id, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_open_accept (n.b.m, n.b.last_open_id, 0, 0), GF_ERR_STATE);
  pump (&n);
  CHECK_EQ (n.a.confirmed, 1);
  net_free (&n);

  /* A type we do not have, and X11, are refused by the library.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  {
    static const char *const types[] = { "x11", "auth-agent@openssh.com",
                                         "tun@openssh.com", "bogus" };
    size_t i;

    for (i = 0; i < 4; i++)
      {
        gf_writer_init (&w, m, sizeof m);
        gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
        gf_wr_cstring (&w, types[i]);
        gf_wr_u32 (&w, 5 + (uint32_t) i);
        gf_wr_u32 (&w, 1000);
        gf_wr_u32 (&w, 500);
        gf_wr_cstring (&w, "whatever the type wants");
        CHECK_EQ (inject (&n.b, m, w.len), GF_OK);
      }
    CHECK_EQ (n.b.open_requests, 0);
    CHECK_EQ (gf_chans_count (n.b.m), 0);
    CHECK_EQ (n.a.qn > 0, 1);
    /* Four refusals, each OPEN_FAILURE naming the peer's number.  */
    {
      size_t off = 0, count = 0;

      while (off < n.a.qn)
        {
          size_t l = (size_t) n.a.q[off] << 24 | n.a.q[off + 1] << 16
            | n.a.q[off + 2] << 8 | n.a.q[off + 3];

          CHECK_EQ (n.a.q[off + 4], GF_MSG_CHANNEL_OPEN_FAILURE);
          CHECK_EQ (n.a.q[off + 8], 5 + count);
          CHECK_EQ (n.a.q[off + 12], GF_OPEN_UNKNOWN_CHANNEL_TYPE);
          off += 4 + l;
          count++;
        }
      CHECK_EQ (count, 4);
    }
    n.a.qn = 0;
  }
  net_free (&n);

  /* The channel limit, and reuse of a number once it is free.  */
  {
    gf_chans_config c3 = cfg (3, 0, 0);

    net_new (&n, &c3, &c3);
  }
  {
    uint32_t ids[4];
    int i;

    for (i = 0; i < 3; i++)
      CHECK_EQ (gf_chans_open_session (n.a.m, &ids[i], 0, 0), GF_OK);
    CHECK_EQ (gf_chans_open_session (n.a.m, &ids[3], 0, 0), GF_ERR_AGAIN);
    pump (&n);
    CHECK_EQ (n.a.confirmed, 3);
    /* B is full too: a channel from B is refused for lack of room, which
       A sees as an open failure.  */
    {
      uint32_t bid;

      CHECK_EQ (gf_chans_open_session (n.b.m, &bid, 0, 0), GF_ERR_AGAIN);
    }
    CHECK_EQ (gf_chans_close (n.a.m, ids[1]), GF_OK);
    pump (&n);
    CHECK_EQ (gf_chans_count (n.a.m), 2);
    CHECK_EQ (gf_chans_open_session (n.a.m, &ids[3], 0, 0), GF_OK);
    CHECK_EQ (ids[3], ids[1]);			/* The number is reused.  */
    pump (&n);
    CHECK_EQ (n.a.confirmed, 4);
  }
  net_free (&n);

  /* The peer opens more than we allow: refused with RESOURCE_SHORTAGE.  */
  {
    gf_chans_config ca = cfg (0, 0, 0), cb = cfg (1, 0, 0);

    net_new (&n, &ca, &cb);
  }
  CHECK_EQ (gf_chans_open_session (n.a.m, &id, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_open_session (n.a.m, &id2, 0, 0), GF_OK);
  pump (&n);
  CHECK_EQ (n.a.confirmed, 1);
  CHECK_EQ (n.a.failed, 1);
  CHECK_EQ (n.a.fail_reason, GF_OPEN_RESOURCE_SHORTAGE);
  net_free (&n);
}

static void
test_streamlocal (void)
{
  struct net n;
  uint32_t id, id2, i;
  uint8_t m[GF_MAX_SOCKET_PATH + 256];
  gf_writer w;
  static char longpath[GF_MAX_SOCKET_PATH + 2];

  /* The two kinds of channel carry their paths; the request carries its.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  CHECK_EQ (gf_chans_open_direct_streamlocal (n.a.m, &id, "/run/app.sock", 0, 0), GF_OK);
  CHECK_EQ (gf_chans_open_forwarded_streamlocal (n.a.m, &id2, "/tmp/fwd.sock", 0, 0), GF_OK);
  CHECK_EQ (gf_chans_request_streamlocal_forward (n.a.m, "/tmp/listen.sock"), GF_OK);
  CHECK_EQ (gf_chans_request_cancel_streamlocal_forward (n.a.m, "/tmp/listen.sock"), GF_OK);
  pump (&n);
  CHECK_EQ (n.b.open_requests, 2);
  CHECK_EQ (n.a.confirmed, 2);
  CHECK_EQ (n.b.open.type, GF_CHAN_FORWARDED_STREAMLOCAL);
  CHECK (strcmp (n.b.path, "/tmp/fwd.sock") == 0);
  CHECK_EQ (n.b.open.host.len, 0);
  CHECK_EQ (n.b.nglobals, 2);
  CHECK_EQ (n.b.globals[0].r.type, GF_GLOBAL_STREAMLOCAL_FORWARD);
  CHECK (strcmp (n.b.globals[0].path, "/tmp/listen.sock") == 0 && n.b.globals[0].r.want_reply);
  CHECK_EQ (n.b.globals[1].r.type, GF_GLOBAL_CANCEL_STREAMLOCAL_FORWARD);
  CHECK_EQ (gf_chans_global_reply (n.b.m, 1, 0), GF_OK);
  CHECK_EQ (gf_chans_global_reply (n.b.m, 0, 0), GF_OK);
  pump (&n);
  CHECK_EQ (n.a.ngreplies, 2);
  CHECK (n.a.global_replies[0] && !n.a.global_replies[1]);
  CHECK_EQ (n.a.global_ports[0], 0);
  CHECK_EQ (n.a.disconnect + n.b.disconnect, 0);
  /* The first one's type, seen by looking at the first open again.  */
  net_free (&n);
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  n.b.auto_accept = 0;
  CHECK_EQ (gf_chans_open_direct_streamlocal (n.a.m, &id, "/run/app.sock", 0, 0), GF_OK);
  pump (&n);
  CHECK_EQ (n.b.open.type, GF_CHAN_DIRECT_STREAMLOCAL);
  CHECK (strcmp (n.b.path, "/run/app.sock") == 0);
  /* A refusal is an open failure like any other.  */
  CHECK_EQ (gf_chans_open_reject (n.b.m, n.b.last_open_id,
                                  GF_OPEN_ADMINISTRATIVELY_PROHIBITED, "no"), GF_OK);
  pump (&n);
  CHECK_EQ (n.a.failed, 1);
  net_free (&n);

  /* Arguments.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  memset (longpath, 'a', sizeof longpath);
  longpath[GF_MAX_SOCKET_PATH + 1] = '\0';
  CHECK_EQ (gf_chans_open_direct_streamlocal (n.a.m, &id, NULL, 0, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_open_direct_streamlocal (n.a.m, &id, "", 0, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_open_direct_streamlocal (n.a.m, &id, longpath, 0, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_open_direct_streamlocal (n.a.m, NULL, "/x", 0, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_open_forwarded_streamlocal (n.a.m, &id, "", 0, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_request_streamlocal_forward (n.a.m, NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_request_streamlocal_forward (n.a.m, ""), GF_ERR_INVAL);
  CHECK_EQ (gf_chans_request_cancel_streamlocal_forward (n.a.m, longpath), GF_ERR_INVAL);
  longpath[GF_MAX_SOCKET_PATH] = '\0';
  CHECK_EQ (gf_chans_open_direct_streamlocal (n.a.m, &id, longpath, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_request_streamlocal_forward (n.a.m, longpath), GF_OK);
  pump (&n);
  CHECK_EQ (n.b.open.path.len, GF_MAX_SOCKET_PATH);
  CHECK_EQ (n.b.nglobals, 1);
  net_free (&n);

  /* Malformed from the peer: each ends the connection.  */
  for (i = 0; i < 10; i++)
    {
      net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
      gf_writer_init (&w, m, sizeof m);
      switch (i)
        {
        case 0:		/* direct: no path at all.  */
        case 1:		/* direct: an empty path.  */
        case 2:		/* direct: a NUL in the path.  */
        case 3:		/* direct: the reserved fields missing.  */
        case 4:		/* direct: bytes after.  */
          gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
          gf_wr_cstring (&w, "direct-streamlocal@openssh.com");
          gf_wr_u32 (&w, 5);
          gf_wr_u32 (&w, 1000);
          gf_wr_u32 (&w, 500);
          if (i == 1)
            {
              gf_wr_cstring (&w, "");
              gf_wr_cstring (&w, "");
              gf_wr_u32 (&w, 0);
            }
          else if (i == 2)
            {
              gf_wr_string (&w, "a\0b", 3);
              gf_wr_cstring (&w, "");
              gf_wr_u32 (&w, 0);
            }
          else if (i == 3)
            gf_wr_cstring (&w, "/x");
          else if (i == 4)
            {
              gf_wr_cstring (&w, "/x");
              gf_wr_cstring (&w, "");
              gf_wr_u32 (&w, 0);
              gf_wr_u8 (&w, 0);
            }
          break;
        case 5:		/* forwarded: path alone.  */
          gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
          gf_wr_cstring (&w, "forwarded-streamlocal@openssh.com");
          gf_wr_u32 (&w, 5);
          gf_wr_u32 (&w, 1000);
          gf_wr_u32 (&w, 500);
          gf_wr_cstring (&w, "/x");
          break;
        case 6:		/* global: no path.  */
          gf_wr_u8 (&w, GF_MSG_GLOBAL_REQUEST);
          gf_wr_cstring (&w, "streamlocal-forward@openssh.com");
          gf_wr_bool (&w, 1);
          break;
        case 7:		/* global: empty path.  */
          gf_wr_u8 (&w, GF_MSG_GLOBAL_REQUEST);
          gf_wr_cstring (&w, "cancel-streamlocal-forward@openssh.com");
          gf_wr_bool (&w, 1);
          gf_wr_cstring (&w, "");
          break;
        case 8:		/* direct: a path too long.  */
          gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
          gf_wr_cstring (&w, "direct-streamlocal@openssh.com");
          gf_wr_u32 (&w, 5);
          gf_wr_u32 (&w, 1000);
          gf_wr_u32 (&w, 500);
          longpath[GF_MAX_SOCKET_PATH] = 'a';
          gf_wr_cstring (&w, longpath);
          longpath[GF_MAX_SOCKET_PATH] = '\0';
          gf_wr_cstring (&w, "");
          gf_wr_u32 (&w, 0);
          break;
        default:	/* global: a path too long.  */
          gf_wr_u8 (&w, GF_MSG_GLOBAL_REQUEST);
          gf_wr_cstring (&w, "streamlocal-forward@openssh.com");
          gf_wr_bool (&w, 1);
          longpath[GF_MAX_SOCKET_PATH] = 'a';
          gf_wr_cstring (&w, longpath);
          longpath[GF_MAX_SOCKET_PATH] = '\0';
          break;
        }
      CHECK_EQ (gf_wr_status (&w), GF_OK);
      if (inject (&n.b, m, w.len) == GF_OK)
        fprintf (stderr, "malformed streamlocal message %u was accepted\n", i);
      CHECK_EQ (n.b.open_requests, 0);
      CHECK_EQ (n.b.nglobals, 0);
      net_free (&n);
    }

  /* The path may be anything but empty or with a NUL: a space, dots,
     non-ASCII.  It is the application's to judge.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  gf_writer_init (&w, m, sizeof m);
  gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
  gf_wr_cstring (&w, "direct-streamlocal@openssh.com");
  gf_wr_u32 (&w, 5);
  gf_wr_u32 (&w, 1000);
  gf_wr_u32 (&w, 500);
  gf_wr_cstring (&w, "../x y/\xc3\xa9");
  gf_wr_cstring (&w, "anything reserved");
  gf_wr_u32 (&w, 77);
  CHECK_EQ (inject (&n.b, m, w.len), GF_OK);
  CHECK_EQ (n.b.open_requests, 1);
  CHECK (strcmp (n.b.path, "../x y/\xc3\xa9") == 0);
  net_free (&n);

  /* Nothing is listening for the callback: refused, not an offence.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  CHECK_EQ (gf_chans_request_streamlocal_forward (n.a.m, "/x"), GF_OK);
  pump (&n);
  CHECK_EQ (n.a.disconnect + n.b.disconnect, 0);
  net_free (&n);
}

static void
test_close_races (void)
{
  struct net n;
  uint32_t a, b, id;
  const uint8_t d[] = "late";

  /* Closing while the open is still in flight: the close waits for the
     confirmation, and the application never hears of the channel.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  CHECK_EQ (gf_chans_open_session (n.a.m, &id, 0, 0), GF_OK);
  CHECK_EQ (gf_chans_close (n.a.m, id), GF_OK);
  pump (&n);
  CHECK_EQ (n.a.confirmed, 0);
  CHECK_EQ (n.a.closed, 1);
  CHECK_EQ (n.b.closed, 1);
  CHECK_EQ (gf_chans_count (n.a.m), 0);
  net_free (&n);

  /* Data in flight when the other side closes: dropped without a callback,
     and not an error.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 0, 0);
  b = n.b.last_open_id;
  CHECK_EQ (gf_chans_send_data (n.a.m, a, d, 4), 4);	/* Queued for B.  */
  CHECK_EQ (gf_chans_close (n.b.m, b), GF_OK);		/* B lets go first.  */
  pump (&n);
  CHECK_EQ (n.b.rxn, 0);
  CHECK_EQ (n.a.disconnect + n.b.disconnect, 0);
  CHECK_EQ (n.a.closed + n.b.closed, 2);
  net_free (&n);

  /* Both close at once.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 0, 0);
  b = n.b.last_open_id;
  CHECK_EQ (gf_chans_close (n.a.m, a), GF_OK);
  CHECK_EQ (gf_chans_close (n.b.m, b), GF_OK);
  pump (&n);
  CHECK_EQ (n.a.closed + n.b.closed, 2);
  CHECK_EQ (n.a.disconnect + n.b.disconnect, 0);
  net_free (&n);

  /* Exit status after EOF, as a command's channel does, then close.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 0, 0);
  b = n.b.last_open_id;
  CHECK_EQ (gf_chans_send_data (n.b.m, b, d, 4), 4);
  CHECK_EQ (gf_chans_send_eof (n.b.m, b), GF_OK);
  CHECK_EQ (gf_chans_request_exit_status (n.b.m, b, 7), GF_OK);
  CHECK_EQ (gf_chans_close (n.b.m, b), GF_OK);
  pump (&n);
  CHECK_EQ (n.a.rxn, 4);
  CHECK_EQ (n.a.eofs, 1);
  CHECK_EQ (n.a.nreqs, 1);
  CHECK_EQ (n.a.reqs[0].status, 7);
  CHECK_EQ (n.a.closed, 1);
  CHECK_EQ (n.b.closed, 1);
  net_free (&n);
}

static void
test_send_failures (void)
{
  struct net n;
  uint32_t a;
  static uint8_t d[5000];
  long r;

  /* A transport that cannot take the data now: nothing is lost, the caller
     is told, and later it goes through.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 0, 0);
  n.a.again_send = 1;
  r = gf_chans_send_data (n.a.m, a, d, sizeof d);
  CHECK_EQ (r, GF_ERR_AGAIN);
  CHECK_EQ (gf_chans_writable (n.a.m, a), GF_CHAN_DEFAULT_WINDOW);
  n.a.again_send = 0;
  CHECK_EQ (n.a.writable_calls, 0);
  CHECK_EQ (gf_chans_resume (n.a.m), GF_OK);	/* After the transport's rekey.  */
  CHECK_EQ (n.a.writable_calls, 1);
  CHECK_EQ (gf_chans_resume (n.a.m), GF_OK);	/* Nothing blocked now.  */
  CHECK_EQ (n.a.writable_calls, 1);
  r = gf_chans_send_data (n.a.m, a, d, sizeof d);
  CHECK_EQ (r, (long) sizeof d);
  pump (&n);
  CHECK_EQ (n.b.rxn, sizeof d);
  net_free (&n);

  /* A fatal failure to send ends the connection.  */
  net_new (&n, &(gf_chans_config) { 0, 0, 0 }, &(gf_chans_config) { 0, 0, 0 });
  a = open_session (&n, 0, 0);
  n.a.fail_send = 1;
  r = gf_chans_send_data (n.a.m, a, d, 10);
  CHECK_EQ (r, GF_ERR_HANDLER);
  CHECK_EQ (n.a.disconnect, GF_DISCONNECT_BY_APPLICATION);
  CHECK_EQ (gf_chans_send_data (n.a.m, a, d, 10), GF_ERR_CLOSED);
  net_free (&n);
}

int
main (void)
{
  gf_crypto_init ();
  test_open_data_close ();
  test_flow_control ();
  test_window_stall ();
  test_violations ();
  test_requests ();
  test_malformed_requests ();
  test_global_requests ();
  test_open_types_and_limits ();
  test_streamlocal ();
  test_close_races ();
  test_send_failures ();
  TST_DONE ();
}
