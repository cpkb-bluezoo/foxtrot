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

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/conn.h>
#include <foxtrot/chan.h>

#define DEFAULT_MAX_CHANNELS 64
#define DEFAULT_MAX_REQUESTS 16
#define MAX_QUEUE 64			/* Bits of the reply masks.  */
#define MAX_HOST 255
#define MAX_ENV_NAME 256
#define MAX_ENV_VALUE 4096
#define MAX_TERM 128
#define MAX_MODES 4096
#define MAX_WINDOW 0xffffffffu

enum cstate
{
  CS_OPENING_OUT,		/* We asked; waiting for the peer.  */
  CS_OPENING_IN,		/* The peer asked; the application decides.  */
  CS_OPEN
};

/* Replies to requests the peer made are owed in order.  A request we
   refuse ourselves is answered at once if nothing earlier is waiting,
   otherwise behind the earlier ones; QMASK marks those entries.  */
struct replyq
{
  unsigned n;			/* Entries waiting.  */
  uint64_t automatic;		/* Bit i: entry i (0 is oldest) is ours.  */
};

struct chan
{
  uint32_t id, remote;
  enum cstate state;
  enum gf_chan_type type;
  uint32_t lwin_initial, lwin, lmax;	/* What we grant the peer.  */
  uint64_t rwin;			/* What the peer grants us.  */
  uint32_t rmax;
  uint64_t unconsumed, credit;
  int sent_eof, recv_eof, sent_close, recv_close;
  int close_when_open, blocked;
  struct replyq in;
  unsigned pending_out;		/* Our requests awaiting a reply.  */
};

struct gf_chans
{
  gf_chans_config cfg;
  gf_chans_events ev;
  struct chan **tab;
  size_t ntab, count;
  uint32_t next;
  struct replyq gin;		/* Global requests the peer made.  */
  unsigned gout;		/* Ours awaiting a reply.  */
  uint64_t gout_wants_port;	/* Bit i: the i-th may return a port.  */
  uint8_t *scratch;
  size_t scratch_cap;
  int dead;
};

/* ------------------------------------------------------------------ */
/* Plumbing                                                           */
/* ------------------------------------------------------------------ */

int
gf_chans_new (gf_chans **out, const gf_chans_config *config,
              const gf_chans_events *events)
{
  gf_chans *m;

  if (out == NULL || config == NULL || events == NULL || events->send == NULL
      || events->disconnect == NULL)
    return GF_ERR_INVAL;
  m = calloc (1, sizeof *m);
  if (m == NULL)
    return GF_ERR_NOMEM;
  m->cfg = *config;
  if (m->cfg.max_channels == 0)
    m->cfg.max_channels = DEFAULT_MAX_CHANNELS;
  if (m->cfg.max_requests == 0)
    m->cfg.max_requests = DEFAULT_MAX_REQUESTS;
  if (m->cfg.max_requests > MAX_QUEUE)
    m->cfg.max_requests = MAX_QUEUE;
  m->ev = *events;
  m->ntab = m->cfg.max_channels;
  m->tab = calloc (m->ntab, sizeof *m->tab);
  m->scratch_cap = GF_MAX_PAYLOAD + 64;
  m->scratch = malloc (m->scratch_cap);
  if (m->tab == NULL || m->scratch == NULL)
    {
      free (m->tab);
      free (m->scratch);
      free (m);
      return GF_ERR_NOMEM;
    }
  *out = m;
  return GF_OK;
}

void
gf_chans_free (gf_chans *m)
{
  size_t i;

  if (m == NULL)
    return;
  for (i = 0; i < m->ntab; i++)
    free (m->tab[i]);
  free (m->tab);
  free (m->scratch);
  free (m);
}

size_t
gf_chans_count (const gf_chans *m)
{
  return m->count;
}

static struct chan *
find (const gf_chans *m, uint32_t id)
{
  return id < m->ntab ? m->tab[id] : NULL;
}

static struct chan *
find_open (const gf_chans *m, uint32_t id)
{
  struct chan *c = find (m, id);

  return c != NULL && c->state == CS_OPEN ? c : NULL;
}

/* The connection must end.  */
static int
die (gf_chans *m, uint32_t reason, int status)
{
  if (!m->dead)
    {
      m->dead = 1;
      m->ev.disconnect (m->ev.user, reason);
    }
  return status;
}

static int
protocol_error (gf_chans *m)
{
  return die (m, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
}

static int
encoding_error (gf_chans *m)
{
  return die (m, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
}

/* Send a message built by the caller.  Control messages must not be lost,
   so anything but success ends the connection.  */
static int
send_msg (gf_chans *m, const uint8_t *p, size_t n)
{
  if (m->ev.send (m->ev.user, p, n) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

static int
send_chan_msg (gf_chans *m, uint8_t type, uint32_t remote)
{
  uint8_t b[5];
  gf_writer w;

  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, type);
  gf_wr_u32 (&w, remote);
  return send_msg (m, b, w.len);
}

static void
free_chan (gf_chans *m, struct chan *c)
{
  m->tab[c->id] = NULL;
  m->count--;
  free (c);
}

static struct chan *
alloc_chan (gf_chans *m)
{
  size_t i;
  struct chan *c;

  if (m->count >= m->ntab)
    return NULL;
  for (i = 0; i < m->ntab; i++)
    {
      uint32_t id = (uint32_t) ((m->next + i) % m->ntab);

      if (m->tab[id] == NULL)
        {
          c = calloc (1, sizeof *c);
          if (c == NULL)
            return NULL;
          c->id = id;
          m->tab[id] = c;
          m->count++;
          m->next = (id + 1) % (uint32_t) m->ntab;
          return c;
        }
    }
  return NULL;
}

/* A channel that has been closed both ways is released.  */
static int
maybe_release (gf_chans *m, struct chan *c)
{
  uint32_t id = c->id;
  int r = 0;

  if (!(c->sent_close && c->recv_close))
    return GF_OK;
  free_chan (m, c);
  if (m->ev.closed)
    r = m->ev.closed (m->ev.user, id);
  return r ? die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER) : GF_OK;
}

static uint32_t
effective_window (uint32_t w)
{
  return w ? w : GF_CHAN_DEFAULT_WINDOW;
}

static uint32_t
effective_packet (uint32_t p)
{
  if (p == 0)
    return GF_CHAN_DEFAULT_PACKET;
  return p > GF_CHAN_MAX_PACKET ? GF_CHAN_MAX_PACKET : p;
}

/* ------------------------------------------------------------------ */
/* Reply queues                                                       */
/* ------------------------------------------------------------------ */

/* Send the refusals at the head of Q that we made ourselves.  */
typedef int (*refuse_fn) (gf_chans *m, void *ctx);

static int
flush_auto (gf_chans *m, struct replyq *q, refuse_fn refuse, void *ctx)
{
  while (q->n > 0 && (q->automatic & 1))
    {
      int r;

      q->automatic >>= 1;
      q->n--;
      r = refuse (m, ctx);
      if (r != GF_OK)
        return r;
    }
  return GF_OK;
}

/* A request with a reply owed.  AUTO: we refuse it ourselves.  Returns 1
   in *NOW if the refusal can go out at once.  */
static int
enqueue (gf_chans *m, struct replyq *q, int automatic, int *now)
{
  *now = 0;
  if (automatic && q->n == 0)
    {
      *now = 1;
      return GF_OK;
    }
  if (q->n >= m->cfg.max_requests)
    return protocol_error (m);
  if (automatic)
    q->automatic |= UINT64_C (1) << q->n;
  q->n++;
  return GF_OK;
}

static int
refuse_chan (gf_chans *m, void *ctx)
{
  struct chan *c = ctx;

  return send_chan_msg (m, GF_MSG_CHANNEL_FAILURE, c->remote);
}

static int
refuse_global (gf_chans *m, void *ctx)
{
  uint8_t t = GF_MSG_REQUEST_FAILURE;

  (void) ctx;
  return send_msg (m, &t, 1);
}

/* ------------------------------------------------------------------ */
/* Opening                                                            */
/* ------------------------------------------------------------------ */

#define MAX_OPEN_FAILURE_TEXT 1024

static int
send_open_failure (gf_chans *m, uint32_t remote, uint32_t reason,
                   const char *text)
{
  uint8_t b[MAX_OPEN_FAILURE_TEXT + 64];
  size_t n = strlen (text);
  gf_writer w;

  /* The text is the application's: a long one is cut, never sent as a
     message with a hole in it.  */
  if (n > MAX_OPEN_FAILURE_TEXT)
    n = MAX_OPEN_FAILURE_TEXT;
  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN_FAILURE);
  gf_wr_u32 (&w, remote);
  gf_wr_u32 (&w, reason);
  gf_wr_string (&w, text, n);
  gf_wr_cstring (&w, "");
  if (gf_wr_status (&w) != GF_OK)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_BUFSIZE);
  return send_msg (m, b, w.len);
}

static int
handle_open (gf_chans *m, gf_reader *rd)
{
  gf_slice type;
  uint32_t sender, window, maxpkt, i;
  gf_chan_open open;
  struct chan *c;
  enum gf_chan_type t;

  memset (&open, 0, sizeof open);
  if (gf_rd_text (rd, &type) != GF_OK || gf_rd_u32 (rd, &sender) != GF_OK
      || gf_rd_u32 (rd, &window) != GF_OK || gf_rd_u32 (rd, &maxpkt) != GF_OK)
    return encoding_error (m);
  if (gf_slice_equals (type, "session"))
    t = GF_CHAN_SESSION;
  else if (gf_slice_equals (type, "direct-tcpip"))
    t = GF_CHAN_DIRECT_TCPIP;
  else if (gf_slice_equals (type, "forwarded-tcpip"))
    t = GF_CHAN_FORWARDED_TCPIP;
  else if (gf_slice_equals (type, "direct-streamlocal@openssh.com"))
    t = GF_CHAN_DIRECT_STREAMLOCAL;
  else if (gf_slice_equals (type, "forwarded-streamlocal@openssh.com"))
    t = GF_CHAN_FORWARDED_STREAMLOCAL;
  else
    return send_open_failure (m, sender, GF_OPEN_UNKNOWN_CHANNEL_TYPE,
                              "unknown channel type");
  if (t == GF_CHAN_DIRECT_TCPIP || t == GF_CHAN_FORWARDED_TCPIP)
    {
      uint32_t port, oport;

      if (gf_rd_text (rd, &open.host) != GF_OK
          || gf_rd_u32 (rd, &port) != GF_OK
          || gf_rd_text (rd, &open.orig_host) != GF_OK
          || gf_rd_u32 (rd, &oport) != GF_OK || port > 65535 || oport > 65535
          || open.host.len > MAX_HOST || open.orig_host.len > MAX_HOST)
        return encoding_error (m);
      open.port = (uint16_t) port;
      open.orig_port = (uint16_t) oport;
    }
  else if (t == GF_CHAN_DIRECT_STREAMLOCAL || t == GF_CHAN_FORWARDED_STREAMLOCAL)
    {
      gf_slice reserved;
      uint32_t reserved32;

      /* The path, and what is reserved for the future, which is ignored.  */
      if (gf_rd_text (rd, &open.path) != GF_OK || open.path.len == 0
          || open.path.len > GF_MAX_SOCKET_PATH
          || gf_rd_string (rd, &reserved) != GF_OK
          || (t == GF_CHAN_DIRECT_STREAMLOCAL
              && gf_rd_u32 (rd, &reserved32) != GF_OK))
        return encoding_error (m);
    }
  if (gf_rd_finish (rd) != GF_OK || maxpkt == 0)
    return encoding_error (m);

  /* The peer numbers its channels uniquely.  */
  for (i = 0; i < m->ntab; i++)
    if (m->tab[i] != NULL && m->tab[i]->state != CS_OPENING_OUT
        && m->tab[i]->remote == sender)
      return protocol_error (m);

  c = alloc_chan (m);
  if (c == NULL || m->ev.open_request == NULL)
    {
      if (c != NULL)
        free_chan (m, c);
      return send_open_failure (m, sender, c == NULL
                                ? GF_OPEN_RESOURCE_SHORTAGE
                                : GF_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                c == NULL ? "too many channels"
                                          : "channels not allowed");
    }
  c->state = CS_OPENING_IN;
  c->type = t;
  c->remote = sender;
  c->rwin = window;
  c->rmax = maxpkt;
  open.id = c->id;
  open.type = t;
  open.window = window;
  open.max_packet = maxpkt;
  if (m->ev.open_request (m->ev.user, &open) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

int
gf_chans_open_accept (gf_chans *m, uint32_t id, uint32_t window,
                      uint32_t max_packet)
{
  struct chan *c = find (m, id);
  uint8_t b[32];
  gf_writer w;

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (c == NULL || c->state != CS_OPENING_IN)
    return GF_ERR_STATE;
  c->lwin_initial = c->lwin = effective_window (window);
  c->lmax = effective_packet (max_packet);
  c->state = CS_OPEN;
  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN_CONFIRMATION);
  gf_wr_u32 (&w, c->remote);
  gf_wr_u32 (&w, c->id);
  gf_wr_u32 (&w, c->lwin);
  gf_wr_u32 (&w, c->lmax);
  return send_msg (m, b, w.len);
}

int
gf_chans_open_reject (gf_chans *m, uint32_t id, uint32_t reason,
                      const char *text)
{
  struct chan *c = find (m, id);
  uint32_t remote;

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (c == NULL || c->state != CS_OPENING_IN || text == NULL)
    return GF_ERR_STATE;
  remote = c->remote;
  free_chan (m, c);
  return send_open_failure (m, remote, reason, text);
}

static int
open_out (gf_chans *m, uint32_t *id, const char *type, const char *host,
          uint16_t port, const char *orig_host, uint16_t orig_port,
          uint32_t window, uint32_t max_packet, enum gf_chan_type t)
{
  struct chan *c;
  uint8_t b[1100];
  gf_writer w;

  if (m == NULL || id == NULL)
    return GF_ERR_INVAL;
  if (m->dead)
    return GF_ERR_CLOSED;
  if (host != NULL && (strlen (host) > MAX_HOST || strlen (orig_host) > MAX_HOST))
    return GF_ERR_RANGE;
  c = alloc_chan (m);
  if (c == NULL)
    return GF_ERR_AGAIN;
  c->state = CS_OPENING_OUT;
  c->type = t;
  c->lwin_initial = c->lwin = effective_window (window);
  c->lmax = effective_packet (max_packet);
  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
  gf_wr_cstring (&w, type);
  gf_wr_u32 (&w, c->id);
  gf_wr_u32 (&w, c->lwin);
  gf_wr_u32 (&w, c->lmax);
  if (host != NULL)
    {
      gf_wr_cstring (&w, host);
      gf_wr_u32 (&w, port);
      gf_wr_cstring (&w, orig_host);
      gf_wr_u32 (&w, orig_port);
    }
  *id = c->id;
  return send_msg (m, b, w.len);
}

static int
open_streamlocal (gf_chans *m, uint32_t *id, const char *type,
                  const char *path, uint32_t window, uint32_t max_packet,
                  enum gf_chan_type t)
{
  struct chan *c;
  uint8_t b[GF_MAX_SOCKET_PATH + 128];
  gf_writer w;

  if (m == NULL || id == NULL || path == NULL || path[0] == '\0'
      || strlen (path) > GF_MAX_SOCKET_PATH)
    return GF_ERR_INVAL;
  if (m->dead)
    return GF_ERR_CLOSED;
  c = alloc_chan (m);
  if (c == NULL)
    return GF_ERR_AGAIN;
  c->state = CS_OPENING_OUT;
  c->type = t;
  c->lwin_initial = c->lwin = effective_window (window);
  c->lmax = effective_packet (max_packet);
  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, GF_MSG_CHANNEL_OPEN);
  gf_wr_cstring (&w, type);
  gf_wr_u32 (&w, c->id);
  gf_wr_u32 (&w, c->lwin);
  gf_wr_u32 (&w, c->lmax);
  gf_wr_cstring (&w, path);
  gf_wr_cstring (&w, "");		/* Reserved.  */
  if (t == GF_CHAN_DIRECT_STREAMLOCAL)
    gf_wr_u32 (&w, 0);
  *id = c->id;
  return send_msg (m, b, w.len);
}

int
gf_chans_open_direct_streamlocal (gf_chans *m, uint32_t *id, const char *path,
                                  uint32_t window, uint32_t max_packet)
{
  return open_streamlocal (m, id, "direct-streamlocal@openssh.com", path,
                           window, max_packet, GF_CHAN_DIRECT_STREAMLOCAL);
}

int
gf_chans_open_forwarded_streamlocal (gf_chans *m, uint32_t *id,
                                     const char *path, uint32_t window,
                                     uint32_t max_packet)
{
  return open_streamlocal (m, id, "forwarded-streamlocal@openssh.com", path,
                           window, max_packet, GF_CHAN_FORWARDED_STREAMLOCAL);
}

int
gf_chans_open_session (gf_chans *m, uint32_t *id, uint32_t window,
                       uint32_t max_packet)
{
  return open_out (m, id, "session", NULL, 0, NULL, 0, window, max_packet,
                   GF_CHAN_SESSION);
}

int
gf_chans_open_direct_tcpip (gf_chans *m, uint32_t *id, const char *host,
                            uint16_t port, const char *orig_host,
                            uint16_t orig_port, uint32_t window,
                            uint32_t max_packet)
{
  if (host == NULL || orig_host == NULL)
    return GF_ERR_INVAL;
  return open_out (m, id, "direct-tcpip", host, port, orig_host, orig_port,
                   window, max_packet, GF_CHAN_DIRECT_TCPIP);
}

int
gf_chans_open_forwarded_tcpip (gf_chans *m, uint32_t *id, const char *host,
                               uint16_t port, const char *orig_host,
                               uint16_t orig_port, uint32_t window,
                               uint32_t max_packet)
{
  if (host == NULL || orig_host == NULL)
    return GF_ERR_INVAL;
  return open_out (m, id, "forwarded-tcpip", host, port, orig_host, orig_port,
                   window, max_packet, GF_CHAN_FORWARDED_TCPIP);
}

static int
handle_open_confirmation (gf_chans *m, gf_reader *rd)
{
  uint32_t recipient, sender, window, maxpkt;
  struct chan *c;
  uint32_t i;

  if (gf_rd_u32 (rd, &recipient) != GF_OK || gf_rd_u32 (rd, &sender) != GF_OK
      || gf_rd_u32 (rd, &window) != GF_OK || gf_rd_u32 (rd, &maxpkt) != GF_OK
      || gf_rd_finish (rd) != GF_OK)
    return encoding_error (m);
  c = find (m, recipient);
  if (c == NULL || c->state != CS_OPENING_OUT || maxpkt == 0)
    return protocol_error (m);
  for (i = 0; i < m->ntab; i++)
    if (m->tab[i] != NULL && m->tab[i] != c && m->tab[i]->state != CS_OPENING_OUT
        && m->tab[i]->remote == sender)
      return protocol_error (m);
  c->remote = sender;
  c->rwin = window;
  c->rmax = maxpkt;
  c->state = CS_OPEN;
  if (c->close_when_open)
    {
      c->sent_close = 1;
      return send_chan_msg (m, GF_MSG_CHANNEL_CLOSE, c->remote);
    }
  if (m->ev.open_confirmed
      && m->ev.open_confirmed (m->ev.user, c->id) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

static int
handle_open_failure (gf_chans *m, gf_reader *rd)
{
  uint32_t recipient, reason;
  gf_slice text, lang;
  struct chan *c;
  uint32_t id;
  int quiet;

  if (gf_rd_u32 (rd, &recipient) != GF_OK || gf_rd_u32 (rd, &reason) != GF_OK
      || gf_rd_utf8 (rd, &text) != GF_OK || gf_rd_string (rd, &lang) != GF_OK
      || gf_rd_finish (rd) != GF_OK)
    return encoding_error (m);
  c = find (m, recipient);
  if (c == NULL || c->state != CS_OPENING_OUT)
    return protocol_error (m);
  id = c->id;
  quiet = c->close_when_open;
  free_chan (m, c);
  if (!quiet && m->ev.open_failed
      && m->ev.open_failed (m->ev.user, id, reason, text) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Data and windows                                                   */
/* ------------------------------------------------------------------ */

static int
handle_window_adjust (gf_chans *m, gf_reader *rd)
{
  uint32_t recipient, n;
  struct chan *c;

  if (gf_rd_u32 (rd, &recipient) != GF_OK || gf_rd_u32 (rd, &n) != GF_OK
      || gf_rd_finish (rd) != GF_OK)
    return encoding_error (m);
  c = find_open (m, recipient);
  if (c == NULL || c->recv_close)
    return protocol_error (m);
  if (c->rwin + n > MAX_WINDOW)
    return protocol_error (m);
  c->rwin += n;
  if (c->blocked && c->rwin > 0 && !c->sent_close && !c->sent_eof)
    {
      c->blocked = 0;
      if (m->ev.writable && m->ev.writable (m->ev.user, c->id) != 0)
        return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
    }
  return GF_OK;
}

/* Data (TYPE 0) or extended data of TYPE on channel C.  */
static int
handle_data (gf_chans *m, gf_reader *rd, int extended)
{
  uint32_t recipient, xtype = 0;
  gf_slice data;
  struct chan *c;
  int r = 0;

  if (gf_rd_u32 (rd, &recipient) != GF_OK
      || (extended && gf_rd_u32 (rd, &xtype) != GF_OK)
      || gf_rd_string (rd, &data) != GF_OK || gf_rd_finish (rd) != GF_OK)
    return encoding_error (m);
  c = find_open (m, recipient);
  if (c == NULL || c->recv_close || c->recv_eof)
    return protocol_error (m);
  if (extended && xtype != GF_EXTENDED_DATA_STDERR)
    return protocol_error (m);
  if (data.len > c->lmax || data.len > c->lwin)
    return protocol_error (m);
  c->lwin -= (uint32_t) data.len;
  if (c->sent_close)
    {
      /* The peer has not heard our CLOSE yet: drop it, and say nothing
         to an application that has let go.  */
      return GF_OK;
    }
  c->unconsumed += data.len;
  if (extended && m->ev.extended_data)
    r = m->ev.extended_data (m->ev.user, c->id, xtype, data.data, data.len);
  else if (!extended && m->ev.data)
    r = m->ev.data (m->ev.user, c->id, data.data, data.len);
  else
    return gf_chans_consumed (m, c->id, data.len);
  if (r != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  if (m->cfg.auto_window && find (m, recipient) == c)
    return gf_chans_consumed (m, c->id, (size_t) c->unconsumed);
  return GF_OK;
}

int
gf_chans_consumed (gf_chans *m, uint32_t id, size_t n)
{
  struct chan *c = find_open (m, id);
  uint8_t b[16];
  gf_writer w;
  uint64_t threshold;

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (c == NULL)
    return GF_ERR_STATE;
  if (n > c->unconsumed)
    return GF_ERR_INVAL;
  c->unconsumed -= n;
  c->credit += n;
  threshold = c->lwin_initial / 2;
  if (threshold == 0)
    threshold = 1;
  if (c->credit < threshold || c->recv_close || c->sent_close)
    return GF_OK;
  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, GF_MSG_CHANNEL_WINDOW_ADJUST);
  gf_wr_u32 (&w, c->remote);
  gf_wr_u32 (&w, (uint32_t) c->credit);
  c->lwin += (uint32_t) c->credit;
  c->credit = 0;
  return send_msg (m, b, w.len);
}

static long
send_some (gf_chans *m, uint32_t id, int extended, uint32_t xtype,
           const uint8_t *data, size_t len)
{
  struct chan *c = find_open (m, id);
  size_t done = 0, chunk_max;

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (c == NULL || c->sent_eof || c->sent_close || c->recv_close)
    return GF_ERR_STATE;
  if (data == NULL && len > 0)
    return GF_ERR_INVAL;
  /* What a transport payload holds after the message's header, which for
     extended data is four bytes longer.  */
  chunk_max = extended ? GF_CHAN_MAX_PACKET - 4 : GF_CHAN_MAX_PACKET;
  if (c->rmax < chunk_max)
    chunk_max = c->rmax;
  while (done < len && c->rwin > 0)
    {
      size_t n = len - done;
      gf_writer w;
      int r;

      if (n > chunk_max)
        n = chunk_max;
      if (n > c->rwin)
        n = (size_t) c->rwin;
      gf_writer_init (&w, m->scratch, m->scratch_cap);
      gf_wr_u8 (&w, extended ? GF_MSG_CHANNEL_EXTENDED_DATA
                             : GF_MSG_CHANNEL_DATA);
      gf_wr_u32 (&w, c->remote);
      if (extended)
        gf_wr_u32 (&w, xtype);
      gf_wr_string (&w, data + done, n);
      r = m->ev.send (m->ev.user, m->scratch, w.len);
      if (r == GF_ERR_AGAIN)
        {
          c->blocked = 1;
          return done ? (long) done : GF_ERR_AGAIN;
        }
      if (r != 0)
        return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
      c->rwin -= n;
      done += n;
    }
  if (done < len)
    c->blocked = 1;
  return (long) done;
}

long
gf_chans_send_data (gf_chans *m, uint32_t id, const uint8_t *data, size_t len)
{
  return send_some (m, id, 0, 0, data, len);
}

long
gf_chans_send_extended (gf_chans *m, uint32_t id, uint32_t type,
                        const uint8_t *data, size_t len)
{
  if (type != GF_EXTENDED_DATA_STDERR)
    return GF_ERR_INVAL;
  return send_some (m, id, 1, type, data, len);
}

int
gf_chans_resume (gf_chans *m)
{
  size_t i;

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  for (i = 0; i < m->ntab; i++)
    {
      struct chan *c = m->tab[i];

      if (c != NULL && c->state == CS_OPEN && c->blocked && c->rwin > 0
          && !c->sent_close && !c->sent_eof)
        {
          c->blocked = 0;
          if (m->ev.writable && m->ev.writable (m->ev.user, c->id) != 0)
            return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
          if (m->dead)
            return GF_ERR_CLOSED;
        }
    }
  return GF_OK;
}

size_t
gf_chans_writable (const gf_chans *m, uint32_t id)
{
  const struct chan *c = find_open (m, id);

  if (c == NULL || c->sent_eof || c->sent_close)
    return 0;
  return c->rwin > SIZE_MAX ? SIZE_MAX : (size_t) c->rwin;
}

uint32_t
gf_chans_remote_max_packet (const gf_chans *m, uint32_t id)
{
  const struct chan *c = find_open (m, id);

  return c ? c->rmax : 0;
}

static int
handle_eof (gf_chans *m, gf_reader *rd)
{
  uint32_t recipient;
  struct chan *c;

  if (gf_rd_u32 (rd, &recipient) != GF_OK || gf_rd_finish (rd) != GF_OK)
    return encoding_error (m);
  c = find_open (m, recipient);
  if (c == NULL || c->recv_close || c->recv_eof)
    return protocol_error (m);
  c->recv_eof = 1;
  if (!c->sent_close && m->ev.eof && m->ev.eof (m->ev.user, c->id) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

int
gf_chans_send_eof (gf_chans *m, uint32_t id)
{
  struct chan *c = find_open (m, id);

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (c == NULL || c->sent_eof || c->sent_close)
    return GF_ERR_STATE;
  c->sent_eof = 1;
  return send_chan_msg (m, GF_MSG_CHANNEL_EOF, c->remote);
}

static int
handle_close (gf_chans *m, gf_reader *rd)
{
  uint32_t recipient;
  struct chan *c;
  int r;

  if (gf_rd_u32 (rd, &recipient) != GF_OK || gf_rd_finish (rd) != GF_OK)
    return encoding_error (m);
  c = find_open (m, recipient);
  if (c == NULL || c->recv_close)
    return protocol_error (m);
  c->recv_close = 1;
  if (!c->sent_close)
    {
      c->sent_close = 1;
      r = send_chan_msg (m, GF_MSG_CHANNEL_CLOSE, c->remote);
      if (r != GF_OK)
        return r;
    }
  return maybe_release (m, c);
}

int
gf_chans_close (gf_chans *m, uint32_t id)
{
  struct chan *c = find (m, id);

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (c == NULL || c->state == CS_OPENING_IN)
    return GF_ERR_STATE;
  if (c->state == CS_OPENING_OUT)
    {
      c->close_when_open = 1;
      return GF_OK;
    }
  if (c->sent_close)
    return GF_OK;
  c->sent_close = 1;
  {
    int r = send_chan_msg (m, GF_MSG_CHANNEL_CLOSE, c->remote);

    if (r != GF_OK)
      return r;
  }
  return maybe_release (m, c);
}

/* ------------------------------------------------------------------ */
/* Requests on channels                                               */
/* ------------------------------------------------------------------ */

static int
handle_request (gf_chans *m, gf_reader *rd)
{
  uint32_t recipient;
  gf_slice type;
  int want;
  struct chan *c;
  gf_chan_request rq;
  int known = 1, now = 0, r;

  if (gf_rd_u32 (rd, &recipient) != GF_OK || gf_rd_text (rd, &type) != GF_OK
      || gf_rd_bool (rd, &want) != GF_OK)
    return encoding_error (m);
  c = find_open (m, recipient);
  if (c == NULL || c->recv_close)
    return protocol_error (m);

  memset (&rq, 0, sizeof rq);
  rq.id = c->id;
  rq.want_reply = want;
  if (gf_slice_equals (type, "exec"))
    {
      rq.type = GF_REQ_EXEC;
      if (gf_rd_text (rd, &rq.command) != GF_OK || gf_rd_finish (rd) != GF_OK)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "shell"))
    {
      rq.type = GF_REQ_SHELL;
      if (gf_rd_finish (rd) != GF_OK)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "subsystem"))
    {
      rq.type = GF_REQ_SUBSYSTEM;
      if (gf_rd_text (rd, &rq.command) != GF_OK || gf_rd_finish (rd) != GF_OK
          || rq.command.len == 0 || rq.command.len > MAX_HOST)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "pty-req"))
    {
      rq.type = GF_REQ_PTY;
      if (gf_rd_text (rd, &rq.name) != GF_OK || gf_rd_u32 (rd, &rq.cols) != GF_OK
          || gf_rd_u32 (rd, &rq.rows) != GF_OK
          || gf_rd_u32 (rd, &rq.width) != GF_OK
          || gf_rd_u32 (rd, &rq.height) != GF_OK
          || gf_rd_string (rd, &rq.modes) != GF_OK
          || gf_rd_finish (rd) != GF_OK || rq.name.len > MAX_TERM
          || rq.modes.len > MAX_MODES)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "env"))
    {
      rq.type = GF_REQ_ENV;
      if (gf_rd_text (rd, &rq.name) != GF_OK || gf_rd_text (rd, &rq.value) != GF_OK
          || gf_rd_finish (rd) != GF_OK || rq.name.len > MAX_ENV_NAME
          || rq.value.len > MAX_ENV_VALUE)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "window-change"))
    {
      rq.type = GF_REQ_WINDOW_CHANGE;
      if (gf_rd_u32 (rd, &rq.cols) != GF_OK || gf_rd_u32 (rd, &rq.rows) != GF_OK
          || gf_rd_u32 (rd, &rq.width) != GF_OK
          || gf_rd_u32 (rd, &rq.height) != GF_OK || gf_rd_finish (rd) != GF_OK)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "signal"))
    {
      rq.type = GF_REQ_SIGNAL;
      if (gf_rd_text (rd, &rq.name) != GF_OK || gf_rd_finish (rd) != GF_OK
          || rq.name.len > MAX_TERM)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "exit-status"))
    {
      rq.type = GF_REQ_EXIT_STATUS;
      if (gf_rd_u32 (rd, &rq.status) != GF_OK || gf_rd_finish (rd) != GF_OK)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "exit-signal"))
    {
      gf_slice lang;

      rq.type = GF_REQ_EXIT_SIGNAL;
      if (gf_rd_text (rd, &rq.name) != GF_OK
          || gf_rd_bool (rd, &rq.core_dumped) != GF_OK
          || gf_rd_utf8 (rd, &rq.message) != GF_OK
          || gf_rd_string (rd, &lang) != GF_OK || gf_rd_finish (rd) != GF_OK
          || rq.name.len > MAX_TERM)
        return encoding_error (m);
    }
  else if (gf_slice_equals (type, "break"))
    {
      rq.type = GF_REQ_BREAK;
      if (gf_rd_u32 (rd, &rq.ms) != GF_OK || gf_rd_finish (rd) != GF_OK)
        return encoding_error (m);
    }
  else
    known = 0;		/* x11-req, auth-agent-req@openssh.com, keepalive...  */

  /* Nothing is done for a channel we have closed; the peer does not know
     yet.  */
  if (c->sent_close)
    return GF_OK;
  if (!known || m->ev.request == NULL)
    {
      if (!want)
        return GF_OK;
      r = enqueue (m, &c->in, 1, &now);
      if (r != GF_OK)
        return r;
      return now ? refuse_chan (m, c) : GF_OK;
    }
  if (want)
    {
      r = enqueue (m, &c->in, 0, &now);
      if (r != GF_OK)
        return r;
    }
  if (m->ev.request (m->ev.user, &rq) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

int
gf_chans_reply (gf_chans *m, uint32_t id, int success)
{
  struct chan *c = find_open (m, id);
  int r;

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (c == NULL || c->in.n == 0 || (c->in.automatic & 1))
    return GF_ERR_STATE;
  c->in.automatic >>= 1;
  c->in.n--;
  if (c->sent_close)
    return GF_OK;
  r = send_chan_msg (m, success ? GF_MSG_CHANNEL_SUCCESS
                               : GF_MSG_CHANNEL_FAILURE, c->remote);
  if (r != GF_OK)
    return r;
  return flush_auto (m, &c->in, refuse_chan, c);
}

static int
handle_chan_reply (gf_chans *m, gf_reader *rd, int success)
{
  uint32_t recipient;
  struct chan *c;

  if (gf_rd_u32 (rd, &recipient) != GF_OK || gf_rd_finish (rd) != GF_OK)
    return encoding_error (m);
  c = find_open (m, recipient);
  if (c == NULL || c->recv_close || c->pending_out == 0)
    return protocol_error (m);
  c->pending_out--;
  if (!c->sent_close && m->ev.request_reply
      && m->ev.request_reply (m->ev.user, c->id, success) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

/* Send a request with the type TYPE on channel ID; BODY (LEN bytes) is the
   rest of the message.  */
static int
send_request (gf_chans *m, uint32_t id, const char *type, int want,
              const uint8_t *body, size_t len)
{
  struct chan *c = find_open (m, id);
  gf_writer w;

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (c == NULL || c->sent_close || c->recv_close)
    return GF_ERR_STATE;
  if (want && c->pending_out >= m->cfg.max_requests)
    return GF_ERR_AGAIN;
  if (len + strlen (type) + 32 > m->scratch_cap)
    return GF_ERR_RANGE;
  gf_writer_init (&w, m->scratch, m->scratch_cap);
  gf_wr_u8 (&w, GF_MSG_CHANNEL_REQUEST);
  gf_wr_u32 (&w, c->remote);
  gf_wr_cstring (&w, type);
  gf_wr_bool (&w, want);
  gf_wr_bytes (&w, body, len);
  if (want)
    c->pending_out++;
  return send_msg (m, m->scratch, w.len);
}

/* A request body of strings and numbers, built in B.  */
#define BODY_START(b, w) gf_writer_init (&(w), (b), sizeof (b))

int
gf_chans_request_exec (gf_chans *m, uint32_t id, const char *command, int want)
{
  uint8_t *b;
  gf_writer w;
  size_t n;
  int r;

  if (command == NULL)
    return GF_ERR_INVAL;
  n = strlen (command);
  if (n > GF_MAX_PAYLOAD - 100)
    return GF_ERR_RANGE;
  b = malloc (n + 8);
  if (b == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, b, n + 8);
  gf_wr_string (&w, command, n);
  r = send_request (m, id, "exec", want, b, w.len);
  free (b);
  return r;
}

int
gf_chans_request_shell (gf_chans *m, uint32_t id, int want)
{
  return send_request (m, id, "shell", want, NULL, 0);
}

int
gf_chans_request_subsystem (gf_chans *m, uint32_t id, const char *name,
                            int want)
{
  uint8_t b[300];
  gf_writer w;

  if (name == NULL || strlen (name) > MAX_HOST)
    return GF_ERR_INVAL;
  BODY_START (b, w);
  gf_wr_cstring (&w, name);
  return send_request (m, id, "subsystem", want, b, w.len);
}

int
gf_chans_request_pty (gf_chans *m, uint32_t id, const char *term,
                      uint32_t cols, uint32_t rows, uint32_t width,
                      uint32_t height, const uint8_t *modes, size_t modes_len,
                      int want)
{
  uint8_t b[MAX_TERM + MAX_MODES + 64];
  gf_writer w;
  static const uint8_t no_modes[] = { 0 };	/* TTY_OP_END.  */

  if (term == NULL || strlen (term) > MAX_TERM || modes_len > MAX_MODES)
    return GF_ERR_INVAL;
  if (modes == NULL)
    {
      modes = no_modes;
      modes_len = 1;
    }
  BODY_START (b, w);
  gf_wr_cstring (&w, term);
  gf_wr_u32 (&w, cols);
  gf_wr_u32 (&w, rows);
  gf_wr_u32 (&w, width);
  gf_wr_u32 (&w, height);
  gf_wr_string (&w, modes, modes_len);
  return send_request (m, id, "pty-req", want, b, w.len);
}

int
gf_chans_request_env (gf_chans *m, uint32_t id, const char *name,
                      const char *value, int want)
{
  uint8_t b[MAX_ENV_NAME + MAX_ENV_VALUE + 16];
  gf_writer w;

  if (name == NULL || value == NULL || strlen (name) > MAX_ENV_NAME
      || strlen (value) > MAX_ENV_VALUE)
    return GF_ERR_INVAL;
  BODY_START (b, w);
  gf_wr_cstring (&w, name);
  gf_wr_cstring (&w, value);
  return send_request (m, id, "env", want, b, w.len);
}

int
gf_chans_request_window_change (gf_chans *m, uint32_t id, uint32_t cols,
                                uint32_t rows, uint32_t width, uint32_t height)
{
  uint8_t b[16];
  gf_writer w;

  BODY_START (b, w);
  gf_wr_u32 (&w, cols);
  gf_wr_u32 (&w, rows);
  gf_wr_u32 (&w, width);
  gf_wr_u32 (&w, height);
  return send_request (m, id, "window-change", 0, b, w.len);
}

int
gf_chans_request_signal (gf_chans *m, uint32_t id, const char *name)
{
  uint8_t b[MAX_TERM + 8];
  gf_writer w;

  if (name == NULL || strlen (name) > MAX_TERM)
    return GF_ERR_INVAL;
  BODY_START (b, w);
  gf_wr_cstring (&w, name);
  return send_request (m, id, "signal", 0, b, w.len);
}

int
gf_chans_request_exit_status (gf_chans *m, uint32_t id, uint32_t status)
{
  uint8_t b[4];
  gf_writer w;

  BODY_START (b, w);
  gf_wr_u32 (&w, status);
  return send_request (m, id, "exit-status", 0, b, w.len);
}

int
gf_chans_request_exit_signal (gf_chans *m, uint32_t id, const char *name,
                              int core_dumped, const char *message)
{
  uint8_t b[MAX_TERM + 1024 + 16];
  gf_writer w;

  if (name == NULL || message == NULL || strlen (name) > MAX_TERM
      || strlen (message) > 1024
      || !gf_utf8_valid ((const uint8_t *) message, strlen (message)))
    return GF_ERR_INVAL;
  BODY_START (b, w);
  gf_wr_cstring (&w, name);
  gf_wr_bool (&w, core_dumped);
  gf_wr_cstring (&w, message);
  gf_wr_cstring (&w, "");
  return send_request (m, id, "exit-signal", 0, b, w.len);
}

/* ------------------------------------------------------------------ */
/* Global requests                                                    */
/* ------------------------------------------------------------------ */

static int
handle_global_request (gf_chans *m, gf_reader *rd)
{
  gf_slice name;
  int want, known = 1, now = 0, r;
  gf_global_request rq;

  if (gf_rd_text (rd, &name) != GF_OK || gf_rd_bool (rd, &want) != GF_OK)
    return encoding_error (m);
  memset (&rq, 0, sizeof rq);
  rq.want_reply = want;
  if (gf_slice_equals (name, "tcpip-forward")
      || gf_slice_equals (name, "cancel-tcpip-forward"))
    {
      rq.type = gf_slice_equals (name, "tcpip-forward")
        ? GF_GLOBAL_TCPIP_FORWARD : GF_GLOBAL_CANCEL_TCPIP_FORWARD;
      if (gf_rd_text (rd, &rq.addr) != GF_OK || gf_rd_u32 (rd, &rq.port) != GF_OK
          || gf_rd_finish (rd) != GF_OK || rq.port > 65535
          || rq.addr.len > MAX_HOST)
        return encoding_error (m);
    }
  else if (gf_slice_equals (name, "streamlocal-forward@openssh.com")
           || gf_slice_equals (name, "cancel-streamlocal-forward@openssh.com"))
    {
      rq.type = gf_slice_equals (name, "streamlocal-forward@openssh.com")
        ? GF_GLOBAL_STREAMLOCAL_FORWARD : GF_GLOBAL_CANCEL_STREAMLOCAL_FORWARD;
      if (gf_rd_text (rd, &rq.path) != GF_OK || gf_rd_finish (rd) != GF_OK
          || rq.path.len == 0 || rq.path.len > GF_MAX_SOCKET_PATH)
        return encoding_error (m);
    }
  else if (gf_slice_equals (name, "no-more-sessions@openssh.com"))
    {
      rq.type = GF_GLOBAL_NO_MORE_SESSIONS;
      if (gf_rd_finish (rd) != GF_OK)
        return encoding_error (m);
    }
  else
    known = 0;
  if (!known || m->ev.global_request == NULL)
    {
      if (!want)
        return GF_OK;
      r = enqueue (m, &m->gin, 1, &now);
      if (r != GF_OK)
        return r;
      return now ? refuse_global (m, NULL) : GF_OK;
    }
  if (want)
    {
      r = enqueue (m, &m->gin, 0, &now);
      if (r != GF_OK)
        return r;
    }
  if (m->ev.global_request (m->ev.user, &rq) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

int
gf_chans_global_reply (gf_chans *m, int success, uint32_t port)
{
  uint8_t b[8];
  gf_writer w;
  int r;

  if (m == NULL || m->dead)
    return GF_ERR_CLOSED;
  if (m->gin.n == 0 || (m->gin.automatic & 1))
    return GF_ERR_STATE;
  m->gin.automatic >>= 1;
  m->gin.n--;
  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, success ? GF_MSG_REQUEST_SUCCESS : GF_MSG_REQUEST_FAILURE);
  if (success && port != 0)
    gf_wr_u32 (&w, port);
  r = send_msg (m, b, w.len);
  if (r != GF_OK)
    return r;
  return flush_auto (m, &m->gin, refuse_global, NULL);
}

static int
send_global (gf_chans *m, const char *name, const char *addr, uint32_t port,
             int with_addr, int wants_port)
{
  uint8_t b[400];
  gf_writer w;

  if (m == NULL || m->dead)
    return m ? GF_ERR_CLOSED : GF_ERR_INVAL;
  if (m->gout >= m->cfg.max_requests)
    return GF_ERR_AGAIN;
  if (with_addr && (addr == NULL || strlen (addr) > MAX_HOST || port > 65535))
    return GF_ERR_INVAL;
  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, GF_MSG_GLOBAL_REQUEST);
  gf_wr_cstring (&w, name);
  gf_wr_bool (&w, 1);
  if (with_addr)
    {
      gf_wr_cstring (&w, addr);
      gf_wr_u32 (&w, port);
    }
  if (wants_port)
    m->gout_wants_port |= UINT64_C (1) << m->gout;
  else
    m->gout_wants_port &= ~(UINT64_C (1) << m->gout);
  m->gout++;
  return send_msg (m, b, w.len);
}

int
gf_chans_request_tcpip_forward (gf_chans *m, const char *addr, uint32_t port)
{
  return send_global (m, "tcpip-forward", addr, port, 1, port == 0);
}

int
gf_chans_request_cancel_tcpip_forward (gf_chans *m, const char *addr,
                                       uint32_t port)
{
  return send_global (m, "cancel-tcpip-forward", addr, port, 1, 0);
}

static int
send_global_path (gf_chans *m, const char *name, const char *path)
{
  uint8_t b[GF_MAX_SOCKET_PATH + 128];
  gf_writer w;

  if (m == NULL || m->dead)
    return m ? GF_ERR_CLOSED : GF_ERR_INVAL;
  if (path == NULL || path[0] == '\0' || strlen (path) > GF_MAX_SOCKET_PATH)
    return GF_ERR_INVAL;
  if (m->gout >= m->cfg.max_requests)
    return GF_ERR_AGAIN;
  gf_writer_init (&w, b, sizeof b);
  gf_wr_u8 (&w, GF_MSG_GLOBAL_REQUEST);
  gf_wr_cstring (&w, name);
  gf_wr_bool (&w, 1);
  gf_wr_cstring (&w, path);
  m->gout_wants_port &= ~(UINT64_C (1) << m->gout);
  m->gout++;
  return send_msg (m, b, w.len);
}

int
gf_chans_request_streamlocal_forward (gf_chans *m, const char *path)
{
  return send_global_path (m, "streamlocal-forward@openssh.com", path);
}

int
gf_chans_request_cancel_streamlocal_forward (gf_chans *m, const char *path)
{
  return send_global_path (m, "cancel-streamlocal-forward@openssh.com", path);
}

int
gf_chans_request_no_more_sessions (gf_chans *m)
{
  return send_global (m, "no-more-sessions@openssh.com", NULL, 0, 0, 0);
}

static int
handle_global_reply (gf_chans *m, gf_reader *rd, int success)
{
  uint32_t port = 0;

  if (m->gout == 0)
    return protocol_error (m);
  if (success && (m->gout_wants_port & 1))
    {
      if (gf_rd_u32 (rd, &port) != GF_OK)
        return encoding_error (m);
    }
  if (gf_rd_finish (rd) != GF_OK)
    return encoding_error (m);
  m->gout--;
  m->gout_wants_port >>= 1;
  if (m->ev.global_reply && m->ev.global_reply (m->ev.user, success, port) != 0)
    return die (m, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER);
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Input                                                              */
/* ------------------------------------------------------------------ */

int
gf_chans_input (gf_chans *m, const uint8_t *payload, size_t len)
{
  gf_reader rd;

  if (m == NULL || payload == NULL || len == 0)
    return GF_ERR_INVAL;
  if (m->dead)
    return GF_ERR_CLOSED;
  gf_reader_init (&rd, payload + 1, len - 1);
  switch (payload[0])
    {
    case GF_MSG_GLOBAL_REQUEST:		return handle_global_request (m, &rd);
    case GF_MSG_REQUEST_SUCCESS:	return handle_global_reply (m, &rd, 1);
    case GF_MSG_REQUEST_FAILURE:	return handle_global_reply (m, &rd, 0);
    case GF_MSG_CHANNEL_OPEN:		return handle_open (m, &rd);
    case GF_MSG_CHANNEL_OPEN_CONFIRMATION:
      return handle_open_confirmation (m, &rd);
    case GF_MSG_CHANNEL_OPEN_FAILURE:	return handle_open_failure (m, &rd);
    case GF_MSG_CHANNEL_WINDOW_ADJUST:	return handle_window_adjust (m, &rd);
    case GF_MSG_CHANNEL_DATA:		return handle_data (m, &rd, 0);
    case GF_MSG_CHANNEL_EXTENDED_DATA:	return handle_data (m, &rd, 1);
    case GF_MSG_CHANNEL_EOF:		return handle_eof (m, &rd);
    case GF_MSG_CHANNEL_CLOSE:		return handle_close (m, &rd);
    case GF_MSG_CHANNEL_REQUEST:	return handle_request (m, &rd);
    case GF_MSG_CHANNEL_SUCCESS:	return handle_chan_reply (m, &rd, 1);
    case GF_MSG_CHANNEL_FAILURE:	return handle_chan_reply (m, &rd, 0);
    default:				return protocol_error (m);
    }
}
