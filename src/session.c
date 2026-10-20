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
#include <foxtrot/session.h>

#define DEFAULT_MAX_CHANNELS 64

enum bind_kind
{
  B_NONE,
  B_SFTP_SERVER,
  B_SFTP_CLIENT
};

/* What the session knows about one channel number.  */
struct binding
{
  struct gf_session *s;
  uint32_t id;
  int used;
  enum gf_chan_type type;	/* A channel the peer asked to open.  */
  int pending_open;		/* Waiting for the application's answer.  */
  int counted;			/* Counts toward max_sessions.  */
  enum bind_kind kind;
  gf_sftp_server *ss;
  gf_sftp_server_events sev;
  gf_sftp_client *sc;
  gf_sftp_client_events cev;
};

struct gf_session
{
  int server;
  gf_session_config cfg;
  gf_session_events ev;
  gf_conn *c;
  gf_auth_server *as;
  gf_auth_client *ac;
  gf_chans *ch;
  enum gf_session_phase phase;
  uint64_t now;
  int no_more_sessions;
  unsigned nsessions;
  char *user;
  struct binding *bind;
  size_t nbind;
};

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void
end (gf_session *s, uint32_t reason)
{
  if (!gf_conn_is_closed (s->c))
    gf_conn_disconnect (s->c, s->now, reason, NULL);
}

static struct binding *
binding_of (gf_session *s, uint32_t id)
{
  return id < s->nbind && s->bind[id].used ? &s->bind[id] : NULL;
}

static struct binding *
binding_new (gf_session *s, uint32_t id)
{
  struct binding *b;

  if (id >= s->nbind)
    return NULL;
  b = &s->bind[id];
  memset (b, 0, sizeof *b);
  b->s = s;
  b->id = id;
  b->used = 1;
  return b;
}

static void
binding_release (gf_session *s, struct binding *b)
{
  if (b->counted && s->nsessions > 0)
    s->nsessions--;
  gf_sftp_server_free (b->ss);
  gf_sftp_client_free (b->sc);
  memset (b, 0, sizeof *b);
}

/* ------------------------------------------------------------------ */
/* Authentication: server                                             */
/* ------------------------------------------------------------------ */

static int
as_send (void *user, const uint8_t *p, size_t n)
{
  gf_session *s = user;

  return gf_conn_send (s->c, s->now, p, n) != GF_OK;
}

static int
as_request (void *user, const gf_auth_request *req)
{
  gf_session *s = user;

  return s->ev.auth_request (s->ev.user, req);
}

static int
as_kbd_response (void *user, const gf_slice *r, size_t n)
{
  gf_session *s = user;

  return s->ev.auth_kbdint_response
    ? s->ev.auth_kbdint_response (s->ev.user, r, n) : 1;
}

static uint64_t
as_unix_time (void *user)
{
  gf_session *s = user;

  return s->ev.unix_time (s->ev.user);
}

static int
as_authenticated (void *user, gf_slice username)
{
  gf_session *s = user;

  free (s->user);
  s->user = malloc (username.len + 1);
  if (s->user == NULL)
    return 1;
  memcpy (s->user, username.data, username.len);
  s->user[username.len] = '\0';
  s->phase = GF_PHASE_READY;
  return s->ev.authenticated ? s->ev.authenticated (s->ev.user, username) : 0;
}

static int
as_disconnect (void *user, uint32_t reason)
{
  end (user, reason);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Authentication: client                                             */
/* ------------------------------------------------------------------ */

static void
ac_banner (void *user, gf_slice text)
{
  gf_session *s = user;

  if (s->ev.auth_banner)
    s->ev.auth_banner (s->ev.user, text);
}

static int
ac_kbdint (void *user, gf_slice name, gf_slice instr, size_t n,
           const gf_slice *prompts, const int *echo)
{
  gf_session *s = user;

  return s->ev.auth_kbdint (s->ev.user, name, instr, n, prompts, echo);
}

static int
ac_authenticated (void *user)
{
  gf_session *s = user;
  gf_slice none = { NULL, 0 };

  s->phase = GF_PHASE_READY;
  return s->ev.authenticated ? s->ev.authenticated (s->ev.user, none) : 0;
}

static int
ac_failed (void *user)
{
  gf_session *s = user;

  if (s->ev.auth_failed)
    s->ev.auth_failed (s->ev.user);
  end (s, GF_DISCONNECT_NO_MORE_AUTH_METHODS);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Channels                                                           */
/* ------------------------------------------------------------------ */

static int
ch_send (void *user, const uint8_t *p, size_t n)
{
  gf_session *s = user;

  return gf_conn_send (s->c, s->now, p, n);
}

static int
ch_disconnect (void *user, uint32_t reason)
{
  end (user, reason);
  return 0;
}

static int
ch_open_request (void *user, const gf_chan_open *o)
{
  gf_session *s = user;
  struct binding *b;

  if (o->type == GF_CHAN_SESSION)
    {
      if (s->no_more_sessions)
        return gf_chans_open_reject (s->ch, o->id,
                                     GF_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                     "no more sessions") != GF_OK;
      if (s->cfg.max_sessions && s->nsessions >= s->cfg.max_sessions)
        return gf_chans_open_reject (s->ch, o->id, GF_OPEN_RESOURCE_SHORTAGE,
                                     "too many sessions") != GF_OK;
    }
  b = binding_new (s, o->id);
  if (b == NULL || s->ev.channel_open == NULL)
    {
      if (b != NULL)
        memset (b, 0, sizeof *b);
      return gf_chans_open_reject (s->ch, o->id,
                                   GF_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                   "not allowed") != GF_OK;
    }
  b->type = o->type;
  b->pending_open = 1;
  return s->ev.channel_open (s->ev.user, o);
}

int
gf_session_channel_accept (gf_session *s, uint32_t id, uint32_t window,
                           uint32_t max_packet)
{
  struct binding *b;

  if (s == NULL)
    return GF_ERR_INVAL;
  b = binding_of (s, id);
  if (b == NULL || !b->pending_open)
    return GF_ERR_STATE;
  if (b->type == GF_CHAN_SESSION)
    {
      if (s->no_more_sessions
          || (s->cfg.max_sessions && s->nsessions >= s->cfg.max_sessions))
        {
          b->pending_open = 0;
          memset (b, 0, sizeof *b);
          gf_chans_open_reject (s->ch, id, GF_OPEN_RESOURCE_SHORTAGE,
                                "too many sessions");
          return GF_ERR_AGAIN;
        }
      s->nsessions++;
      b->counted = 1;
    }
  b->pending_open = 0;
  return gf_chans_open_accept (s->ch, id, window, max_packet);
}

int
gf_session_channel_reject (gf_session *s, uint32_t id, uint32_t reason,
                           const char *text)
{
  struct binding *b;

  if (s == NULL)
    return GF_ERR_INVAL;
  b = binding_of (s, id);
  if (b == NULL || !b->pending_open)
    return GF_ERR_STATE;
  memset (b, 0, sizeof *b);
  return gf_chans_open_reject (s->ch, id, reason, text);
}

static int
ch_open_confirmed (void *user, uint32_t id)
{
  gf_session *s = user;

  return s->ev.channel_confirmed ? s->ev.channel_confirmed (s->ev.user, id) : 0;
}

static int
ch_open_failed (void *user, uint32_t id, uint32_t reason, gf_slice text)
{
  gf_session *s = user;

  return s->ev.channel_failed
    ? s->ev.channel_failed (s->ev.user, id, reason, text) : 0;
}

static int
ch_data (void *user, uint32_t id, const uint8_t *d, size_t n)
{
  gf_session *s = user;
  struct binding *b = binding_of (s, id);

  if (b != NULL && b->kind == B_SFTP_SERVER)
    {
      if (gf_sftp_server_input (b->ss, d, n) != GF_OK)
        gf_chans_close (s->ch, id);
    }
  else if (b != NULL && b->kind == B_SFTP_CLIENT)
    {
      if (gf_sftp_client_input (b->sc, d, n) != GF_OK)
        gf_chans_close (s->ch, id);
    }
  else if (s->ev.channel_data)
    return s->ev.channel_data (s->ev.user, id, d, n);
  /* Dealt with (or nobody wants it): the peer may send more.  */
  gf_chans_consumed (s->ch, id, n);
  return 0;
}

static int
ch_ext (void *user, uint32_t id, uint32_t type, const uint8_t *d, size_t n)
{
  gf_session *s = user;

  if (s->ev.channel_extended_data)
    return s->ev.channel_extended_data (s->ev.user, id, type, d, n);
  gf_chans_consumed (s->ch, id, n);
  return 0;
}

static int
ch_eof (void *user, uint32_t id)
{
  gf_session *s = user;
  struct binding *b = binding_of (s, id);

  if (b != NULL && b->kind != B_NONE)
    {
      /* The peer will say no more: the SFTP session is over.  */
      gf_chans_close (s->ch, id);
      return 0;
    }
  return s->ev.channel_eof ? s->ev.channel_eof (s->ev.user, id) : 0;
}

static int
ch_writable (void *user, uint32_t id)
{
  gf_session *s = user;
  struct binding *b = binding_of (s, id);

  /* A failure here has already been reported by the SFTP object, which
     closes the channel.  */
  if (b != NULL && b->kind == B_SFTP_SERVER)
    {
      (void) gf_sftp_server_writable (b->ss);
      return 0;
    }
  if (b != NULL && b->kind == B_SFTP_CLIENT)
    {
      (void) gf_sftp_client_writable (b->sc);
      return 0;
    }
  return s->ev.channel_writable ? s->ev.channel_writable (s->ev.user, id) : 0;
}

static int
ch_request (void *user, const gf_chan_request *q)
{
  gf_session *s = user;

  if (s->ev.channel_request)
    return s->ev.channel_request (s->ev.user, q);
  /* Nobody to decide: refuse what asks for an answer.  */
  return q->want_reply ? gf_chans_reply (s->ch, q->id, 0) != GF_OK : 0;
}

static int
ch_request_reply (void *user, uint32_t id, int ok)
{
  gf_session *s = user;

  return s->ev.channel_request_reply
    ? s->ev.channel_request_reply (s->ev.user, id, ok) : 0;
}

static int
ch_closed (void *user, uint32_t id)
{
  gf_session *s = user;
  struct binding *b = binding_of (s, id);

  if (b != NULL)
    binding_release (s, b);
  return s->ev.channel_closed ? s->ev.channel_closed (s->ev.user, id) : 0;
}

static int
ch_global_request (void *user, const gf_global_request *r)
{
  gf_session *s = user;

  if (r->type == GF_GLOBAL_NO_MORE_SESSIONS)
    {
      s->no_more_sessions = 1;
      return r->want_reply ? gf_chans_global_reply (s->ch, 1, 0) != GF_OK : 0;
    }
  if (s->ev.global_request)
    return s->ev.global_request (s->ev.user, r);
  return r->want_reply ? gf_chans_global_reply (s->ch, 0, 0) != GF_OK : 0;
}

static int
ch_global_reply (void *user, int ok, uint32_t port)
{
  gf_session *s = user;

  return s->ev.global_reply ? s->ev.global_reply (s->ev.user, ok, port) : 0;
}

/* ------------------------------------------------------------------ */
/* Transport                                                          */
/* ------------------------------------------------------------------ */

static int
cn_write (void *user, const uint8_t *d, size_t n)
{
  gf_session *s = user;

  return s->ev.write (s->ev.user, d, n);
}

static int
cn_host_key (void *user, const gf_key *key)
{
  gf_session *s = user;

  return s->ev.host_key ? s->ev.host_key (s->ev.user, key) : 1;
}

static int
cn_established (void *user, const gf_conn_info *info)
{
  gf_session *s = user;
  size_t bl;
  const uint8_t *blob = gf_key_blob (info->host_key, &bl);

  s->phase = GF_PHASE_AUTH;
  if (s->server)
    {
      if (gf_auth_server_start (s->as, s->now, info->session_id,
                                info->session_id_len, blob, bl) != GF_OK)
        return 1;
    }
  else if (gf_conn_request_service (s->c, s->now, "ssh-userauth") != GF_OK)
    return 1;
  return s->ev.established ? s->ev.established (s->ev.user, info) : 0;
}

static int
cn_rekeyed (void *user, const gf_conn_info *info)
{
  gf_session *s = user;

  /* Sends held back by the exchange may go now.  */
  if (s->phase == GF_PHASE_READY && gf_chans_resume (s->ch) != GF_OK)
    return 1;
  return s->ev.rekeyed ? s->ev.rekeyed (s->ev.user, info) : 0;
}

static int
cn_service_accepted (void *user, gf_slice name)
{
  gf_session *s = user;
  const gf_conn_info *info = gf_conn_get_info (s->c);
  size_t bl;
  const uint8_t *blob;

  (void) name;
  if (s->server || info == NULL)
    return 0;
  blob = gf_key_blob (info->host_key, &bl);
  return gf_auth_client_start (s->ac, s->now, info->session_id,
                               info->session_id_len, blob, bl) != GF_OK;
}

static int
cn_extension (void *user, gf_slice name, gf_slice value)
{
  gf_session *s = user;

  if (!s->server)
    gf_auth_client_extension (s->ac, name, value);
  return 0;
}

static void
cn_debug (void *user, int always, gf_slice text)
{
  gf_session *s = user;

  if (s->ev.debug)
    s->ev.debug (s->ev.user, always, text);
}

static void
cn_unimplemented (void *user, uint32_t seq)
{
  gf_session *s = user;

  if (s->ev.unimplemented)
    s->ev.unimplemented (s->ev.user, seq);
}

static int
cn_message (void *user, const uint8_t *p, size_t n)
{
  gf_session *s = user;
  int r;

  if (p[0] >= 50 && p[0] <= 79)
    {
      if (s->phase == GF_PHASE_HANDSHAKE)
        return 1;
      if (s->server)
        {
          r = gf_auth_server_input (s->as, s->now, p, n);
          /* Errors have already asked for the connection to end.  */
          if (r != GF_OK && !gf_auth_server_is_done (s->as))
            end (s, GF_DISCONNECT_PROTOCOL_ERROR);
        }
      else
        {
          r = gf_auth_client_input (s->ac, s->now, p, n);
          if (r != GF_OK && r != GF_ERR_AUTH)
            end (s, GF_DISCONNECT_PROTOCOL_ERROR);
        }
      return 0;
    }
  if (p[0] >= 80 && p[0] <= 100)
    {
      if (s->phase != GF_PHASE_READY)
        {
          end (s, GF_DISCONNECT_PROTOCOL_ERROR);
          return 0;
        }
      r = gf_chans_input (s->ch, p, n);
      if (r != GF_OK)
        end (s, GF_DISCONNECT_PROTOCOL_ERROR);
      return 0;
    }
  gf_conn_reject_message (s->c);
  return 0;
}

static void
cn_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  gf_session *s = user;

  s->phase = GF_PHASE_CLOSED;
  if (s->ev.closed)
    s->ev.closed (s->ev.user, error, reason, text);
}

/* ------------------------------------------------------------------ */
/* Construction                                                       */
/* ------------------------------------------------------------------ */

static int
session_new (gf_session **out, int server, const gf_session_config *config,
             const gf_session_events *events)
{
  gf_session *s;
  gf_conn_events ce;
  gf_conn_config cc;
  gf_chans_events che;
  int r;

  if (out == NULL || config == NULL || events == NULL || events->write == NULL)
    return GF_ERR_INVAL;
  if (server && events->auth_request == NULL)
    return GF_ERR_INVAL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return GF_ERR_NOMEM;
  s->server = server;
  s->cfg = *config;
  s->ev = *events;
  s->phase = GF_PHASE_HANDSHAKE;
  s->nbind = config->chans.max_channels ? config->chans.max_channels
                                        : DEFAULT_MAX_CHANNELS;
  s->bind = calloc (s->nbind, sizeof *s->bind);
  if (s->bind == NULL)
    {
      free (s);
      return GF_ERR_NOMEM;
    }

  memset (&ce, 0, sizeof ce);
  ce.user = s;
  ce.write = cn_write;
  ce.host_key = cn_host_key;
  ce.established = cn_established;
  ce.rekeyed = cn_rekeyed;
  ce.service_accepted = cn_service_accepted;
  ce.message = cn_message;
  ce.extension = cn_extension;
  ce.debug = cn_debug;
  ce.unimplemented = cn_unimplemented;
  ce.closed = cn_closed;
  cc = config->conn;
  if (server)
    cc.announce_hostbound = config->server_auth.hostbound;
  r = server ? gf_conn_server_new (&s->c, &cc, &ce)
             : gf_conn_client_new (&s->c, &cc, &ce);

  if (r == GF_OK)
    {
      memset (&che, 0, sizeof che);
      che.user = s;
      che.send = ch_send;
      che.disconnect = ch_disconnect;
      che.open_request = ch_open_request;
      che.open_confirmed = ch_open_confirmed;
      che.open_failed = ch_open_failed;
      che.data = ch_data;
      che.extended_data = ch_ext;
      che.eof = ch_eof;
      che.writable = ch_writable;
      che.request = ch_request;
      che.request_reply = ch_request_reply;
      che.global_request = ch_global_request;
      che.global_reply = ch_global_reply;
      che.closed = ch_closed;
      r = gf_chans_new (&s->ch, &config->chans, &che);
    }
  if (r == GF_OK && server)
    {
      gf_auth_server_events ae;

      memset (&ae, 0, sizeof ae);
      ae.user = s;
      ae.send = as_send;
      ae.request = as_request;
      ae.kbdint_response = events->auth_kbdint_response ? as_kbd_response : NULL;
      ae.authenticated = as_authenticated;
      ae.disconnect = as_disconnect;
      ae.unix_time = events->unix_time ? as_unix_time : NULL;
      r = gf_auth_server_new (&s->as, &config->server_auth, &ae);
    }
  else if (r == GF_OK)
    {
      gf_auth_client_events ae;

      memset (&ae, 0, sizeof ae);
      ae.user = s;
      ae.send = as_send;
      ae.banner = ac_banner;
      ae.kbdint = events->auth_kbdint ? ac_kbdint : NULL;
      ae.authenticated = ac_authenticated;
      ae.failed = ac_failed;
      r = gf_auth_client_new (&s->ac, &config->client_auth, &ae);
    }
  if (r != GF_OK)
    {
      gf_session_free (s);
      return r;
    }
  *out = s;
  return GF_OK;
}

int
gf_session_client_new (gf_session **out, const gf_session_config *config,
                       const gf_session_events *events)
{
  return session_new (out, 0, config, events);
}

int
gf_session_server_new (gf_session **out, const gf_session_config *config,
                       const gf_session_events *events)
{
  return session_new (out, 1, config, events);
}

void
gf_session_free (gf_session *s)
{
  size_t i;

  if (s == NULL)
    return;
  for (i = 0; i < s->nbind; i++)
    if (s->bind[i].used)
      binding_release (s, &s->bind[i]);
  gf_auth_server_free (s->as);
  gf_auth_client_free (s->ac);
  gf_chans_free (s->ch);
  gf_conn_free (s->c);
  free (s->bind);
  free (s->user);
  free (s);
}

/* ------------------------------------------------------------------ */
/* Driving                                                            */
/* ------------------------------------------------------------------ */

void
gf_session_set_time (gf_session *s, uint64_t now_us)
{
  s->now = now_us;
}

int
gf_session_start (gf_session *s, uint64_t now_us)
{
  if (s == NULL)
    return GF_ERR_INVAL;
  s->now = now_us;
  return gf_conn_start (s->c, now_us);
}

int
gf_session_receive (gf_session *s, uint64_t now_us, const uint8_t *data,
                    size_t len)
{
  if (s == NULL)
    return GF_ERR_INVAL;
  s->now = now_us;
  return gf_conn_receive (s->c, now_us, data, len);
}

uint64_t
gf_session_timeout (const gf_session *s)
{
  uint64_t t = gf_conn_timeout (s->c);

  if (s->server && s->as != NULL && !gf_conn_is_closed (s->c))
    {
      uint64_t a = gf_auth_server_timeout (s->as);

      if (a < t)
        t = a;
    }
  return t;
}

int
gf_session_on_timeout (gf_session *s, uint64_t now_us)
{
  int r;

  if (s == NULL)
    return GF_ERR_INVAL;
  s->now = now_us;
  r = gf_conn_on_timeout (s->c, now_us);
  if (r == GF_OK && s->server && s->as != NULL && !gf_conn_is_closed (s->c))
    gf_auth_server_on_timeout (s->as, now_us);
  return r;
}

int
gf_session_disconnect (gf_session *s, uint64_t now_us, uint32_t reason,
                       const char *description)
{
  if (s == NULL)
    return GF_ERR_INVAL;
  s->now = now_us;
  return gf_conn_disconnect (s->c, now_us, reason, description);
}

enum gf_session_phase
gf_session_phase (const gf_session *s)
{
  return gf_conn_is_closed (s->c) ? GF_PHASE_CLOSED : s->phase;
}

const gf_conn_info *
gf_session_info (const gf_session *s)
{
  return gf_conn_get_info (s->c);
}

const char *
gf_session_user (const gf_session *s)
{
  return s->user;
}

const char *
gf_session_force_command (const gf_session *s)
{
  gf_slice cmd;

  if (s == NULL || s->as == NULL
      || gf_auth_server_force_command (s->as, &cmd) != GF_OK || cmd.len == 0)
    return NULL;
  return (const char *) cmd.data;
}

gf_chans *
gf_session_channels (gf_session *s)
{
  return s->ch;
}

gf_conn *
gf_session_conn (gf_session *s)
{
  return s->c;
}

/* ------------------------------------------------------------------ */
/* Authentication answers                                             */
/* ------------------------------------------------------------------ */

#define SERVER_ONLY(s) \
  do { if ((s) == NULL || !(s)->server) return GF_ERR_STATE; } while (0)

int
gf_session_auth_accept (gf_session *s)
{
  SERVER_ONLY (s);
  return gf_auth_server_accept (s->as, s->now);
}

int
gf_session_auth_reject (gf_session *s, int partial)
{
  SERVER_ONLY (s);
  return gf_auth_server_reject (s->as, s->now, partial);
}

int
gf_session_auth_pk_ok (gf_session *s)
{
  SERVER_ONLY (s);
  return gf_auth_server_pk_ok (s->as, s->now);
}

int
gf_session_auth_kbdint_prompt (gf_session *s, const char *name,
                               const char *instruction, size_t nprompts,
                               const char *const *prompts, const int *echo)
{
  SERVER_ONLY (s);
  return gf_auth_server_kbdint_prompt (s->as, s->now, name, instruction,
                                       nprompts, prompts, echo);
}

int
gf_session_auth_banner (gf_session *s, const char *text)
{
  SERVER_ONLY (s);
  return gf_auth_server_banner (s->as, s->now, text);
}

int
gf_session_auth_kbdint_respond (gf_session *s, size_t n,
                                const char *const *responses)
{
  if (s == NULL || s->server)
    return GF_ERR_STATE;
  return gf_auth_client_kbdint_respond (s->ac, s->now, n, responses);
}

/* ------------------------------------------------------------------ */
/* SFTP on a channel                                                  */
/* ------------------------------------------------------------------ */

static long
bs_write (void *user, const uint8_t *d, size_t n)
{
  struct binding *b = user;
  long r = gf_chans_send_data (b->s->ch, b->id, d, n);

  return r == GF_ERR_AGAIN ? 0 : r;
}

static int
bs_request (void *user, const gf_sftp_request *q)
{
  struct binding *b = user;

  return b->sev.request (b->sev.user, q);
}

static void
bs_disconnect (void *user, int status)
{
  struct binding *b = user;

  if (b->sev.disconnect)
    b->sev.disconnect (b->sev.user, status);
  gf_chans_close (b->s->ch, b->id);
}

static int
bc_ready (void *user)
{
  struct binding *b = user;

  return b->cev.ready ? b->cev.ready (b->cev.user) : 0;
}

static int
bc_response (void *user, const gf_sftp_response *r)
{
  struct binding *b = user;

  return b->cev.response (b->cev.user, r);
}

static void
bc_disconnect (void *user, int status)
{
  struct binding *b = user;

  if (b->cev.disconnect)
    b->cev.disconnect (b->cev.user, status);
  gf_chans_close (b->s->ch, b->id);
}

static struct binding *
bind_for (gf_session *s, uint32_t id)
{
  struct binding *b;

  if (s == NULL || s->phase != GF_PHASE_READY
      || gf_chans_remote_max_packet (s->ch, id) == 0)
    return NULL;			/* No such open channel.  */
  b = binding_of (s, id);
  if (b != NULL && b->kind != B_NONE)
    return NULL;			/* Already bound.  */
  if (b == NULL)
    b = binding_new (s, id);
  return b;
}

int
gf_session_sftp_server (gf_session *s, uint32_t id,
                        const gf_sftp_server_config *config,
                        const gf_sftp_server_events *events,
                        gf_sftp_server **out)
{
  struct binding *b;
  gf_sftp_server_events se;
  int r;

  if (config == NULL || events == NULL || events->request == NULL)
    return GF_ERR_INVAL;
  b = bind_for (s, id);
  if (b == NULL)
    return GF_ERR_STATE;
  b->sev = *events;
  memset (&se, 0, sizeof se);
  se.user = b;
  se.write = bs_write;
  se.request = bs_request;
  se.disconnect = bs_disconnect;
  r = gf_sftp_server_new (&b->ss, config, &se);
  if (r != GF_OK)
    return r;
  b->kind = B_SFTP_SERVER;
  if (out)
    *out = b->ss;
  return GF_OK;
}

int
gf_session_sftp_client (gf_session *s, uint32_t id,
                        const gf_sftp_client_config *config,
                        const gf_sftp_client_events *events,
                        gf_sftp_client **out)
{
  struct binding *b;
  gf_sftp_client_events ce;
  int r;

  if (config == NULL || events == NULL || events->response == NULL)
    return GF_ERR_INVAL;
  b = bind_for (s, id);
  if (b == NULL)
    return GF_ERR_STATE;
  b->cev = *events;
  memset (&ce, 0, sizeof ce);
  ce.user = b;
  ce.write = bs_write;
  ce.ready = bc_ready;
  ce.response = bc_response;
  ce.disconnect = bc_disconnect;
  r = gf_sftp_client_new (&b->sc, config, &ce);
  if (r != GF_OK)
    return r;
  b->kind = B_SFTP_CLIENT;
  r = gf_sftp_client_start (b->sc);
  if (r != GF_OK)
    {
      gf_sftp_client_free (b->sc);
      b->sc = NULL;
      b->kind = B_NONE;
      return r;
    }
  if (out)
    *out = b->sc;
  return GF_OK;
}
