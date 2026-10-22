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

/* A client and a server connection wired to each other in memory, on a
   virtual clock, for the tests of the layers above the packet layer.  */

#ifndef GF_TST_PAIR_H
#define GF_TST_PAIR_H

#include <stdlib.h>

#include <foxtrot/conn.h>

#include "tst-util.h"

struct pipe
{
  uint8_t *buf;
  size_t len, cap;
};

struct msg
{
  uint8_t *data;
  size_t len;
};

struct end;

struct end
{
  gf_conn *c;
  struct pipe out;
  int is_server;
  int established, rekeyed, closed, accepted, trust;
  int close_error;
  uint32_t close_reason;
  int host_key_calls;
  struct msg *msgs;
  size_t nmsgs, capmsgs;
  char extension[256];
  char service[64];
  uint32_t unimpl;
  int unimpl_calls;
  int debug_calls;
  gf_conn_info info;
  /* Optional hooks, for the tests of the layers above.  */
  int (*on_established) (struct end *e);
  int (*on_service_accepted) (struct end *e);
  int (*on_extension) (struct end *e, gf_slice name, gf_slice value);
  int (*on_message) (struct end *e, const uint8_t *p, size_t n);
  void *hook;
};

static uint64_t tst_now = 1000000;

static int
end_write (void *user, const uint8_t *data, size_t len)
{
  struct end *e = user;

  if (e->out.len + len > e->out.cap)
    {
      e->out.cap = (e->out.len + len) * 2;
      e->out.buf = realloc (e->out.buf, e->out.cap);
    }
  memcpy (e->out.buf + e->out.len, data, len);
  e->out.len += len;
  return 0;
}

static int
end_host_key (void *user, const gf_key *key)
{
  struct end *e = user;

  (void) key;
  e->host_key_calls++;
  return e->trust ? 0 : 1;
}

static int
end_established (void *user, const gf_conn_info *info)
{
  struct end *e = user;

  e->established++;
  e->info = *info;
  return e->on_established ? e->on_established (e) : 0;
}

static int
end_rekeyed (void *user, const gf_conn_info *info)
{
  struct end *e = user;

  e->rekeyed++;
  e->info = *info;
  return 0;
}

static int
end_message (void *user, const uint8_t *p, size_t n)
{
  struct end *e = user;

  if (e->on_message)
    return e->on_message (e, p, n);
  if (e->nmsgs == e->capmsgs)
    {
      e->capmsgs = e->capmsgs ? e->capmsgs * 2 : 16;
      e->msgs = realloc (e->msgs, e->capmsgs * sizeof *e->msgs);
    }
  e->msgs[e->nmsgs].data = malloc (n);
  memcpy (e->msgs[e->nmsgs].data, p, n);
  e->msgs[e->nmsgs].len = n;
  e->nmsgs++;
  return 0;
}

static int
end_service_accepted (void *user, gf_slice name)
{
  struct end *e = user;

  e->accepted++;
  snprintf (e->service, sizeof e->service, "%.*s", (int) name.len,
            (const char *) name.data);
  return e->on_service_accepted ? e->on_service_accepted (e) : 0;
}

static int
end_service_request (void *user, gf_slice name)
{
  struct end *e = user;

  snprintf (e->service, sizeof e->service, "%.*s", (int) name.len,
            (const char *) name.data);
  return 0;
}

static int
end_extension (void *user, gf_slice name, gf_slice value)
{
  struct end *e = user;
  size_t used = strlen (e->extension);

  snprintf (e->extension + used, sizeof e->extension - used, "%.*s=%.*s;",
            (int) name.len, (const char *) name.data, (int) value.len,
            (const char *) value.data);
  return e->on_extension ? e->on_extension (e, name, value) : 0;
}

static void
end_unimplemented (void *user, uint32_t seq)
{
  struct end *e = user;

  e->unimpl = seq;
  e->unimpl_calls++;
}

static void
end_debug (void *user, int always, gf_slice text)
{
  struct end *e = user;

  (void) always;
  (void) text;
  e->debug_calls++;
}

static void
end_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  struct end *e = user;

  (void) text;
  e->closed++;
  e->close_error = error;
  e->close_reason = reason;
}

static gf_conn_events
end_events (struct end *e)
{
  gf_conn_events ev;

  memset (&ev, 0, sizeof ev);
  ev.user = e;
  ev.write = end_write;
  ev.host_key = end_host_key;
  ev.established = end_established;
  ev.rekeyed = end_rekeyed;
  ev.service_request = end_service_request;
  ev.service_accepted = end_service_accepted;
  ev.message = end_message;
  ev.extension = end_extension;
  ev.debug = end_debug;
  ev.unimplemented = end_unimplemented;
  ev.closed = end_closed;
  return ev;
}

struct pair
{
  struct end cl, sv;
};

/* Set to leave the client without a host key callback.  */
static int pair_no_host_key_callback;

/* Create both ends (not started).  */
static int
pair_new (struct pair *p, const gf_conn_config *ccfg, const gf_conn_config *scfg)
{
  gf_conn_events ce, se;
  int r;

  memset (p, 0, sizeof *p);
  p->cl.trust = 1;
  p->sv.is_server = 1;
  ce = end_events (&p->cl);
  se = end_events (&p->sv);
  if (pair_no_host_key_callback)
    ce.host_key = NULL;
  r = gf_conn_client_new (&p->cl.c, ccfg, &ce);
  if (r != GF_OK)
    return r;
  return gf_conn_server_new (&p->sv.c, scfg, &se);
}

static void
end_clear (struct end *e)
{
  size_t i;

  for (i = 0; i < e->nmsgs; i++)
    free (e->msgs[i].data);
  free (e->msgs);
  free (e->out.buf);
  gf_conn_free (e->c);
}

static void
pair_free (struct pair *p)
{
  end_clear (&p->cl);
  end_clear (&p->sv);
}

/* Deliver everything written by FROM to TO in pieces of CHUNK bytes (0:
   all at once).  Returns the number of bytes moved.  */
static size_t
deliver (struct end *from, struct end *to, size_t chunk)
{
  size_t moved = 0;

  while (from->out.len > 0)
    {
      size_t n = chunk && chunk < from->out.len ? chunk : from->out.len;
      uint8_t *copy = malloc (n);

      memcpy (copy, from->out.buf, n);
      memmove (from->out.buf, from->out.buf + n, from->out.len - n);
      from->out.len -= n;
      moved += n;
      if (!gf_conn_is_closed (to->c))
        (void) gf_conn_receive (to->c, tst_now, copy, n);
      free (copy);
    }
  return moved;
}

/* Run the two ends until nothing more is written.  */
static void
pump (struct pair *p, size_t chunk)
{
  int guard = 0;

  while ((p->cl.out.len || p->sv.out.len) && guard++ < 100000)
    {
      deliver (&p->cl, &p->sv, chunk);
      deliver (&p->sv, &p->cl, chunk);
    }
}

/* Both ends are told the user has authenticated, as the session does, so
   that they rekey.  Established first.  */
static inline void
pair_authenticate (struct pair *p)
{
  CHECK_EQ (gf_conn_set_authenticated (p->cl.c), GF_OK);
  CHECK_EQ (gf_conn_set_authenticated (p->sv.c), GF_OK);
}

static void
pair_start (struct pair *p)
{
  CHECK_EQ (gf_conn_start (p->cl.c, tst_now), GF_OK);
  CHECK_EQ (gf_conn_start (p->sv.c, tst_now), GF_OK);
}

/* A message numbered 50 or more with a recognisable body.  */
static inline size_t
mkmsg (uint8_t *buf, uint8_t type, size_t len, uint8_t seed)
{
  size_t i;

  buf[0] = type;
  for (i = 1; i < len; i++)
    buf[i] = (uint8_t) (seed + i * 13);
  return len;
}

static inline int
msg_is (const struct msg *m, uint8_t type, size_t len, uint8_t seed)
{
  uint8_t ref[GF_MAX_PAYLOAD];

  if (m->len != len)
    return 0;
  mkmsg (ref, type, len, seed);
  return memcmp (m->data, ref, len) == 0;
}

#endif /* GF_TST_PAIR_H */
