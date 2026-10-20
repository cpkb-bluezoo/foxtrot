#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/wire.h>
#include <foxtrot/chan.h>

#include "fuzz-common.h"

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  return 0;
}

struct ctx
{
  gf_chans *m;
  unsigned schedule, counter;
  int stop;
  uint32_t ids[8];
  size_t nids;
};

static int
c_send (void *u, const uint8_t *p, size_t n)
{
  struct ctx *c = u;

  (void) p;
  (void) n;
  /* Now and then the transport says "not now" to a message of data.  */
  return (c->schedule & 0x80) && p[0] == 94 && (c->counter++ % 5) == 0
    ? GF_ERR_AGAIN : 0;
}

static unsigned
choice (struct ctx *c)
{
  return (c->schedule >> (c->counter++ % 8 * 2)) & 3;
}

static int
c_open_request (void *u, const gf_chan_open *o)
{
  struct ctx *c = u;

  switch (choice (c))
    {
    case 0:
      return gf_chans_open_reject (c->m, o->id, GF_OPEN_ADMINISTRATIVELY_PROHIBITED, "no") != GF_OK;
    default:
      if (gf_chans_open_accept (c->m, o->id, 1024, 512) != GF_OK)
        return 1;
      if (c->nids < 8)
        c->ids[c->nids++] = o->id;
      return 0;
    }
}

static int
c_confirmed (void *u, uint32_t id)
{
  struct ctx *c = u;

  if (c->nids < 8)
    c->ids[c->nids++] = id;
  return 0;
}

static int
c_failed (void *u, uint32_t id, uint32_t reason, gf_slice text)
{
  (void) u;
  (void) id;
  (void) reason;
  (void) text;
  return 0;
}

static int
c_data (void *u, uint32_t id, const uint8_t *d, size_t n)
{
  struct ctx *c = u;

  (void) d;
  /* Sometimes the application is slow to say it is done.  */
  if (choice (c) == 3)
    return 0;
  (void) gf_chans_consumed (c->m, id, n);
  return 0;
}

static int
c_ext (void *u, uint32_t id, uint32_t type, const uint8_t *d, size_t n)
{
  (void) type;
  return c_data (u, id, d, n);
}

static int
c_eof (void *u, uint32_t id)
{
  (void) u;
  (void) id;
  return 0;
}

static int
c_writable (void *u, uint32_t id)
{
  (void) u;
  (void) id;
  return 0;
}

static int
c_request (void *u, const gf_chan_request *q)
{
  struct ctx *c = u;

  if (!q->want_reply)
    return 0;
  return gf_chans_reply (c->m, q->id, choice (c) != 0) != GF_OK;
}

static int
c_reply (void *u, uint32_t id, int ok)
{
  (void) u;
  (void) id;
  (void) ok;
  return 0;
}

static int
c_global (void *u, const gf_global_request *r)
{
  struct ctx *c = u;

  if (!r->want_reply)
    return 0;
  return gf_chans_global_reply (c->m, choice (c) != 0, 1000) != GF_OK;
}

static int
c_global_reply (void *u, int ok, uint32_t port)
{
  (void) u;
  (void) ok;
  (void) port;
  return 0;
}

static int
c_closed (void *u, uint32_t id)
{
  struct ctx *c = u;
  size_t i;

  for (i = 0; i < c->nids; i++)
    if (c->ids[i] == id)
      c->ids[i] = (uint32_t) -1;
  return 0;
}

static int
c_disconnect (void *u, uint32_t reason)
{
  struct ctx *c = u;

  (void) reason;
  c->stop = 1;
  return 0;
}

/* Something we do on our own account between the peer's messages.  */
static void
act (struct ctx *c, uint8_t what)
{
  uint32_t id = c->nids ? c->ids[what % c->nids] : 0;
  uint8_t buf[300];

  memset (buf, 'x', sizeof buf);
  switch (what % 9)
    {
    case 0:
      break;
    case 1:
      (void) gf_chans_send_data (c->m, id, buf, sizeof buf);
      break;
    case 2:
      (void) gf_chans_send_eof (c->m, id);
      break;
    case 3:
      (void) gf_chans_close (c->m, id);
      break;
    case 4:
      (void) gf_chans_request_pty (c->m, id, "xterm", 80, 24, 0, 0, NULL, 0, 1);
      break;
    case 5:
      (void) gf_chans_resume (c->m);
      break;
    case 6:
      {
        uint32_t nid;

        if (gf_chans_open_session (c->m, &nid, 0, 0) == GF_OK && c->nids < 8)
          c->ids[c->nids++] = nid;
      }
      break;
    case 7:
      (void) gf_chans_request_tcpip_forward (c->m, "0.0.0.0", 0);
      break;
    default:
      (void) gf_chans_send_extended (c->m, id, 1, buf, 50);
      break;
    }
}

/* Channel messages (80 to 100) in a stream of frames, to a channel layer
   that has a channel of each side's opening and acts on its own.  The input
   starts with a byte that says how the application answers.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct ctx c;
  gf_chans_config cfg;
  gf_chans_events ev;
  const uint8_t *frame;
  size_t flen;
  uint32_t id;

  if (size < 2)
    return 0;
  memset (&c, 0, sizeof c);
  c.schedule = data[0] | (unsigned) data[1] << 8;
  data += 2;
  size -= 2;
  memset (&cfg, 0, sizeof cfg);
  cfg.max_channels = 8;
  cfg.max_requests = 4;
  cfg.auto_window = (c.schedule & 0x100) != 0;
  memset (&ev, 0, sizeof ev);
  ev.user = &c;
  ev.send = c_send;
  ev.open_request = c_open_request;
  ev.open_confirmed = c_confirmed;
  ev.open_failed = c_failed;
  ev.data = c_data;
  ev.extended_data = c_ext;
  ev.eof = c_eof;
  ev.writable = c_writable;
  ev.request = c_request;
  ev.request_reply = c_reply;
  ev.global_request = c_global;
  ev.global_reply = c_global_reply;
  ev.closed = c_closed;
  ev.disconnect = c_disconnect;
  if (gf_chans_new (&c.m, &cfg, &ev) != GF_OK)
    abort ();
  /* A channel we opened, which the peer confirms.  */
  if (gf_chans_open_session (c.m, &id, 0, 0) == GF_OK)
    {
      uint8_t m[32];
      gf_writer w;

      c.ids[c.nids++] = id;
      gf_writer_init (&w, m, sizeof m);
      gf_wr_u8 (&w, 91);
      gf_wr_u32 (&w, id);
      gf_wr_u32 (&w, 700);
      gf_wr_u32 (&w, 2048);
      gf_wr_u32 (&w, 1024);
      (void) gf_chans_input (c.m, m, w.len);
    }
  /* And one the peer opens.  */
  {
    uint8_t m[64];
    gf_writer w;

    gf_writer_init (&w, m, sizeof m);
    gf_wr_u8 (&w, 90);
    gf_wr_cstring (&w, "session");
    gf_wr_u32 (&w, 800);
    gf_wr_u32 (&w, 2048);
    gf_wr_u32 (&w, 1024);
    (void) gf_chans_input (c.m, m, w.len);
  }
  while (!c.stop && fuzz_frame (&data, &size, &frame, &flen))
    {
      if (flen == 0 || frame[0] < 80 || frame[0] > 100)
        continue;
      (void) gf_chans_input (c.m, frame, flen);
      if (size > 0)
        {
          act (&c, data[0]);
          data++;
          size--;
        }
    }
  gf_chans_free (c.m);
  return 0;
}
