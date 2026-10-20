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
#include <foxtrot/sftp.h>

#define DEFAULT_SERVER_REQUESTS 128
#define DEFAULT_CLIENT_REQUESTS 64
#define DEFAULT_MAX_OUTPUT (4 * 1024 * 1024)
#define MAX_EXT_PAIRS 64
#define KNOWN_ATTR_FLAGS (GF_FILEXFER_ATTR_SIZE | GF_FILEXFER_ATTR_UIDGID \
                          | GF_FILEXFER_ATTR_PERMISSIONS \
                          | GF_FILEXFER_ATTR_ACMODTIME | 0x80000000u)

/* ------------------------------------------------------------------ */
/* Framing and output, shared                                         */
/* ------------------------------------------------------------------ */

struct io
{
  uint32_t max_packet;
  size_t max_output;
  uint8_t lenbuf[4];
  size_t lenn;
  uint32_t need;		/* Body length being collected, 0: the length.  */
  uint8_t *in;
  size_t inn, incap;
  uint8_t *out;
  size_t outn, outcap;
  long (*write) (void *, const uint8_t *, size_t);
  void *user;
  int dead;
};

static void
io_init (struct io *io, uint32_t max_packet, size_t max_output,
         long (*write) (void *, const uint8_t *, size_t), void *user)
{
  memset (io, 0, sizeof *io);
  io->max_packet = max_packet ? max_packet : GF_SFTP_DEFAULT_MAX_PACKET;
  io->max_output = max_output ? max_output : DEFAULT_MAX_OUTPUT;
  io->write = write;
  io->user = user;
}

static void
io_free (struct io *io)
{
  free (io->in);
  if (io->out)
    memset (io->out, 0, io->outcap);
  free (io->out);
}

/* Send what can go; keep the rest.  */
static int
io_flush (struct io *io)
{
  while (io->outn > 0)
    {
      long r = io->write (io->user, io->out, io->outn);

      if (r < 0)
        return GF_ERR_HANDLER;
      if (r == 0)
        break;
      if ((size_t) r > io->outn)
        return GF_ERR_INVAL;
      memmove (io->out, io->out + r, io->outn - (size_t) r);
      io->outn -= (size_t) r;
    }
  return GF_OK;
}

/* Queue one complete packet (length included) and try to send it.  */
static int
io_emit (struct io *io, const uint8_t *pkt, size_t n)
{
  int r;

  if (io->outn + n > io->max_output)
    return GF_ERR_AGAIN;
  if (io->outn + n > io->outcap)
    {
      size_t cap = (io->outn + n) * 2;
      uint8_t *p = realloc (io->out, cap);

      if (p == NULL)
        return GF_ERR_NOMEM;
      io->out = p;
      io->outcap = cap;
    }
  memcpy (io->out + io->outn, pkt, n);
  io->outn += n;
  r = io_flush (io);
  return r;
}

/* A packet under construction: the length is filled in by pkt_end.  */
struct pkt
{
  uint8_t *buf;
  gf_writer w;
};

static int
pkt_begin (struct pkt *p, uint8_t type, size_t body_estimate)
{
  p->buf = malloc (body_estimate + 16);
  if (p->buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&p->w, p->buf, body_estimate + 16);
  gf_wr_u32 (&p->w, 0);
  gf_wr_u8 (&p->w, type);
  return GF_OK;
}

static int
pkt_end (struct io *io, struct pkt *p)
{
  size_t body;
  int r;

  if (gf_wr_status (&p->w) != GF_OK)
    r = GF_ERR_BUFSIZE;
  else
    {
      body = p->w.len - 4;
      if (body > io->max_packet)
        r = GF_ERR_RANGE;
      else
        {
          p->buf[0] = (uint8_t) (body >> 24);
          p->buf[1] = (uint8_t) (body >> 16);
          p->buf[2] = (uint8_t) (body >> 8);
          p->buf[3] = (uint8_t) body;
          r = io_emit (io, p->buf, p->w.len);
        }
    }
  memset (p->buf, 0, p->w.cap);
  free (p->buf);
  return r;
}

/* Feed bytes; HANDLER is called with each packet's body.  Returns what the
   handler returns for the first failure, GF_ERR_PROTOCOL for a bad
   length.  */
typedef int (*packet_fn) (void *ctx, const uint8_t *body, size_t len);

static int
io_input (struct io *io, const uint8_t *d, size_t n, packet_fn fn, void *ctx)
{
  while (n > 0)
    {
      if (io->need == 0)
        {
          while (io->lenn < 4 && n > 0)
            {
              io->lenbuf[io->lenn++] = *d++;
              n--;
            }
          if (io->lenn < 4)
            return GF_OK;
          io->need = (uint32_t) io->lenbuf[0] << 24 | io->lenbuf[1] << 16
            | io->lenbuf[2] << 8 | io->lenbuf[3];
          io->lenn = 0;
          if (io->need == 0 || io->need > io->max_packet)
            return GF_ERR_PROTOCOL;
          io->inn = 0;
        }
      if (io->inn == 0 && n >= io->need)
        {
          /* The whole body is here: no copy.  */
          uint32_t len = io->need;
          int r;

          io->need = 0;
          r = fn (ctx, d, len);
          if (r != GF_OK)
            return r;
          d += len;
          n -= len;
          continue;
        }
      {
        size_t take = io->need - io->inn;

        if (take > n)
          take = n;
        if (io->inn + take > io->incap)
          {
            size_t cap = io->need;
            uint8_t *p = realloc (io->in, cap);

            if (p == NULL)
              return GF_ERR_NOMEM;
            io->in = p;
            io->incap = cap;
          }
        if (take > 0)		/* io->in is NULL until something arrives.  */
          memcpy (io->in + io->inn, d, take);
        io->inn += take;
        d += take;
        n -= take;
        if (io->inn == io->need)
          {
            uint32_t len = io->need;
            int r;

            io->need = 0;
            io->inn = 0;
            r = fn (ctx, io->in, len);
            if (r != GF_OK)
              return r;
          }
      }
    }
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Attributes and strings                                             */
/* ------------------------------------------------------------------ */

static int
rd_attrs (gf_reader *r, gf_sftp_attrs *a)
{
  uint32_t flags, count, i;
  gf_slice skip;

  memset (a, 0, sizeof *a);
  if (gf_rd_u32 (r, &flags) != GF_OK || (flags & ~KNOWN_ATTR_FLAGS))
    return GF_ERR_ENCODING;
  a->flags = flags & ~0x80000000u;
  if ((flags & GF_FILEXFER_ATTR_SIZE) && gf_rd_u64 (r, &a->size) != GF_OK)
    return GF_ERR_ENCODING;
  if ((flags & GF_FILEXFER_ATTR_UIDGID)
      && (gf_rd_u32 (r, &a->uid) != GF_OK || gf_rd_u32 (r, &a->gid) != GF_OK))
    return GF_ERR_ENCODING;
  if ((flags & GF_FILEXFER_ATTR_PERMISSIONS)
      && gf_rd_u32 (r, &a->permissions) != GF_OK)
    return GF_ERR_ENCODING;
  if ((flags & GF_FILEXFER_ATTR_ACMODTIME)
      && (gf_rd_u32 (r, &a->atime) != GF_OK || gf_rd_u32 (r, &a->mtime) != GF_OK))
    return GF_ERR_ENCODING;
  if (flags & 0x80000000u)
    {
      if (gf_rd_u32 (r, &count) != GF_OK || count > MAX_EXT_PAIRS)
        return GF_ERR_ENCODING;
      for (i = 0; i < count; i++)
        if (gf_rd_string (r, &skip) != GF_OK || gf_rd_string (r, &skip) != GF_OK)
          return GF_ERR_ENCODING;
    }
  return GF_OK;
}

static void
wr_attrs (gf_writer *w, const gf_sftp_attrs *a)
{
  uint32_t flags = a ? a->flags & (GF_FILEXFER_ATTR_SIZE
                                   | GF_FILEXFER_ATTR_UIDGID
                                   | GF_FILEXFER_ATTR_PERMISSIONS
                                   | GF_FILEXFER_ATTR_ACMODTIME) : 0;

  gf_wr_u32 (w, flags);
  if (flags & GF_FILEXFER_ATTR_SIZE)
    gf_wr_u64 (w, a->size);
  if (flags & GF_FILEXFER_ATTR_UIDGID)
    {
      gf_wr_u32 (w, a->uid);
      gf_wr_u32 (w, a->gid);
    }
  if (flags & GF_FILEXFER_ATTR_PERMISSIONS)
    gf_wr_u32 (w, a->permissions);
  if (flags & GF_FILEXFER_ATTR_ACMODTIME)
    {
      gf_wr_u32 (w, a->atime);
      gf_wr_u32 (w, a->mtime);
    }
}

/* A path or name: no NUL, bounded.  */
static int
rd_path (gf_reader *r, gf_slice *s)
{
  if (gf_rd_text (r, s) != GF_OK || s->len > GF_SFTP_MAX_PATH)
    return GF_ERR_ENCODING;
  return GF_OK;
}

static int
rd_handle (gf_reader *r, gf_slice *s)
{
  if (gf_rd_string (r, s) != GF_OK || s->len > GF_SFTP_MAX_HANDLE)
    return GF_ERR_ENCODING;
  return GF_OK;
}

/* ================================================================== */
/* Server                                                             */
/* ================================================================== */

struct outstanding_srv
{
  uint32_t id;
  enum gf_sftp_type type;
};

struct gf_sftp_server
{
  struct io io;
  gf_sftp_server_events ev;
  unsigned max_requests;
  int got_init;
  struct outstanding_srv *out;
  unsigned nout;
};

int
gf_sftp_server_new (gf_sftp_server **out, const gf_sftp_server_config *config,
                    const gf_sftp_server_events *events)
{
  gf_sftp_server *s;

  if (out == NULL || config == NULL || events == NULL || events->write == NULL
      || events->request == NULL)
    return GF_ERR_INVAL;
  s = calloc (1, sizeof *s);
  if (s == NULL)
    return GF_ERR_NOMEM;
  io_init (&s->io, config->max_packet, config->max_output, events->write,
           events->user);
  s->ev = *events;
  s->max_requests = config->max_requests ? config->max_requests
                                         : DEFAULT_SERVER_REQUESTS;
  s->out = calloc (s->max_requests, sizeof *s->out);
  if (s->out == NULL)
    {
      free (s);
      return GF_ERR_NOMEM;
    }
  *out = s;
  return GF_OK;
}

void
gf_sftp_server_free (gf_sftp_server *s)
{
  if (s == NULL)
    return;
  io_free (&s->io);
  free (s->out);
  free (s);
}

size_t
gf_sftp_server_pending (const gf_sftp_server *s)
{
  return s->io.outn;
}

int
gf_sftp_server_writable (gf_sftp_server *s)
{
  int r;

  if (s->io.dead)
    return GF_ERR_CLOSED;
  r = io_flush (&s->io);
  if (r != GF_OK)
    {
      s->io.dead = 1;
      s->ev.disconnect (s->ev.user, r);
    }
  return r;
}

static int
srv_die (gf_sftp_server *s, int status)
{
  if (!s->io.dead)
    {
      s->io.dead = 1;
      if (s->ev.disconnect)
        s->ev.disconnect (s->ev.user, status);
    }
  return status;
}

static struct outstanding_srv *
srv_find (gf_sftp_server *s, uint32_t id)
{
  unsigned i;

  for (i = 0; i < s->nout; i++)
    if (s->out[i].id == id)
      return &s->out[i];
  return NULL;
}

static void
srv_remove (gf_sftp_server *s, struct outstanding_srv *o)
{
  *o = s->out[--s->nout];
}

static int
srv_status_direct (gf_sftp_server *s, uint32_t id, uint32_t code,
                   const char *msg)
{
  struct pkt p;
  int r = pkt_begin (&p, GF_FXP_STATUS, strlen (msg) + 24);

  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, id);
  gf_wr_u32 (&p.w, code);
  gf_wr_cstring (&p.w, msg);
  gf_wr_cstring (&p.w, "");
  return pkt_end (&s->io, &p);
}

static int
srv_request (gf_sftp_server *s, const uint8_t *body, size_t len)
{
  gf_reader rd;
  uint8_t type;
  uint32_t id;
  gf_sftp_request rq;
  int bad = 0, known = 1;

  gf_reader_init (&rd, body, len);
  if (gf_rd_u8 (&rd, &type) != GF_OK)
    return srv_die (s, GF_ERR_PROTOCOL);
  if (!s->got_init)
    {
      uint32_t version;
      struct pkt p;
      int r;

      if (type != GF_FXP_INIT || gf_rd_u32 (&rd, &version) != GF_OK)
        return srv_die (s, GF_ERR_PROTOCOL);
      /* Extension pairs may follow; we use none.  */
      if (version < GF_SFTP_VERSION)
        return srv_die (s, GF_ERR_UNSUPPORTED);
      s->got_init = 1;
      r = pkt_begin (&p, GF_FXP_VERSION, 8);
      if (r != GF_OK)
        return r;
      gf_wr_u32 (&p.w, GF_SFTP_VERSION);
      r = pkt_end (&s->io, &p);
      return r == GF_OK ? GF_OK : srv_die (s, r);
    }
  if (type == GF_FXP_INIT || type == GF_FXP_VERSION
      || (type >= GF_FXP_STATUS && type <= GF_FXP_ATTRS)
      || type == GF_FXP_EXTENDED_REPLY || gf_rd_u32 (&rd, &id) != GF_OK)
    return srv_die (s, GF_ERR_PROTOCOL);

  memset (&rq, 0, sizeof rq);
  rq.id = id;
  rq.type = (enum gf_sftp_type) type;
  switch (type)
    {
    case GF_FXP_OPEN:
      bad = rd_path (&rd, &rq.path) != GF_OK
        || gf_rd_u32 (&rd, &rq.pflags) != GF_OK
        || rd_attrs (&rd, &rq.attrs) != GF_OK;
      break;
    case GF_FXP_CLOSE:
    case GF_FXP_FSTAT:
    case GF_FXP_READDIR:
      bad = rd_handle (&rd, &rq.handle) != GF_OK;
      break;
    case GF_FXP_READ:
      bad = rd_handle (&rd, &rq.handle) != GF_OK
        || gf_rd_u64 (&rd, &rq.offset) != GF_OK
        || gf_rd_u32 (&rd, &rq.length) != GF_OK;
      break;
    case GF_FXP_WRITE:
      bad = rd_handle (&rd, &rq.handle) != GF_OK
        || gf_rd_u64 (&rd, &rq.offset) != GF_OK
        || gf_rd_string (&rd, &rq.data) != GF_OK;
      break;
    case GF_FXP_LSTAT:
    case GF_FXP_STAT:
    case GF_FXP_OPENDIR:
    case GF_FXP_REMOVE:
    case GF_FXP_RMDIR:
    case GF_FXP_REALPATH:
    case GF_FXP_READLINK:
      bad = rd_path (&rd, &rq.path) != GF_OK;
      break;
    case GF_FXP_SETSTAT:
    case GF_FXP_MKDIR:
      bad = rd_path (&rd, &rq.path) != GF_OK
        || rd_attrs (&rd, &rq.attrs) != GF_OK;
      break;
    case GF_FXP_FSETSTAT:
      bad = rd_handle (&rd, &rq.handle) != GF_OK
        || rd_attrs (&rd, &rq.attrs) != GF_OK;
      break;
    case GF_FXP_RENAME:
      bad = rd_path (&rd, &rq.path) != GF_OK || rd_path (&rd, &rq.path2) != GF_OK;
      break;
    case GF_FXP_SYMLINK:
      /* The target comes first on the wire (see sftp.h).  */
      bad = rd_path (&rd, &rq.path2) != GF_OK || rd_path (&rd, &rq.path) != GF_OK;
      break;
    case GF_FXP_EXTENDED:
      bad = gf_rd_text (&rd, &rq.ext_name) != GF_OK
        || rq.ext_name.len > GF_SFTP_MAX_PATH
        || gf_rd_bytes (&rd, gf_rd_remaining (&rd), &rq.ext_data) != GF_OK;
      break;
    default:
      known = 0;
      break;
    }
  if (known && !bad && type != GF_FXP_EXTENDED && gf_rd_finish (&rd) != GF_OK)
    bad = 1;
  if (srv_find (s, id) != NULL || s->nout >= s->max_requests)
    return srv_die (s, GF_ERR_PROTOCOL);
  if (!known || bad)
    {
      int r = srv_status_direct (s, id, known ? GF_FX_BAD_MESSAGE
                                              : GF_FX_OP_UNSUPPORTED,
                                 known ? "bad message" : "unsupported");

      return r == GF_OK ? GF_OK : srv_die (s, r);
    }
  s->out[s->nout].id = id;
  s->out[s->nout].type = rq.type;
  s->nout++;
  if (s->ev.request (s->ev.user, &rq) != 0)
    return srv_die (s, GF_ERR_HANDLER);
  return GF_OK;
}

static int
srv_packet (void *ctx, const uint8_t *body, size_t len)
{
  return srv_request (ctx, body, len);
}

int
gf_sftp_server_input (gf_sftp_server *s, const uint8_t *data, size_t len)
{
  int r;

  if (s == NULL || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  if (s->io.dead)
    return GF_ERR_CLOSED;
  r = io_input (&s->io, data, len, srv_packet, s);
  if (r != GF_OK && !s->io.dead)
    srv_die (s, r);
  return r;
}

/* Common head of a response: check the id and the kind, and remove it.  */
static int
srv_claim (gf_sftp_server *s, uint32_t id, const enum gf_sftp_type *ok,
           size_t nok, struct outstanding_srv **o)
{
  size_t i;

  if (s->io.dead)
    return GF_ERR_CLOSED;
  *o = srv_find (s, id);
  if (*o == NULL)
    return GF_ERR_STATE;
  if (nok == 0)
    return GF_OK;
  for (i = 0; i < nok; i++)
    if ((*o)->type == ok[i])
      return GF_OK;
  return GF_ERR_INVAL;
}

/* Finish a response: the id is released once the packet is queued.  */
static int
srv_done (gf_sftp_server *s, struct outstanding_srv *o, int r)
{
  if (r == GF_OK)
    srv_remove (s, o);
  else if (r != GF_ERR_AGAIN && r != GF_ERR_RANGE && r != GF_ERR_INVAL)
    srv_die (s, r);
  return r;
}

int
gf_sftp_server_status (gf_sftp_server *s, uint32_t id, uint32_t code,
                       const char *message)
{
  struct outstanding_srv *o;
  struct pkt p;
  int r;

  if (s == NULL || message == NULL)
    return GF_ERR_INVAL;
  r = srv_claim (s, id, NULL, 0, &o);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_STATUS, strlen (message) + 24);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, id);
  gf_wr_u32 (&p.w, code);
  gf_wr_cstring (&p.w, message);
  gf_wr_cstring (&p.w, "");
  return srv_done (s, o, pkt_end (&s->io, &p));
}

int
gf_sftp_server_handle (gf_sftp_server *s, uint32_t id, const uint8_t *handle,
                       size_t len)
{
  static const enum gf_sftp_type ok[] = { GF_FXP_OPEN, GF_FXP_OPENDIR };
  struct outstanding_srv *o;
  struct pkt p;
  int r;

  if (s == NULL || handle == NULL || len == 0 || len > GF_SFTP_MAX_HANDLE)
    return GF_ERR_INVAL;
  r = srv_claim (s, id, ok, 2, &o);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_HANDLE, len + 8);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, id);
  gf_wr_string (&p.w, handle, len);
  return srv_done (s, o, pkt_end (&s->io, &p));
}

int
gf_sftp_server_data (gf_sftp_server *s, uint32_t id, const uint8_t *data,
                     size_t len)
{
  static const enum gf_sftp_type ok[] = { GF_FXP_READ };
  struct outstanding_srv *o;
  struct pkt p;
  int r;

  if (s == NULL || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  if (len + 16 > s->io.max_packet)
    return GF_ERR_RANGE;
  r = srv_claim (s, id, ok, 1, &o);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_DATA, len + 8);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, id);
  gf_wr_string (&p.w, data, len);
  return srv_done (s, o, pkt_end (&s->io, &p));
}

int
gf_sftp_server_names (gf_sftp_server *s, uint32_t id, size_t count,
                      const gf_sftp_name *names)
{
  static const enum gf_sftp_type ok[] = { GF_FXP_READDIR, GF_FXP_REALPATH,
                                          GF_FXP_READLINK };
  struct outstanding_srv *o;
  struct pkt p;
  size_t i, est = 16;
  int r;

  if (s == NULL || (count > 0 && names == NULL) || count == 0)
    return GF_ERR_INVAL;
  r = srv_claim (s, id, ok, 3, &o);
  if (r != GF_OK)
    return r;
  if (o->type != GF_FXP_READDIR && count != 1)
    return GF_ERR_INVAL;
  for (i = 0; i < count; i++)
    est += 8 + names[i].filename.len + names[i].longname.len + 48;
  r = pkt_begin (&p, GF_FXP_NAME, est);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, id);
  gf_wr_u32 (&p.w, (uint32_t) count);
  for (i = 0; i < count; i++)
    {
      gf_wr_string (&p.w, names[i].filename.data, names[i].filename.len);
      gf_wr_string (&p.w, names[i].longname.data, names[i].longname.len);
      wr_attrs (&p.w, &names[i].attrs);
    }
  return srv_done (s, o, pkt_end (&s->io, &p));
}

int
gf_sftp_server_attrs (gf_sftp_server *s, uint32_t id, const gf_sftp_attrs *a)
{
  static const enum gf_sftp_type ok[] = { GF_FXP_STAT, GF_FXP_LSTAT,
                                          GF_FXP_FSTAT };
  struct outstanding_srv *o;
  struct pkt p;
  int r;

  if (s == NULL || a == NULL)
    return GF_ERR_INVAL;
  r = srv_claim (s, id, ok, 3, &o);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_ATTRS, 64);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, id);
  wr_attrs (&p.w, a);
  return srv_done (s, o, pkt_end (&s->io, &p));
}

int
gf_sftp_server_extended_reply (gf_sftp_server *s, uint32_t id,
                               const uint8_t *data, size_t len)
{
  static const enum gf_sftp_type ok[] = { GF_FXP_EXTENDED };
  struct outstanding_srv *o;
  struct pkt p;
  int r;

  if (s == NULL || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  r = srv_claim (s, id, ok, 1, &o);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_EXTENDED_REPLY, len + 8);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, id);
  gf_wr_bytes (&p.w, data, len);
  return srv_done (s, o, pkt_end (&s->io, &p));
}

/* ================================================================== */
/* Client                                                             */
/* ================================================================== */

struct outstanding_cli
{
  uint32_t id;
  enum gf_sftp_type type;
  void *tag;
  uint32_t length;		/* READ: the most the answer may carry.  */
};

struct gf_sftp_client
{
  struct io io;
  gf_sftp_client_events ev;
  unsigned max_requests;
  int started, ready;
  uint32_t next_id;
  struct outstanding_cli *out;
  unsigned nout;
};

int
gf_sftp_client_new (gf_sftp_client **out, const gf_sftp_client_config *config,
                    const gf_sftp_client_events *events)
{
  gf_sftp_client *c;

  if (out == NULL || config == NULL || events == NULL || events->write == NULL
      || events->response == NULL)
    return GF_ERR_INVAL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GF_ERR_NOMEM;
  io_init (&c->io, config->max_packet, config->max_output, events->write,
           events->user);
  c->ev = *events;
  c->max_requests = config->max_requests ? config->max_requests
                                         : DEFAULT_CLIENT_REQUESTS;
  c->out = calloc (c->max_requests, sizeof *c->out);
  if (c->out == NULL)
    {
      free (c);
      return GF_ERR_NOMEM;
    }
  c->next_id = 1;
  *out = c;
  return GF_OK;
}

void
gf_sftp_client_free (gf_sftp_client *c)
{
  if (c == NULL)
    return;
  io_free (&c->io);
  free (c->out);
  free (c);
}

size_t
gf_sftp_client_pending (const gf_sftp_client *c)
{
  return c->io.outn;
}

int
gf_sftp_client_is_ready (const gf_sftp_client *c)
{
  return c->ready && !c->io.dead;
}

static int
cli_die (gf_sftp_client *c, int status)
{
  if (!c->io.dead)
    {
      c->io.dead = 1;
      if (c->ev.disconnect)
        c->ev.disconnect (c->ev.user, status);
    }
  return status;
}

int
gf_sftp_client_writable (gf_sftp_client *c)
{
  int r;

  if (c->io.dead)
    return GF_ERR_CLOSED;
  r = io_flush (&c->io);
  if (r != GF_OK)
    cli_die (c, r);
  return r;
}

int
gf_sftp_client_start (gf_sftp_client *c)
{
  struct pkt p;
  int r;

  if (c == NULL)
    return GF_ERR_INVAL;
  if (c->started)
    return GF_ERR_STATE;
  c->started = 1;
  r = pkt_begin (&p, GF_FXP_INIT, 8);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, GF_SFTP_VERSION);
  r = pkt_end (&c->io, &p);
  return r == GF_OK ? GF_OK : cli_die (c, r);
}

int
gf_sftp_response_next_name (gf_sftp_response *r, gf_sftp_name *out)
{
  gf_reader rd;

  if (r->type != GF_FXP_NAME || r->count == 0)
    return 0;
  gf_reader_init (&rd, r->names_.data, r->names_.len);
  memset (out, 0, sizeof *out);
  if (gf_rd_text (&rd, &out->filename) != GF_OK
      || gf_rd_string (&rd, &out->longname) != GF_OK
      || rd_attrs (&rd, &out->attrs) != GF_OK)
    {
      r->count = 0;
      return 0;
    }
  r->names_.data = rd.p;
  r->names_.len = rd.len;
  r->count--;
  return 1;
}

/* Which responses a request can have.  */
static int
response_fits (enum gf_sftp_type req, uint8_t resp)
{
  if (resp == GF_FXP_STATUS)
    return 1;
  switch (req)
    {
    case GF_FXP_OPEN:
    case GF_FXP_OPENDIR:
      return resp == GF_FXP_HANDLE;
    case GF_FXP_READ:
      return resp == GF_FXP_DATA;
    case GF_FXP_LSTAT:
    case GF_FXP_FSTAT:
    case GF_FXP_STAT:
      return resp == GF_FXP_ATTRS;
    case GF_FXP_READDIR:
    case GF_FXP_REALPATH:
    case GF_FXP_READLINK:
      return resp == GF_FXP_NAME;
    case GF_FXP_EXTENDED:
      return resp == GF_FXP_EXTENDED_REPLY;
    default:
      return 0;
    }
}

static int
cli_packet (void *ctx, const uint8_t *body, size_t len)
{
  gf_sftp_client *c = ctx;
  gf_reader rd;
  uint8_t type;
  uint32_t id;
  gf_sftp_response rs;
  unsigned i;
  struct outstanding_cli o;

  gf_reader_init (&rd, body, len);
  if (gf_rd_u8 (&rd, &type) != GF_OK)
    return cli_die (c, GF_ERR_PROTOCOL);
  if (!c->ready)
    {
      uint32_t version;

      if (type != GF_FXP_VERSION || gf_rd_u32 (&rd, &version) != GF_OK)
        return cli_die (c, GF_ERR_PROTOCOL);
      if (version != GF_SFTP_VERSION)
        return cli_die (c, GF_ERR_UNSUPPORTED);
      /* Extensions (pairs of strings) are noted by nobody here.  */
      c->ready = 1;
      if (c->ev.ready && c->ev.ready (c->ev.user) != 0)
        return cli_die (c, GF_ERR_HANDLER);
      return GF_OK;
    }
  if (type < GF_FXP_STATUS || type > GF_FXP_ATTRS)
    {
      if (type != GF_FXP_EXTENDED_REPLY)
        return cli_die (c, GF_ERR_PROTOCOL);
    }
  if (gf_rd_u32 (&rd, &id) != GF_OK)
    return cli_die (c, GF_ERR_PROTOCOL);
  for (i = 0; i < c->nout; i++)
    if (c->out[i].id == id)
      break;
  if (i == c->nout || !response_fits (c->out[i].type, type))
    return cli_die (c, GF_ERR_PROTOCOL);
  o = c->out[i];
  memset (&rs, 0, sizeof rs);
  rs.id = id;
  rs.tag = o.tag;
  rs.type = (enum gf_sftp_type) type;
  switch (type)
    {
    case GF_FXP_STATUS:
      {
        gf_slice lang;

        if (gf_rd_u32 (&rd, &rs.status) != GF_OK
            || gf_rd_string (&rd, &rs.message) != GF_OK)
          return cli_die (c, GF_ERR_ENCODING);
        /* The language tag is missing from some servers' answers.  */
        if (gf_rd_remaining (&rd) > 0 && gf_rd_string (&rd, &lang) != GF_OK)
          return cli_die (c, GF_ERR_ENCODING);
        if (gf_rd_finish (&rd) != GF_OK)
          return cli_die (c, GF_ERR_ENCODING);
        break;
      }
    case GF_FXP_HANDLE:
      if (rd_handle (&rd, &rs.handle) != GF_OK || rs.handle.len == 0
          || gf_rd_finish (&rd) != GF_OK)
        return cli_die (c, GF_ERR_ENCODING);
      break;
    case GF_FXP_DATA:
      if (gf_rd_string (&rd, &rs.data) != GF_OK || gf_rd_finish (&rd) != GF_OK)
        return cli_die (c, GF_ERR_ENCODING);
      if (rs.data.len > o.length)
        return cli_die (c, GF_ERR_PROTOCOL);	/* More than was asked.  */
      break;
    case GF_FXP_ATTRS:
      if (rd_attrs (&rd, &rs.attrs) != GF_OK || gf_rd_finish (&rd) != GF_OK)
        return cli_die (c, GF_ERR_ENCODING);
      break;
    case GF_FXP_NAME:
      {
        gf_reader scan;
        uint32_t k;
        gf_sftp_name nm;

        if (gf_rd_u32 (&rd, &rs.count) != GF_OK)
          return cli_die (c, GF_ERR_ENCODING);
        rs.names_.data = rd.p;
        rs.names_.len = rd.len;
        if ((o.type != GF_FXP_READDIR && rs.count != 1) || rs.count == 0)
          return cli_die (c, GF_ERR_PROTOCOL);
        /* Every entry must parse; in a listing no name may be empty or
           hold a slash, or be "." followed by nothing odd.  */
        gf_reader_init (&scan, rd.p, rd.len);
        for (k = 0; k < rs.count; k++)
          {
            if (gf_rd_text (&scan, &nm.filename) != GF_OK
                || gf_rd_string (&scan, &nm.longname) != GF_OK
                || rd_attrs (&scan, &nm.attrs) != GF_OK)
              return cli_die (c, GF_ERR_ENCODING);
            if (o.type == GF_FXP_READDIR
                && (nm.filename.len == 0
                    || memchr (nm.filename.data, '/', nm.filename.len)))
              return cli_die (c, GF_ERR_PROTOCOL);
          }
        if (gf_rd_finish (&scan) != GF_OK)
          return cli_die (c, GF_ERR_ENCODING);
        break;
      }
    case GF_FXP_EXTENDED_REPLY:
      gf_rd_bytes (&rd, gf_rd_remaining (&rd), &rs.data);
      break;
    default:
      return cli_die (c, GF_ERR_PROTOCOL);
    }
  c->out[i] = c->out[--c->nout];
  if (c->ev.response (c->ev.user, &rs) != 0)
    return cli_die (c, GF_ERR_HANDLER);
  return GF_OK;
}

int
gf_sftp_client_input (gf_sftp_client *c, const uint8_t *data, size_t len)
{
  int r;

  if (c == NULL || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  if (c->io.dead)
    return GF_ERR_CLOSED;
  r = io_input (&c->io, data, len, cli_packet, c);
  if (r != GF_OK && !c->io.dead)
    cli_die (c, r);
  return r;
}

/* Start a request: check the state, take an id.  */
static int
cli_begin (gf_sftp_client *c, enum gf_sftp_type type, void *tag,
           uint32_t length, uint32_t *id)
{
  uint32_t n;

  if (c == NULL)
    return GF_ERR_INVAL;
  if (c->io.dead)
    return GF_ERR_CLOSED;
  if (!c->ready)
    return GF_ERR_STATE;
  if (c->nout >= c->max_requests || c->io.outn >= c->io.max_output / 2)
    return GF_ERR_AGAIN;
  n = c->next_id++;
  if (c->next_id == 0)
    c->next_id = 1;
  c->out[c->nout].id = n;
  c->out[c->nout].type = type;
  c->out[c->nout].tag = tag;
  c->out[c->nout].length = length;
  if (id)
    *id = n;
  return GF_OK;
}

/* The request packet is built; send it, or forget the id.  */
static int
cli_send (gf_sftp_client *c, struct pkt *p)
{
  int r = pkt_end (&c->io, p);

  if (r == GF_OK)
    c->nout++;
  else if (r != GF_ERR_AGAIN && r != GF_ERR_RANGE)
    cli_die (c, r);
  return r;
}

static int
cli_path (gf_sftp_client *c, enum gf_sftp_type type, const char *path,
          const gf_sftp_attrs *attrs, int with_attrs, void *tag, uint32_t *id)
{
  struct pkt p;
  uint32_t n;
  int r;

  if (path == NULL || strlen (path) > GF_SFTP_MAX_PATH)
    return GF_ERR_INVAL;
  r = cli_begin (c, type, tag, 0, &n);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, type, strlen (path) + 64);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, n);
  gf_wr_cstring (&p.w, path);
  if (with_attrs)
    wr_attrs (&p.w, attrs);
  if (id)
    *id = n;
  return cli_send (c, &p);
}

static int
cli_handle (gf_sftp_client *c, enum gf_sftp_type type, const uint8_t *h,
            size_t hl, void *tag, uint32_t *id)
{
  struct pkt p;
  uint32_t n;
  int r;

  if (h == NULL || hl == 0 || hl > GF_SFTP_MAX_HANDLE)
    return GF_ERR_INVAL;
  r = cli_begin (c, type, tag, 0, &n);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, type, hl + 16);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, n);
  gf_wr_string (&p.w, h, hl);
  if (id)
    *id = n;
  return cli_send (c, &p);
}

int
gf_sftp_client_open (gf_sftp_client *c, const char *path, uint32_t pflags,
                     const gf_sftp_attrs *attrs, void *tag, uint32_t *id)
{
  struct pkt p;
  uint32_t n;
  int r;

  if (path == NULL || strlen (path) > GF_SFTP_MAX_PATH)
    return GF_ERR_INVAL;
  r = cli_begin (c, GF_FXP_OPEN, tag, 0, &n);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_OPEN, strlen (path) + 64);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, n);
  gf_wr_cstring (&p.w, path);
  gf_wr_u32 (&p.w, pflags);
  wr_attrs (&p.w, attrs);
  if (id)
    *id = n;
  return cli_send (c, &p);
}

int
gf_sftp_client_close (gf_sftp_client *c, const uint8_t *h, size_t hl, void *tag,
                      uint32_t *id)
{
  return cli_handle (c, GF_FXP_CLOSE, h, hl, tag, id);
}

int
gf_sftp_client_read (gf_sftp_client *c, const uint8_t *h, size_t hl,
                     uint64_t offset, uint32_t length, void *tag, uint32_t *id)
{
  struct pkt p;
  uint32_t n;
  int r;

  if (h == NULL || hl == 0 || hl > GF_SFTP_MAX_HANDLE || length == 0
      || c == NULL || length + 16 > c->io.max_packet)
    return GF_ERR_INVAL;
  r = cli_begin (c, GF_FXP_READ, tag, length, &n);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_READ, hl + 32);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, n);
  gf_wr_string (&p.w, h, hl);
  gf_wr_u64 (&p.w, offset);
  gf_wr_u32 (&p.w, length);
  if (id)
    *id = n;
  return cli_send (c, &p);
}

int
gf_sftp_client_write (gf_sftp_client *c, const uint8_t *h, size_t hl,
                      uint64_t offset, const uint8_t *data, size_t len,
                      void *tag, uint32_t *id)
{
  struct pkt p;
  uint32_t n;
  int r;

  if (h == NULL || hl == 0 || hl > GF_SFTP_MAX_HANDLE
      || (data == NULL && len > 0) || c == NULL)
    return GF_ERR_INVAL;
  if (len + hl + 32 > c->io.max_packet)
    return GF_ERR_RANGE;
  r = cli_begin (c, GF_FXP_WRITE, tag, 0, &n);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_WRITE, hl + len + 32);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, n);
  gf_wr_string (&p.w, h, hl);
  gf_wr_u64 (&p.w, offset);
  gf_wr_string (&p.w, data, len);
  if (id)
    *id = n;
  return cli_send (c, &p);
}

int
gf_sftp_client_stat (gf_sftp_client *c, const char *path, void *tag,
                     uint32_t *id)
{
  return cli_path (c, GF_FXP_STAT, path, NULL, 0, tag, id);
}

int
gf_sftp_client_lstat (gf_sftp_client *c, const char *path, void *tag,
                      uint32_t *id)
{
  return cli_path (c, GF_FXP_LSTAT, path, NULL, 0, tag, id);
}

int
gf_sftp_client_fstat (gf_sftp_client *c, const uint8_t *h, size_t hl, void *tag,
                      uint32_t *id)
{
  return cli_handle (c, GF_FXP_FSTAT, h, hl, tag, id);
}

int
gf_sftp_client_setstat (gf_sftp_client *c, const char *path,
                        const gf_sftp_attrs *attrs, void *tag, uint32_t *id)
{
  return cli_path (c, GF_FXP_SETSTAT, path, attrs, 1, tag, id);
}

int
gf_sftp_client_fsetstat (gf_sftp_client *c, const uint8_t *h, size_t hl,
                         const gf_sftp_attrs *attrs, void *tag, uint32_t *id)
{
  struct pkt p;
  uint32_t n;
  int r;

  if (h == NULL || hl == 0 || hl > GF_SFTP_MAX_HANDLE)
    return GF_ERR_INVAL;
  r = cli_begin (c, GF_FXP_FSETSTAT, tag, 0, &n);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_FSETSTAT, hl + 64);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, n);
  gf_wr_string (&p.w, h, hl);
  wr_attrs (&p.w, attrs);
  if (id)
    *id = n;
  return cli_send (c, &p);
}

int
gf_sftp_client_opendir (gf_sftp_client *c, const char *path, void *tag,
                        uint32_t *id)
{
  return cli_path (c, GF_FXP_OPENDIR, path, NULL, 0, tag, id);
}

int
gf_sftp_client_readdir (gf_sftp_client *c, const uint8_t *h, size_t hl,
                        void *tag, uint32_t *id)
{
  return cli_handle (c, GF_FXP_READDIR, h, hl, tag, id);
}

int
gf_sftp_client_remove (gf_sftp_client *c, const char *path, void *tag,
                       uint32_t *id)
{
  return cli_path (c, GF_FXP_REMOVE, path, NULL, 0, tag, id);
}

int
gf_sftp_client_mkdir (gf_sftp_client *c, const char *path,
                      const gf_sftp_attrs *attrs, void *tag, uint32_t *id)
{
  return cli_path (c, GF_FXP_MKDIR, path, attrs, 1, tag, id);
}

int
gf_sftp_client_rmdir (gf_sftp_client *c, const char *path, void *tag,
                      uint32_t *id)
{
  return cli_path (c, GF_FXP_RMDIR, path, NULL, 0, tag, id);
}

int
gf_sftp_client_realpath (gf_sftp_client *c, const char *path, void *tag,
                         uint32_t *id)
{
  return cli_path (c, GF_FXP_REALPATH, path, NULL, 0, tag, id);
}

int
gf_sftp_client_readlink (gf_sftp_client *c, const char *path, void *tag,
                         uint32_t *id)
{
  return cli_path (c, GF_FXP_READLINK, path, NULL, 0, tag, id);
}

static int
cli_two (gf_sftp_client *c, enum gf_sftp_type type, const char *a,
         const char *b, void *tag, uint32_t *id)
{
  struct pkt p;
  uint32_t n;
  int r;

  if (a == NULL || b == NULL || strlen (a) > GF_SFTP_MAX_PATH
      || strlen (b) > GF_SFTP_MAX_PATH)
    return GF_ERR_INVAL;
  r = cli_begin (c, type, tag, 0, &n);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, type, strlen (a) + strlen (b) + 24);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, n);
  gf_wr_cstring (&p.w, a);
  gf_wr_cstring (&p.w, b);
  if (id)
    *id = n;
  return cli_send (c, &p);
}

int
gf_sftp_client_rename (gf_sftp_client *c, const char *from, const char *to,
                       void *tag, uint32_t *id)
{
  return cli_two (c, GF_FXP_RENAME, from, to, tag, id);
}

int
gf_sftp_client_symlink (gf_sftp_client *c, const char *linkpath,
                        const char *target, void *tag, uint32_t *id)
{
  return cli_two (c, GF_FXP_SYMLINK, target, linkpath, tag, id);
}

int
gf_sftp_client_extended (gf_sftp_client *c, const char *name,
                         const uint8_t *data, size_t len, void *tag,
                         uint32_t *id)
{
  struct pkt p;
  uint32_t n;
  int r;

  if (name == NULL || strlen (name) > GF_SFTP_MAX_PATH
      || (data == NULL && len > 0) || c == NULL)
    return GF_ERR_INVAL;
  if (len + 64 + strlen (name) > c->io.max_packet)
    return GF_ERR_RANGE;
  r = cli_begin (c, GF_FXP_EXTENDED, tag, 0, &n);
  if (r != GF_OK)
    return r;
  r = pkt_begin (&p, GF_FXP_EXTENDED, strlen (name) + len + 16);
  if (r != GF_OK)
    return r;
  gf_wr_u32 (&p.w, n);
  gf_wr_cstring (&p.w, name);
  gf_wr_bytes (&p.w, data, len);
  if (id)
    *id = n;
  return cli_send (c, &p);
}
