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
#include <foxtrot/sftp.h>

#include "tst-util.h"

/* ================================================================== */
/* A client and a server joined by two byte pipes                     */
/* ================================================================== */

struct pipe
{
  uint8_t *buf;
  size_t len, cap;
  size_t accept;		/* Take at most this many bytes per write
				   (0: all).  */
  int blocked;			/* Take none.  */
  int budget_on;
  size_t budget;		/* With budget_on: take this many in all.  */
};

static void
pipe_add (struct pipe *p, const uint8_t *d, size_t n)
{
  if (p->len + n > p->cap)
    {
      p->cap = (p->len + n) * 2;
      p->buf = realloc (p->buf, p->cap);
    }
  memcpy (p->buf + p->len, d, n);
  p->len += n;
}

/* A file system in memory.  */
struct file
{
  char name[64];
  uint8_t *data;
  size_t len;
  uint32_t perms;
  int is_dir;
  char link[64];		/* A symbolic link if not empty.  */
  int used;
};

#define MAXFILES 32
#define MAXHANDLES 16

struct handle
{
  int used;
  int file;			/* Index, or -1.  */
  int is_dir;
  size_t dir_pos;
};

struct rlog
{
  enum gf_sftp_type type;
  uint32_t id, status;
  void *tag;
  char message[64];
  uint8_t handle[GF_SFTP_MAX_HANDLE];
  size_t handle_len;
  uint8_t *data;
  size_t data_len;
  gf_sftp_attrs attrs;
  char names[16][64];
  char longnames[16][64];
  uint32_t nnames;
};

struct world
{
  gf_sftp_server *srv;
  gf_sftp_client *cli;
  struct pipe to_srv, to_cli;	/* What the client / server wrote.  */
  int srv_disconnect, cli_disconnect;
  int srv_status, cli_status;
  struct file files[MAXFILES];
  struct handle handles[MAXHANDLES];
  int hold;			/* The server does not answer; it keeps the
				   requests.  */
  uint32_t held[200];
  size_t nheld;
  gf_sftp_request last_request;
  int requests;
  int ready;

  /* The responses, copied.  */
  int got;
  size_t nresponses;
  struct rlog log[64];
};

static long
srv_write (void *user, const uint8_t *d, size_t n)
{
  struct world *w = user;
  size_t take = n;

  if (w->to_cli.blocked)
    return 0;
  if (w->to_cli.accept && take > w->to_cli.accept)
    take = w->to_cli.accept;
  if (w->to_cli.budget_on)
    {
      if (take > w->to_cli.budget)
        take = w->to_cli.budget;
      w->to_cli.budget -= take;
    }
  pipe_add (&w->to_cli, d, take);
  return (long) take;
}

static long
cli_write (void *user, const uint8_t *d, size_t n)
{
  struct world *w = user;
  size_t take = n;

  if (w->to_srv.blocked)
    return 0;
  if (w->to_srv.accept && take > w->to_srv.accept)
    take = w->to_srv.accept;
  pipe_add (&w->to_srv, d, take);
  return (long) take;
}

static int
find_file (struct world *w, gf_slice name)
{
  int i;

  for (i = 0; i < MAXFILES; i++)
    if (w->files[i].used && strlen (w->files[i].name) == name.len
        && memcmp (w->files[i].name, name.data, name.len) == 0)
      return i;
  return -1;
}

static int
new_handle (struct world *w, int file, int is_dir, uint8_t out[4])
{
  int i;

  for (i = 0; i < MAXHANDLES; i++)
    if (!w->handles[i].used)
      {
        w->handles[i].used = 1;
        w->handles[i].file = file;
        w->handles[i].is_dir = is_dir;
        w->handles[i].dir_pos = 0;
        out[0] = 'H';
        out[1] = (uint8_t) i;
        out[2] = out[3] = 0;
        return 0;
      }
  return -1;
}

static struct handle *
get_handle (struct world *w, gf_slice h)
{
  if (h.len != 4 || h.data[0] != 'H' || h.data[1] >= MAXHANDLES
      || !w->handles[h.data[1]].used)
    return NULL;
  return &w->handles[h.data[1]];
}

static int
status (struct world *w, uint32_t id, uint32_t code)
{
  return gf_sftp_server_status (w->srv, id, code, code ? "failed" : "ok")
    != GF_OK;
}

static void
fill_attrs (const struct file *f, gf_sftp_attrs *a)
{
  memset (a, 0, sizeof *a);
  a->flags = GF_FILEXFER_ATTR_SIZE | GF_FILEXFER_ATTR_PERMISSIONS;
  a->size = f->len;
  a->permissions = f->perms | (f->is_dir ? 040000 : 0100000);
}

static int
srv_request (void *user, const gf_sftp_request *q)
{
  struct world *w = user;
  int f, k;
  struct handle *h;
  uint8_t hb[4];

  w->requests++;
  w->last_request = *q;
  if (w->hold)
    {
      if (w->nheld < 200)
        w->held[w->nheld++] = q->id;
      return 0;
    }
  switch (q->type)
    {
    case GF_FXP_OPEN:
      f = find_file (w, q->path);
      if (f >= 0 && (q->pflags & GF_FXF_EXCL) && (q->pflags & GF_FXF_CREAT))
        return status (w, q->id, GF_FX_FAILURE);
      if (f < 0)
        {
          if (!(q->pflags & GF_FXF_CREAT))
            return status (w, q->id, GF_FX_NO_SUCH_FILE);
          for (k = 0; k < MAXFILES && w->files[k].used; k++)
            ;
          if (k == MAXFILES)
            return status (w, q->id, GF_FX_FAILURE);
          memset (&w->files[k], 0, sizeof w->files[k]);
          w->files[k].used = 1;
          w->files[k].perms = (q->attrs.flags & GF_FILEXFER_ATTR_PERMISSIONS)
            ? q->attrs.permissions & 0777 : 0644;
          snprintf (w->files[k].name, sizeof w->files[k].name, "%.*s",
                    (int) q->path.len, (const char *) q->path.data);
          f = k;
        }
      if (q->pflags & GF_FXF_TRUNC)
        w->files[f].len = 0;
      if (new_handle (w, f, 0, hb) < 0)
        return status (w, q->id, GF_FX_FAILURE);
      return gf_sftp_server_handle (w->srv, q->id, hb, 4) != GF_OK;
    case GF_FXP_CLOSE:
      h = get_handle (w, q->handle);
      if (h == NULL)
        return status (w, q->id, GF_FX_FAILURE);
      h->used = 0;
      return status (w, q->id, GF_FX_OK);
    case GF_FXP_READ:
      h = get_handle (w, q->handle);
      if (h == NULL || h->is_dir)
        return status (w, q->id, GF_FX_FAILURE);
      {
        struct file *fl = &w->files[h->file];
        size_t n;

        if (q->offset >= fl->len)
          return status (w, q->id, GF_FX_EOF);
        n = fl->len - (size_t) q->offset;
        if (n > q->length)
          n = q->length;
        return gf_sftp_server_data (w->srv, q->id, fl->data + q->offset, n)
          != GF_OK;
      }
    case GF_FXP_WRITE:
      h = get_handle (w, q->handle);
      if (h == NULL || h->is_dir)
        return status (w, q->id, GF_FX_FAILURE);
      {
        struct file *fl = &w->files[h->file];
        size_t end = (size_t) q->offset + q->data.len;

        if (end > fl->len)
          {
            fl->data = realloc (fl->data, end);
            memset (fl->data + fl->len, 0, end - fl->len);
            fl->len = end;
          }
        memcpy (fl->data + q->offset, q->data.data, q->data.len);
        return status (w, q->id, GF_FX_OK);
      }
    case GF_FXP_STAT:
    case GF_FXP_LSTAT:
      f = find_file (w, q->path);
      if (f < 0)
        return status (w, q->id, GF_FX_NO_SUCH_FILE);
      {
        gf_sftp_attrs a;

        fill_attrs (&w->files[f], &a);
        return gf_sftp_server_attrs (w->srv, q->id, &a) != GF_OK;
      }
    case GF_FXP_FSTAT:
      h = get_handle (w, q->handle);
      if (h == NULL)
        return status (w, q->id, GF_FX_FAILURE);
      {
        gf_sftp_attrs a;

        fill_attrs (&w->files[h->file], &a);
        return gf_sftp_server_attrs (w->srv, q->id, &a) != GF_OK;
      }
    case GF_FXP_SETSTAT:
      f = find_file (w, q->path);
      if (f < 0)
        return status (w, q->id, GF_FX_NO_SUCH_FILE);
      if (q->attrs.flags & GF_FILEXFER_ATTR_PERMISSIONS)
        w->files[f].perms = q->attrs.permissions & 0777;
      return status (w, q->id, GF_FX_OK);
    case GF_FXP_OPENDIR:
      f = find_file (w, q->path);
      if (q->path.len == 1 && q->path.data[0] == '/')
        f = -2;
      else if (f < 0 || !w->files[f].is_dir)
        return status (w, q->id, GF_FX_NO_SUCH_FILE);
      if (new_handle (w, f, 1, hb) < 0)
        return status (w, q->id, GF_FX_FAILURE);
      return gf_sftp_server_handle (w->srv, q->id, hb, 4) != GF_OK;
    case GF_FXP_READDIR:
      h = get_handle (w, q->handle);
      if (h == NULL || !h->is_dir)
        return status (w, q->id, GF_FX_FAILURE);
      {
        gf_sftp_name names[2];
        char longs[2][80];
        size_t n = 0;

        while (n < 2 && h->dir_pos < MAXFILES)
          {
            struct file *fl = &w->files[h->dir_pos++];

            if (!fl->used)
              continue;
            snprintf (longs[n], sizeof longs[n], "-rw-r--r-- 1 u g %zu %s",
                      fl->len, fl->name);
            names[n].filename.data = (const uint8_t *) fl->name;
            names[n].filename.len = strlen (fl->name);
            names[n].longname.data = (const uint8_t *) longs[n];
            names[n].longname.len = strlen (longs[n]);
            fill_attrs (fl, &names[n].attrs);
            n++;
          }
        if (n == 0)
          return status (w, q->id, GF_FX_EOF);
        return gf_sftp_server_names (w->srv, q->id, n, names) != GF_OK;
      }
    case GF_FXP_REMOVE:
    case GF_FXP_RMDIR:
      f = find_file (w, q->path);
      if (f < 0)
        return status (w, q->id, GF_FX_NO_SUCH_FILE);
      w->files[f].used = 0;
      free (w->files[f].data);
      w->files[f].data = NULL;
      return status (w, q->id, GF_FX_OK);
    case GF_FXP_MKDIR:
      for (k = 0; k < MAXFILES && w->files[k].used; k++)
        ;
      if (k == MAXFILES || find_file (w, q->path) >= 0)
        return status (w, q->id, GF_FX_FAILURE);
      memset (&w->files[k], 0, sizeof w->files[k]);
      w->files[k].used = 1;
      w->files[k].is_dir = 1;
      w->files[k].perms = 0755;
      snprintf (w->files[k].name, sizeof w->files[k].name, "%.*s",
                (int) q->path.len, (const char *) q->path.data);
      return status (w, q->id, GF_FX_OK);
    case GF_FXP_RENAME:
      f = find_file (w, q->path);
      if (f < 0)
        return status (w, q->id, GF_FX_NO_SUCH_FILE);
      snprintf (w->files[f].name, sizeof w->files[f].name, "%.*s",
                (int) q->path2.len, (const char *) q->path2.data);
      return status (w, q->id, GF_FX_OK);
    case GF_FXP_REALPATH:
      {
        gf_sftp_name nm;
        char buf[80];

        snprintf (buf, sizeof buf, "/%.*s", (int) q->path.len,
                  (const char *) q->path.data);
        nm.filename.data = (const uint8_t *) buf;
        nm.filename.len = strlen (buf);
        nm.longname = nm.filename;
        memset (&nm.attrs, 0, sizeof nm.attrs);
        return gf_sftp_server_names (w->srv, q->id, 1, &nm) != GF_OK;
      }
    case GF_FXP_SYMLINK:
      for (k = 0; k < MAXFILES && w->files[k].used; k++)
        ;
      if (k == MAXFILES)
        return status (w, q->id, GF_FX_FAILURE);
      memset (&w->files[k], 0, sizeof w->files[k]);
      w->files[k].used = 1;
      snprintf (w->files[k].name, sizeof w->files[k].name, "%.*s",
                (int) q->path.len, (const char *) q->path.data);
      snprintf (w->files[k].link, sizeof w->files[k].link, "%.*s",
                (int) q->path2.len, (const char *) q->path2.data);
      return status (w, q->id, GF_FX_OK);
    case GF_FXP_READLINK:
      f = find_file (w, q->path);
      if (f < 0 || !w->files[f].link[0])
        return status (w, q->id, GF_FX_NO_SUCH_FILE);
      {
        gf_sftp_name nm;

        nm.filename.data = (const uint8_t *) w->files[f].link;
        nm.filename.len = strlen (w->files[f].link);
        nm.longname = nm.filename;
        memset (&nm.attrs, 0, sizeof nm.attrs);
        return gf_sftp_server_names (w->srv, q->id, 1, &nm) != GF_OK;
      }
    case GF_FXP_EXTENDED:
      if (q->ext_name.len == 7 && memcmp (q->ext_name.data, "echo@te", 7) == 0)
        return gf_sftp_server_extended_reply (w->srv, q->id, q->ext_data.data,
                                              q->ext_data.len) != GF_OK;
      return status (w, q->id, GF_FX_OP_UNSUPPORTED);
    default:
      return status (w, q->id, GF_FX_OP_UNSUPPORTED);
    }
}

static void
srv_disconnect (void *user, int st)
{
  struct world *w = user;

  w->srv_disconnect++;
  w->srv_status = st;
}

static void
cli_disconnect (void *user, int st)
{
  struct world *w = user;

  w->cli_disconnect++;
  w->cli_status = st;
}

static int
cli_ready (void *user)
{
  ((struct world *) user)->ready = 1;
  return 0;
}

static int
cli_response (void *user, const gf_sftp_response *rr)
{
  struct world *w = user;
  gf_sftp_response copy = *rr;
  gf_sftp_name nm;
  struct rlog *r = &w->log[w->nresponses < 64 ? w->nresponses : 63];

  memset (r, 0, sizeof *r);
  r->type = rr->type;
  r->id = rr->id;
  r->tag = rr->tag;
  r->status = rr->status;
  snprintf (r->message, sizeof r->message, "%.*s", (int) rr->message.len,
            (const char *) rr->message.data);
  if (rr->handle.len <= sizeof r->handle)
    memcpy (r->handle, rr->handle.data, rr->handle.len);
  r->handle_len = rr->handle.len;
  r->data = malloc (rr->data.len + 1);
  memcpy (r->data, rr->data.data, rr->data.len);
  r->data_len = rr->data.len;
  r->attrs = rr->attrs;
  while (r->nnames < 16 && gf_sftp_response_next_name (&copy, &nm))
    {
      snprintf (r->names[r->nnames], 64, "%.*s", (int) nm.filename.len,
                (const char *) nm.filename.data);
      snprintf (r->longnames[r->nnames], 64, "%.*s", (int) nm.longname.len,
                (const char *) nm.longname.data);
      r->nnames++;
    }
  w->nresponses++;
  w->got = 1;
  return 0;
}

static void
world_new (struct world *w, const gf_sftp_server_config *sc,
           const gf_sftp_client_config *cc)
{
  gf_sftp_server_events se;
  gf_sftp_client_events ce;

  memset (w, 0, sizeof *w);
  memset (&se, 0, sizeof se);
  memset (&ce, 0, sizeof ce);
  se.user = w;
  se.write = srv_write;
  se.request = srv_request;
  se.disconnect = srv_disconnect;
  ce.user = w;
  ce.write = cli_write;
  ce.ready = cli_ready;
  ce.response = cli_response;
  ce.disconnect = cli_disconnect;
  CHECK_EQ (gf_sftp_server_new (&w->srv, sc, &se), GF_OK);
  CHECK_EQ (gf_sftp_client_new (&w->cli, cc, &ce), GF_OK);
}

static void
world_free (struct world *w)
{
  size_t i;

  gf_sftp_server_free (w->srv);
  gf_sftp_client_free (w->cli);
  free (w->to_srv.buf);
  free (w->to_cli.buf);
  for (i = 0; i < MAXFILES; i++)
    free (w->files[i].data);
  for (i = 0; i < 64; i++)
    free (w->log[i].data);
}

/* Move all pending bytes both ways, in pieces of CHUNK (0: whole).  */
static void
pump (struct world *w, size_t chunk)
{
  int guard = 0;

  while ((w->to_srv.len || w->to_cli.len) && guard++ < 100000)
    {
      size_t n;

      if (w->to_srv.len)
        {
          n = chunk && chunk < w->to_srv.len ? chunk : w->to_srv.len;
          memmove (w->to_srv.buf, w->to_srv.buf, w->to_srv.len);
          {
            uint8_t *copy = malloc (n);

            memcpy (copy, w->to_srv.buf, n);
            memmove (w->to_srv.buf, w->to_srv.buf + n, w->to_srv.len - n);
            w->to_srv.len -= n;
            (void) gf_sftp_server_input (w->srv, copy, n);
            free (copy);
          }
        }
      if (w->to_cli.len)
        {
          n = chunk && chunk < w->to_cli.len ? chunk : w->to_cli.len;
          {
            uint8_t *copy = malloc (n);

            memcpy (copy, w->to_cli.buf, n);
            memmove (w->to_cli.buf, w->to_cli.buf + n, w->to_cli.len - n);
            w->to_cli.len -= n;
            (void) gf_sftp_client_input (w->cli, copy, n);
            free (copy);
          }
        }
    }
}

static void
start (struct world *w, size_t chunk)
{
  CHECK_EQ (gf_sftp_client_start (w->cli), GF_OK);
  pump (w, chunk);
  CHECK (w->ready);
  CHECK (gf_sftp_client_is_ready (w->cli));
}

/* Wait for the next response (they arrive in order of the log).  */
static int
await (struct world *w, size_t chunk)
{
  size_t before = w->nresponses;

  pump (w, chunk);
  return w->nresponses > before;
}

#define LAST(w) ((w)->log[(w)->nresponses - 1])

/* A call and its response.  */
static int
call_open (struct world *w, const char *path, uint32_t pflags, size_t chunk)
{
  gf_sftp_attrs a;

  memset (&a, 0, sizeof a);
  a.flags = GF_FILEXFER_ATTR_PERMISSIONS;
  a.permissions = 0600;
  CHECK_EQ (gf_sftp_client_open (w->cli, path, pflags, &a, NULL, NULL), GF_OK);
  return await (w, chunk);
}

/* ---------------------------------------------------------------- */

static void
test_lifecycle (size_t chunk)
{
  struct world w;
  uint8_t h[GF_SFTP_MAX_HANDLE];
  size_t hl;
  static uint8_t buf[300];
  size_t i;
  gf_sftp_attrs a;

  world_new (&w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 0, 0 });
  /* Requests wait for the version.  */
  CHECK_EQ (gf_sftp_client_stat (w.cli, "x", NULL, NULL), GF_ERR_STATE);
  start (&w, chunk);
  CHECK_EQ (gf_sftp_client_start (w.cli), GF_ERR_STATE);

  CHECK (call_open (&w, "a.txt", GF_FXF_WRITE | GF_FXF_CREAT, chunk));
  CHECK_EQ (LAST (&w).type, GF_FXP_HANDLE);
  hl = LAST (&w).handle_len;
  memcpy (h, LAST (&w).handle, hl);
  CHECK_EQ (hl, 4);
  CHECK_EQ (w.last_request.pflags, GF_FXF_WRITE | GF_FXF_CREAT);
  CHECK (w.last_request.attrs.flags & GF_FILEXFER_ATTR_PERMISSIONS);
  CHECK_EQ (w.last_request.attrs.permissions, 0600);

  for (i = 0; i < sizeof buf; i++)
    buf[i] = (uint8_t) (i * 5);
  CHECK_EQ (gf_sftp_client_write (w.cli, h, hl, 0, buf, 100, NULL, NULL), GF_OK);
  CHECK_EQ (gf_sftp_client_write (w.cli, h, hl, 100, buf + 100, 200, NULL, NULL),
            GF_OK);
  CHECK (await (&w, chunk));
  pump (&w, chunk);
  CHECK_EQ (w.nresponses, 3);		/* Handle, and two statuses.  */
  CHECK_EQ (LAST (&w).type, GF_FXP_STATUS);
  CHECK_EQ (LAST (&w).status, GF_FX_OK);
  CHECK_EQ (w.files[0].len, 300);
  CHECK (memcmp (w.files[0].data, buf, 300) == 0);

  CHECK_EQ (gf_sftp_client_fstat (w.cli, h, hl, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).type, GF_FXP_ATTRS);
  CHECK_EQ (LAST (&w).attrs.size, 300);
  CHECK (LAST (&w).attrs.flags & GF_FILEXFER_ATTR_SIZE);
  CHECK_EQ (gf_sftp_client_close (w.cli, h, hl, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).status, GF_FX_OK);

  /* Read it back in pieces, then at the end.  */
  CHECK (call_open (&w, "a.txt", GF_FXF_READ, chunk));
  memcpy (h, LAST (&w).handle, 4);
  CHECK_EQ (gf_sftp_client_read (w.cli, h, 4, 50, 100, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).type, GF_FXP_DATA);
  CHECK (LAST (&w).data_len == 100 && memcmp (LAST (&w).data, buf + 50, 100) == 0);
  CHECK_EQ (gf_sftp_client_read (w.cli, h, 4, 250, 100, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).data_len, 50);	/* A short read.  */
  CHECK_EQ (gf_sftp_client_read (w.cli, h, 4, 300, 100, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).type, GF_FXP_STATUS);
  CHECK_EQ (LAST (&w).status, GF_FX_EOF);
  CHECK_EQ (gf_sftp_client_close (w.cli, h, 4, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));

  /* Stat, setstat, rename, listing.  */
  CHECK_EQ (gf_sftp_client_stat (w.cli, "a.txt", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).attrs.permissions & 0777, 0600);
  memset (&a, 0, sizeof a);
  a.flags = GF_FILEXFER_ATTR_PERMISSIONS;
  a.permissions = 0640;
  CHECK_EQ (gf_sftp_client_setstat (w.cli, "a.txt", &a, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (w.files[0].perms, 0640);
  CHECK_EQ (gf_sftp_client_stat (w.cli, "nope", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).status, GF_FX_NO_SUCH_FILE);
  CHECK_EQ (gf_sftp_client_rename (w.cli, "a.txt", "b.txt", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK (strcmp (w.files[0].name, "b.txt") == 0);
  CHECK_EQ (gf_sftp_client_mkdir (w.cli, "d", NULL, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (gf_sftp_client_symlink (w.cli, "lnk", "b.txt", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (w.last_request.type, GF_FXP_SYMLINK);
  CHECK (w.last_request.path.len == 3 && w.last_request.path2.len == 5);
  CHECK_EQ (gf_sftp_client_readlink (w.cli, "lnk", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).type, GF_FXP_NAME);
  CHECK (LAST (&w).nnames == 1 && strcmp (LAST (&w).names[0], "b.txt") == 0);
  CHECK_EQ (gf_sftp_client_realpath (w.cli, "x/y", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK (strcmp (LAST (&w).names[0], "/x/y") == 0);

  CHECK_EQ (gf_sftp_client_opendir (w.cli, "/", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  memcpy (h, LAST (&w).handle, 4);
  {
    uint32_t seen = 0;
    int rounds = 0;

    for (;;)
      {
        CHECK_EQ (gf_sftp_client_readdir (w.cli, h, 4, NULL, NULL), GF_OK);
        CHECK (await (&w, chunk));
        if (LAST (&w).type == GF_FXP_STATUS || rounds++ > 10)
          break;
        seen += LAST (&w).nnames;
        CHECK (strstr (LAST (&w).longnames[0], "-rw") == LAST (&w).longnames[0]);
      }
    CHECK_EQ (LAST (&w).status, GF_FX_EOF);
    CHECK_EQ (seen, 3);			/* b.txt, d, lnk: in batches of two.  */
  }
  CHECK_EQ (gf_sftp_client_close (w.cli, h, 4, NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));

  CHECK_EQ (gf_sftp_client_remove (w.cli, "b.txt", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (gf_sftp_client_rmdir (w.cli, "d", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (gf_sftp_client_remove (w.cli, "b.txt", NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).status, GF_FX_NO_SUCH_FILE);

  /* Extensions: one the server knows, one it does not.  */
  CHECK_EQ (gf_sftp_client_extended (w.cli, "echo@te", (const uint8_t *) "abc", 3,
                                     NULL, NULL), GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).type, GF_FXP_EXTENDED_REPLY);
  CHECK (LAST (&w).data_len == 3 && memcmp (LAST (&w).data, "abc", 3) == 0);
  CHECK_EQ (gf_sftp_client_extended (w.cli, "bogus@te", NULL, 0, NULL, NULL),
            GF_OK);
  CHECK (await (&w, chunk));
  CHECK_EQ (LAST (&w).status, GF_FX_OP_UNSUPPORTED);
  CHECK_EQ (w.srv_disconnect + w.cli_disconnect, 0);
  world_free (&w);
}

static void
test_chunking (void)
{
  static const size_t chunks[] = { 0, 1, 2, 3, 5, 7, 16, 100, 1000 };
  size_t i;

  for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++)
    test_lifecycle (chunks[i]);
}

/* Many requests at once, answered in order, each with its own tag; and
   the limit on how many.  */
static void
test_pipelining (void)
{
  struct world w;
  uint8_t h[4];
  uintptr_t i;
  size_t k;

  world_new (&w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 8, 0 });
  start (&w, 0);
  CHECK (call_open (&w, "f", GF_FXF_WRITE | GF_FXF_CREAT, 0));
  memcpy (h, LAST (&w).handle, 4);
  for (i = 1; i <= 8; i++)
    CHECK_EQ (gf_sftp_client_write (w.cli, h, 4, i * 10, (const uint8_t *) "0123456789",
                                    10, (void *) i, NULL), GF_OK);
  /* The ninth must wait.  */
  CHECK_EQ (gf_sftp_client_write (w.cli, h, 4, 0, (const uint8_t *) "x", 1,
                                  NULL, NULL), GF_ERR_AGAIN);
  pump (&w, 0);
  CHECK_EQ (w.nresponses, 9);
  for (k = 1; k <= 8; k++)
    CHECK_EQ ((uintptr_t) w.log[k].tag, k);
  CHECK_EQ (gf_sftp_client_write (w.cli, h, 4, 0, (const uint8_t *) "x", 1,
                                  NULL, NULL), GF_OK);
  pump (&w, 0);
  world_free (&w);
}

/* ---------------------------------------------------------------- */
/* Hand-made packets                                                 */
/* ---------------------------------------------------------------- */

static size_t
pkt (uint8_t *buf, size_t cap, uint8_t type, const uint8_t *body, size_t n)
{
  gf_writer w;

  gf_writer_init (&w, buf, cap);
  gf_wr_u32 (&w, (uint32_t) (n + 1));
  gf_wr_u8 (&w, type);
  gf_wr_bytes (&w, body, n);
  return w.len;
}

static void
srv_feed (struct world *w, const uint8_t *p, size_t n)
{
  (void) gf_sftp_server_input (w->srv, p, n);
}

/* A server that has had INIT.  */
static void
srv_ready (struct world *w, const gf_sftp_server_config *sc)
{
  uint8_t b[64];
  uint8_t v[4] = { 0, 0, 0, 3 };
  size_t n = pkt (b, sizeof b, GF_FXP_INIT, v, 4);

  world_new (w, sc, &(gf_sftp_client_config) { 0, 0, 0 });
  srv_feed (w, b, n);
  CHECK_EQ (w->to_cli.len, 9);		/* VERSION 3.  */
  CHECK_EQ (w->to_cli.buf[4], GF_FXP_VERSION);
  w->to_cli.len = 0;
}

static void
test_server_protocol (void)
{
  struct world w;
  uint8_t b[600], body[600];
  size_t n, i;
  gf_writer bw;

  /* Not INIT first; INIT twice; an old version; broken lengths.  */
  world_new (&w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 0, 0 });
  {
    uint8_t one[] = { 0, 0, 0, 5 };

    n = pkt (b, sizeof b, GF_FXP_STAT, one, 4);
    srv_feed (&w, b, n);
    CHECK_EQ (w.srv_disconnect, 1);
    CHECK_EQ (gf_sftp_server_input (w.srv, b, n), GF_ERR_CLOSED);
  }
  world_free (&w);

  srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
  {
    uint8_t v[4] = { 0, 0, 0, 3 };

    n = pkt (b, sizeof b, GF_FXP_INIT, v, 4);
    srv_feed (&w, b, n);
    CHECK_EQ (w.srv_disconnect, 1);
  }
  world_free (&w);

  world_new (&w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 0, 0 });
  {
    uint8_t v[4] = { 0, 0, 0, 2 };

    n = pkt (b, sizeof b, GF_FXP_INIT, v, 4);
    srv_feed (&w, b, n);
    CHECK_EQ (w.srv_disconnect, 1);
    CHECK_EQ (w.srv_status, GF_ERR_UNSUPPORTED);
  }
  world_free (&w);

  /* A client may offer a newer version: it gets 3.  */
  world_new (&w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 0, 0 });
  {
    uint8_t v[4] = { 0, 0, 0, 6 };

    n = pkt (b, sizeof b, GF_FXP_INIT, v, 4);
    srv_feed (&w, b, n);
    CHECK_EQ (w.srv_disconnect, 0);
    CHECK_EQ (w.to_cli.buf[8], 3);
  }
  world_free (&w);

  {
    static const uint8_t lens[][4] = {
      { 0, 0, 0, 0 }, { 0xff, 0xff, 0xff, 0xff }, { 0, 4, 0, 1 }
    };

    for (i = 0; i < 3; i++)
      {
        srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
        srv_feed (&w, lens[i], 4);	/* Refused before any body.  */
        CHECK_EQ (w.srv_disconnect, 1);
        CHECK_EQ (w.srv_status, GF_ERR_PROTOCOL);
        world_free (&w);
      }
  }
  /* The limit is configurable, and exact.  */
  srv_ready (&w, &(gf_sftp_server_config) { 100, 0, 0 });
  {
    uint8_t big[4] = { 0, 0, 0, 101 };

    srv_feed (&w, big, 4);
    CHECK_EQ (w.srv_disconnect, 1);
  }
  world_free (&w);

  /* Responses and other things a client must not send.  */
  {
    static const uint8_t types[] = { GF_FXP_VERSION, GF_FXP_STATUS,
                                     GF_FXP_HANDLE, GF_FXP_DATA, GF_FXP_NAME,
                                     GF_FXP_ATTRS, GF_FXP_EXTENDED_REPLY,
                                     GF_FXP_INIT };

    for (i = 0; i < sizeof types; i++)
      {
        uint8_t body0[8] = { 0, 0, 0, 1, 0, 0, 0, 0 };

        srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
        n = pkt (b, sizeof b, types[i], body0, 8);
        srv_feed (&w, b, n);
        CHECK_EQ (w.srv_disconnect, 1);
        world_free (&w);
      }
  }
  /* A packet with no id.  */
  srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
  n = pkt (b, sizeof b, GF_FXP_STAT, (const uint8_t *) "ab", 2);
  srv_feed (&w, b, n);
  CHECK_EQ (w.srv_disconnect, 1);
  world_free (&w);

  /* Malformed requests that have an id are answered, not fatal.  */
  {
    struct
    {
      const char *what;
      int kind;
    } cases[] = {
      { "OPEN truncated", 0 }, { "OPEN with trailing bytes", 1 },
      { "STAT path with a NUL", 2 }, { "CLOSE handle over 256 bytes", 3 },
      { "OPEN attrs with unknown flag bits", 4 },
      { "STAT with a path over 4096 bytes", 5 },
      { "READ without length", 6 },
      { "an unknown request type", 7 }
    };

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
      {
        uint8_t type = GF_FXP_STAT;
        uint32_t want = GF_FX_BAD_MESSAGE;

        srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
        gf_writer_init (&bw, body, sizeof body);
        gf_wr_u32 (&bw, 77);
        switch (cases[i].kind)
          {
          case 0:
            type = GF_FXP_OPEN;
            gf_wr_cstring (&bw, "x");
            break;
          case 1:
            type = GF_FXP_STAT;
            gf_wr_cstring (&bw, "x");
            gf_wr_u8 (&bw, 0);
            break;
          case 2:
            gf_wr_string (&bw, "a\0b", 3);
            break;
          case 3:
            type = GF_FXP_CLOSE;
            {
              static uint8_t h[257];

              gf_wr_string (&bw, h, sizeof h);
            }
            break;
          case 4:
            type = GF_FXP_MKDIR;
            gf_wr_cstring (&bw, "d");
            gf_wr_u32 (&bw, 0x100);
            break;
          case 5:
            {
              static char longp[4200];

              memset (longp, 'a', sizeof longp);
              gf_wr_string (&bw, longp, sizeof longp);
            }
            break;
          case 6:
            type = GF_FXP_READ;
            gf_wr_cstring (&bw, "hhhh");
            gf_wr_u64 (&bw, 0);
            break;
          default:
            type = 150;
            want = GF_FX_OP_UNSUPPORTED;
            break;
          }
        {
          static uint8_t big[8192];

          if (cases[i].kind == 3 || cases[i].kind == 5)
            {
              gf_writer w2;

              gf_writer_init (&w2, big, sizeof big);
              gf_wr_u32 (&w2, (uint32_t) (bw.len + 1));
              gf_wr_u8 (&w2, type);
              gf_wr_bytes (&w2, body, bw.len);
              n = w2.len;
              memcpy (b, big, n < sizeof b ? n : sizeof b);
              srv_feed (&w, big, n);
            }
          else
            {
              n = pkt (b, sizeof b, type, body, bw.len);
              srv_feed (&w, b, n);
            }
        }
        if (w.srv_disconnect)
          fprintf (stderr, "fatal: %s\n", cases[i].what);
        CHECK_EQ (w.srv_disconnect, 0);
        CHECK_EQ (w.requests, 0);	/* The application never saw it.  */
        CHECK (w.to_cli.len >= 17 && w.to_cli.buf[4] == GF_FXP_STATUS);
        CHECK_EQ (w.to_cli.buf[8], 77);
        CHECK_EQ (((uint32_t) w.to_cli.buf[9] << 24 | w.to_cli.buf[10] << 16
                   | w.to_cli.buf[11] << 8 | w.to_cli.buf[12]), want);
        /* And the session still works.  */
        gf_writer_init (&bw, body, sizeof body);
        gf_wr_u32 (&bw, 78);
        gf_wr_cstring (&bw, "fine");
        n = pkt (b, sizeof b, GF_FXP_STAT, body, bw.len);
        srv_feed (&w, b, n);
        CHECK_EQ (w.requests, 1);
        world_free (&w);
      }
  }

  /* Extended requests carry their data through.  */
  srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
  gf_writer_init (&bw, body, sizeof body);
  gf_wr_u32 (&bw, 5);
  gf_wr_cstring (&bw, "posix-rename@openssh.com");
  gf_wr_cstring (&bw, "old");
  gf_wr_cstring (&bw, "new");
  n = pkt (b, sizeof b, GF_FXP_EXTENDED, body, bw.len);
  srv_feed (&w, b, n);
  CHECK_EQ (w.requests, 1);
  CHECK_EQ (w.last_request.type, GF_FXP_EXTENDED);
  CHECK (w.last_request.ext_name.len == 24);
  CHECK_EQ (w.last_request.ext_data.len, 14);
  world_free (&w);

  /* A request id in use.  */
  srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
  w.hold = 1;
  gf_writer_init (&bw, body, sizeof body);
  gf_wr_u32 (&bw, 9);
  gf_wr_cstring (&bw, "p");
  n = pkt (b, sizeof b, GF_FXP_STAT, body, bw.len);
  srv_feed (&w, b, n);
  CHECK_EQ (w.requests, 1);
  CHECK_EQ (w.srv_disconnect, 0);
  srv_feed (&w, b, n);
  CHECK_EQ (w.srv_disconnect, 1);
  CHECK_EQ (w.requests, 1);
  world_free (&w);

  /* Too many unanswered.  */
  srv_ready (&w, &(gf_sftp_server_config) { 0, 3, 0 });
  w.hold = 1;
  for (i = 1; i <= 3; i++)
    {
      gf_writer_init (&bw, body, sizeof body);
      gf_wr_u32 (&bw, (uint32_t) i);
      gf_wr_cstring (&bw, "p");
      n = pkt (b, sizeof b, GF_FXP_STAT, body, bw.len);
      srv_feed (&w, b, n);
    }
  CHECK_EQ (w.requests, 3);
  CHECK_EQ (w.srv_disconnect, 0);
  srv_feed (&w, b, n);			/* The id 3 again.  */
  CHECK_EQ (w.srv_disconnect, 1);
  world_free (&w);
  srv_ready (&w, &(gf_sftp_server_config) { 0, 3, 0 });
  w.hold = 1;
  for (i = 1; i <= 4 && !w.srv_disconnect; i++)
    {
      gf_writer_init (&bw, body, sizeof body);
      gf_wr_u32 (&bw, (uint32_t) i);
      gf_wr_cstring (&bw, "p");
      n = pkt (b, sizeof b, GF_FXP_STAT, body, bw.len);
      srv_feed (&w, b, n);
    }
  CHECK_EQ (w.srv_disconnect, 1);
  CHECK_EQ (w.requests, 3);
  world_free (&w);
}

static void
test_server_responses (void)
{
  struct world w;
  uint8_t b[600], body[600];
  gf_writer bw;
  size_t n;
  gf_sftp_name nm;
  gf_sftp_attrs a;
  uint8_t h[300];

  memset (h, 1, sizeof h);
  memset (&a, 0, sizeof a);
  memset (&nm, 0, sizeof nm);
  srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
  w.hold = 1;
  /* Requests of several kinds, unanswered: OPEN 1, READ 2, STAT 3,
     READDIR 4, REALPATH 5, CLOSE 6, EXTENDED 7.  */
  {
    static const struct
    {
      uint8_t type;
      int shape;
    } reqs[] = {
      { GF_FXP_OPEN, 0 }, { GF_FXP_READ, 1 }, { GF_FXP_STAT, 2 },
      { GF_FXP_READDIR, 3 }, { GF_FXP_REALPATH, 2 }, { GF_FXP_CLOSE, 3 },
      { GF_FXP_EXTENDED, 4 }
    };
    size_t i;

    for (i = 0; i < sizeof reqs / sizeof reqs[0]; i++)
      {
        gf_writer_init (&bw, body, sizeof body);
        gf_wr_u32 (&bw, (uint32_t) i + 1);
        switch (reqs[i].shape)
          {
          case 0:
            gf_wr_cstring (&bw, "f");
            gf_wr_u32 (&bw, GF_FXF_READ);
            gf_wr_u32 (&bw, 0);
            break;
          case 1:
            gf_wr_cstring (&bw, "hhhh");
            gf_wr_u64 (&bw, 0);
            gf_wr_u32 (&bw, 10);
            break;
          case 2:
            gf_wr_cstring (&bw, "p");
            break;
          case 3:
            gf_wr_cstring (&bw, "hhhh");
            break;
          default:
            gf_wr_cstring (&bw, "x@y");
            break;
          }
        n = pkt (b, sizeof b, reqs[i].type, body, bw.len);
        srv_feed (&w, b, n);
      }
    CHECK_EQ (w.requests, 7);
  }
  nm.filename.data = (const uint8_t *) "n";
  nm.filename.len = 1;
  nm.longname = nm.filename;
  /* The wrong kind of answer for a request is refused and the request
     stays open.  */
  CHECK_EQ (gf_sftp_server_data (w.srv, 1, h, 3), GF_ERR_INVAL);	/* To OPEN. */
  CHECK_EQ (gf_sftp_server_handle (w.srv, 2, h, 4), GF_ERR_INVAL);	/* To READ. */
  CHECK_EQ (gf_sftp_server_attrs (w.srv, 4, &a), GF_ERR_INVAL);		/* READDIR. */
  CHECK_EQ (gf_sftp_server_names (w.srv, 3, 1, &nm), GF_ERR_INVAL);	/* STAT. */
  CHECK_EQ (gf_sftp_server_extended_reply (w.srv, 6, h, 1), GF_ERR_INVAL);
  CHECK_EQ (gf_sftp_server_handle (w.srv, 6, h, 1), GF_ERR_INVAL);	/* CLOSE. */
  /* REALPATH takes exactly one name.  */
  {
    gf_sftp_name two[2] = { nm, nm };

    CHECK_EQ (gf_sftp_server_names (w.srv, 5, 2, two), GF_ERR_INVAL);
    CHECK_EQ (gf_sftp_server_names (w.srv, 5, 0, two), GF_ERR_INVAL);
    CHECK_EQ (gf_sftp_server_names (w.srv, 4, 2, two), GF_OK);	/* READDIR may.  */
  }
  /* Handles are 1 to 256 bytes.  */
  CHECK_EQ (gf_sftp_server_handle (w.srv, 1, h, 257), GF_ERR_INVAL);
  CHECK_EQ (gf_sftp_server_handle (w.srv, 1, h, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_sftp_server_handle (w.srv, 1, h, 256), GF_OK);
  /* An id that was never asked, or has been answered.  */
  CHECK_EQ (gf_sftp_server_status (w.srv, 99, 0, "ok"), GF_ERR_STATE);
  CHECK_EQ (gf_sftp_server_status (w.srv, 1, 0, "ok"), GF_ERR_STATE);
  /* Data longer than a packet may be.  */
  {
    static uint8_t huge[GF_SFTP_DEFAULT_MAX_PACKET];

    CHECK_EQ (gf_sftp_server_data (w.srv, 2, huge, sizeof huge), GF_ERR_RANGE);
    CHECK_EQ (gf_sftp_server_data (w.srv, 2, huge, 1000), GF_OK);
  }
  CHECK_EQ (gf_sftp_server_attrs (w.srv, 3, &a), GF_OK);
  CHECK_EQ (gf_sftp_server_names (w.srv, 5, 1, &nm), GF_OK);
  CHECK_EQ (gf_sftp_server_status (w.srv, 6, 0, "ok"), GF_OK);
  CHECK_EQ (gf_sftp_server_extended_reply (w.srv, 7, h, 5), GF_OK);
  CHECK_EQ (w.srv_disconnect, 0);
  world_free (&w);
}

/* The peer that does not read: output is kept, up to a limit, and sent
   when it can take it.  */
static void
test_output_limits (void)
{
  struct world w;
  uint8_t b[600], body[600];
  gf_writer bw;
  size_t n, i, want = 0;
  static uint8_t data[40000];

  srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 100000 });
  w.to_cli.blocked = 1;
  w.hold = 1;
  for (i = 1; i <= 4; i++)
    {
      gf_writer_init (&bw, body, sizeof body);
      gf_wr_u32 (&bw, (uint32_t) i);
      gf_wr_cstring (&bw, "hhhh");
      gf_wr_u64 (&bw, 0);
      gf_wr_u32 (&bw, 40000);
      n = pkt (b, sizeof b, GF_FXP_READ, body, bw.len);
      srv_feed (&w, b, n);
    }
  CHECK_EQ (gf_sftp_server_data (w.srv, 1, data, sizeof data), GF_OK);
  CHECK_EQ (gf_sftp_server_data (w.srv, 2, data, sizeof data), GF_OK);
  CHECK_EQ (gf_sftp_server_pending (w.srv), 2 * (sizeof data + 13));
  /* The third would exceed the limit: not queued, and still outstanding.  */
  CHECK_EQ (gf_sftp_server_data (w.srv, 3, data, sizeof data), GF_ERR_AGAIN);
  want = gf_sftp_server_pending (w.srv);
  CHECK_EQ (w.to_cli.len, 0);
  /* The peer starts reading, a few bytes at a time.  */
  w.to_cli.blocked = 0;
  w.to_cli.budget_on = 1;
  w.to_cli.budget = 1000;
  CHECK_EQ (gf_sftp_server_writable (w.srv), GF_OK);
  CHECK_EQ (w.to_cli.len, 1000);
  w.to_cli.budget_on = 0;
  CHECK_EQ (gf_sftp_server_writable (w.srv), GF_OK);
  CHECK_EQ (gf_sftp_server_pending (w.srv), 0);
  CHECK_EQ (w.to_cli.len, want);
  CHECK_EQ (gf_sftp_server_data (w.srv, 3, data, sizeof data), GF_OK);
  CHECK_EQ (w.srv_disconnect, 0);
  world_free (&w);

  /* A write that fails ends the session.  */
  srv_ready (&w, &(gf_sftp_server_config) { 0, 0, 0 });
  w.hold = 1;
  gf_writer_init (&bw, body, sizeof body);
  gf_wr_u32 (&bw, 1);
  gf_wr_cstring (&bw, "p");
  n = pkt (b, sizeof b, GF_FXP_STAT, body, bw.len);
  srv_feed (&w, b, n);
  w.srv_disconnect = 0;
  gf_sftp_server_free (w.srv);
  {
    gf_sftp_server_events se;

    memset (&se, 0, sizeof se);
    se.user = &w;
    se.write = NULL;
    CHECK_EQ (gf_sftp_server_new (&w.srv, &(gf_sftp_server_config) { 0, 0, 0 },
                                  &se), GF_ERR_INVAL);
    se.write = srv_write;
    se.request = srv_request;
    se.disconnect = srv_disconnect;
    CHECK_EQ (gf_sftp_server_new (&w.srv, &(gf_sftp_server_config) { 0, 0, 0 },
                                  &se), GF_OK);
  }
  world_free (&w);
}

/* ---------------------------------------------------------------- */
/* The client against a scripted server                              */
/* ---------------------------------------------------------------- */

static void
cli_feed (struct world *w, const uint8_t *p, size_t n)
{
  (void) gf_sftp_client_input (w->cli, p, n);
}

static void
cli_ready_world (struct world *w, uint32_t *first_id)
{
  uint8_t b[64], v[4] = { 0, 0, 0, 3 };
  size_t n = pkt (b, sizeof b, GF_FXP_VERSION, v, 4);

  world_new (w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 0, 0 });
  CHECK_EQ (gf_sftp_client_start (w->cli), GF_OK);
  CHECK_EQ (w->to_srv.len, 9);
  w->to_srv.len = 0;
  cli_feed (w, b, n);
  CHECK (w->ready);
  (void) first_id;
}

static size_t
response (uint8_t *out, size_t cap, uint8_t type, uint32_t id,
          const uint8_t *body, size_t n)
{
  uint8_t tmp[1024];
  gf_writer w;

  gf_writer_init (&w, tmp, sizeof tmp);
  gf_wr_u32 (&w, id);
  gf_wr_bytes (&w, body, n);
  return pkt (out, cap, type, tmp, w.len);
}

static void
test_client_protocol (void)
{
  struct world w;
  uint8_t b[1200], body[1000];
  gf_writer bw;
  size_t n, i;
  uint32_t id = 0;
  uint8_t h[4] = { 'H', 0, 0, 0 };

  /* VERSION: right, old, too new, not VERSION at all.  */
  world_new (&w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 0, 0 });
  gf_sftp_client_start (w.cli);
  {
    uint8_t v[4] = { 0, 0, 0, 2 };

    n = pkt (b, sizeof b, GF_FXP_VERSION, v, 4);
    cli_feed (&w, b, n);
    CHECK_EQ (w.cli_disconnect, 1);
    CHECK_EQ (w.cli_status, GF_ERR_UNSUPPORTED);
  }
  world_free (&w);
  world_new (&w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 0, 0 });
  gf_sftp_client_start (w.cli);
  {
    uint8_t v[4] = { 0, 0, 0, 6 };

    n = pkt (b, sizeof b, GF_FXP_VERSION, v, 4);
    cli_feed (&w, b, n);
    CHECK_EQ (w.cli_disconnect, 1);
  }
  world_free (&w);
  world_new (&w, &(gf_sftp_server_config) { 0, 0, 0 },
             &(gf_sftp_client_config) { 0, 0, 0 });
  gf_sftp_client_start (w.cli);
  n = response (b, sizeof b, GF_FXP_STATUS, 1, (const uint8_t *) "\0\0\0\0", 4);
  cli_feed (&w, b, n);
  CHECK_EQ (w.cli_disconnect, 1);
  world_free (&w);

  /* Garbage lengths.  */
  {
    static const uint8_t lens[][4] = { { 0, 0, 0, 0 }, { 0x7f, 0, 0, 0 } };

    for (i = 0; i < 2; i++)
      {
        cli_ready_world (&w, NULL);
        cli_feed (&w, lens[i], 4);
        CHECK_EQ (w.cli_disconnect, 1);
        world_free (&w);
      }
  }

  /* Responses to nothing, and twice.  */
  cli_ready_world (&w, NULL);
  n = response (b, sizeof b, GF_FXP_STATUS, 99, (const uint8_t *) "\0\0\0\0\0\0\0\0\0\0\0\0", 12);
  cli_feed (&w, b, n);
  CHECK_EQ (w.cli_disconnect, 1);
  world_free (&w);
  cli_ready_world (&w, NULL);
  CHECK_EQ (gf_sftp_client_remove (w.cli, "x", NULL, &id), GF_OK);
  n = response (b, sizeof b, GF_FXP_STATUS, id, (const uint8_t *) "\0\0\0\0\0\0\0\0\0\0\0\0", 12);
  cli_feed (&w, b, n);
  CHECK_EQ (w.nresponses, 1);
  CHECK_EQ (w.cli_disconnect, 0);
  cli_feed (&w, b, n);
  CHECK_EQ (w.cli_disconnect, 1);
  world_free (&w);

  /* A status without the language tag is fine.  */
  cli_ready_world (&w, NULL);
  gf_sftp_client_remove (w.cli, "x", NULL, &id);
  gf_writer_init (&bw, body, sizeof body);
  gf_wr_u32 (&bw, GF_FX_FAILURE);
  gf_wr_cstring (&bw, "no tag");
  n = response (b, sizeof b, GF_FXP_STATUS, id, body, bw.len);
  cli_feed (&w, b, n);
  CHECK_EQ (w.cli_disconnect, 0);
  CHECK (strcmp (LAST (&w).message, "no tag") == 0);
  world_free (&w);

  /* A response that cannot answer that request.  */
  {
    static const struct
    {
      int request;
      uint8_t resp;
    } bad[] = {
      { 0, GF_FXP_DATA },	/* READ answered with NAME.  */
      { 1, GF_FXP_HANDLE },	/* STAT answered with HANDLE.  */
      { 2, GF_FXP_ATTRS },	/* OPEN answered with ATTRS.  */
      { 3, GF_FXP_NAME },	/* REMOVE answered with NAME.  */
      { 4, GF_FXP_EXTENDED_REPLY }	/* READDIR answered with EXTENDED_REPLY.  */
    };

    for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
      {
        cli_ready_world (&w, NULL);
        switch (bad[i].request)
          {
          case 0:
            gf_sftp_client_read (w.cli, h, 4, 0, 10, NULL, &id);
            break;
          case 1:
            gf_sftp_client_stat (w.cli, "x", NULL, &id);
            break;
          case 2:
            gf_sftp_client_open (w.cli, "x", GF_FXF_READ, NULL, NULL, &id);
            break;
          case 3:
            gf_sftp_client_remove (w.cli, "x", NULL, &id);
            break;
          default:
            gf_sftp_client_readdir (w.cli, h, 4, NULL, &id);
            break;
          }
        gf_writer_init (&bw, body, sizeof body);
        gf_wr_u32 (&bw, 0);
        gf_wr_u32 (&bw, 0);
        gf_wr_u32 (&bw, 0);
        gf_wr_u32 (&bw, 0);
        n = response (b, sizeof b, bad[i].resp, id, body, bw.len);
        cli_feed (&w, b, n);
        CHECK_EQ (w.nresponses, 0);
        CHECK_EQ (w.cli_disconnect, 1);
        world_free (&w);
      }
  }

  /* DATA longer than was asked for.  */
  cli_ready_world (&w, NULL);
  gf_sftp_client_read (w.cli, h, 4, 0, 10, NULL, &id);
  gf_writer_init (&bw, body, sizeof body);
  gf_wr_string (&bw, "01234567890", 11);
  n = response (b, sizeof b, GF_FXP_DATA, id, body, bw.len);
  cli_feed (&w, b, n);
  CHECK_EQ (w.cli_disconnect, 1);
  world_free (&w);
  cli_ready_world (&w, NULL);
  gf_sftp_client_read (w.cli, h, 4, 0, 10, NULL, &id);
  gf_writer_init (&bw, body, sizeof body);
  gf_wr_string (&bw, "0123456789", 10);
  n = response (b, sizeof b, GF_FXP_DATA, id, body, bw.len);
  cli_feed (&w, b, n);
  CHECK_EQ (w.cli_disconnect, 0);
  CHECK_EQ (LAST (&w).data_len, 10);
  world_free (&w);

  /* Directory listings that try to name a path, or nothing at all.  */
  {
    static const char *const names[] = { "../../etc/passwd", "a/b", "/abs",
                                         "", "a\0b" };

    for (i = 0; i < 5; i++)
      {
        cli_ready_world (&w, NULL);
        gf_sftp_client_readdir (w.cli, h, 4, NULL, &id);
        gf_writer_init (&bw, body, sizeof body);
        gf_wr_u32 (&bw, 1);
        gf_wr_string (&bw, names[i], i == 4 ? 3 : strlen (names[i]));
        gf_wr_string (&bw, "x", 1);
        gf_wr_u32 (&bw, 0);
        n = response (b, sizeof b, GF_FXP_NAME, id, body, bw.len);
        cli_feed (&w, b, n);
        CHECK_EQ (w.nresponses, 0);
        CHECK_EQ (w.cli_disconnect, 1);
        world_free (&w);
      }
    /* "..", "." and ordinary names are left to the application, which
       skips the first two as it always had to.  */
    cli_ready_world (&w, NULL);
    gf_sftp_client_readdir (w.cli, h, 4, NULL, &id);
    gf_writer_init (&bw, body, sizeof body);
    gf_wr_u32 (&bw, 3);
    for (i = 0; i < 3; i++)
      {
        gf_wr_cstring (&bw, i == 0 ? "." : i == 1 ? ".." : "file");
        gf_wr_cstring (&bw, "x");
        gf_wr_u32 (&bw, 0);
      }
    n = response (b, sizeof b, GF_FXP_NAME, id, body, bw.len);
    cli_feed (&w, b, n);
    CHECK_EQ (w.cli_disconnect, 0);
    CHECK_EQ (LAST (&w).nnames, 3);
    world_free (&w);
  }
  /* A realpath may have slashes but only one name; a NAME with no names
     or with a count that the data does not back is refused.  */
  cli_ready_world (&w, NULL);
  gf_sftp_client_realpath (w.cli, "x", NULL, &id);
  gf_writer_init (&bw, body, sizeof body);
  gf_wr_u32 (&bw, 1);
  gf_wr_cstring (&bw, "/home/u/x");
  gf_wr_cstring (&bw, "x");
  gf_wr_u32 (&bw, 0);
  n = response (b, sizeof b, GF_FXP_NAME, id, body, bw.len);
  cli_feed (&w, b, n);
  CHECK_EQ (w.cli_disconnect, 0);
  world_free (&w);
  for (i = 0; i < 3; i++)
    {
      cli_ready_world (&w, NULL);
      gf_sftp_client_realpath (w.cli, "x", NULL, &id);
      gf_writer_init (&bw, body, sizeof body);
      gf_wr_u32 (&bw, i == 0 ? 2 : i == 1 ? 0 : 5);
      gf_wr_cstring (&bw, "/a");
      gf_wr_cstring (&bw, "x");
      gf_wr_u32 (&bw, 0);
      if (i == 0)		/* The second name is all there.  */
        {
          gf_wr_cstring (&bw, "/b");
          gf_wr_cstring (&bw, "x");
          gf_wr_u32 (&bw, 0);
        }
      n = response (b, sizeof b, GF_FXP_NAME, id, body, bw.len);
      cli_feed (&w, b, n);
      CHECK_EQ (w.cli_disconnect, 1);
      world_free (&w);
    }

  /* Handles: empty and too long.  */
  for (i = 0; i < 2; i++)
    {
      static uint8_t big[300];

      cli_ready_world (&w, NULL);
      gf_sftp_client_opendir (w.cli, "x", NULL, &id);
      gf_writer_init (&bw, body, sizeof body);
      gf_wr_string (&bw, big, i ? 257 : 0);
      n = response (b, sizeof b, GF_FXP_HANDLE, id, body, bw.len);
      cli_feed (&w, b, n);
      CHECK_EQ (w.cli_disconnect, 1);
      world_free (&w);
    }
  /* Attributes with unknown flag bits, and with data missing.  */
  for (i = 0; i < 2; i++)
    {
      cli_ready_world (&w, NULL);
      gf_sftp_client_stat (w.cli, "x", NULL, &id);
      gf_writer_init (&bw, body, sizeof body);
      gf_wr_u32 (&bw, i ? GF_FILEXFER_ATTR_SIZE : 0x100);
      n = response (b, sizeof b, GF_FXP_ATTRS, id, body, bw.len);
      cli_feed (&w, b, n);
      CHECK_EQ (w.cli_disconnect, 1);
      world_free (&w);
    }
  /* Extended attributes in the answer are skipped, not interpreted.  */
  cli_ready_world (&w, NULL);
  gf_sftp_client_stat (w.cli, "x", NULL, &id);
  gf_writer_init (&bw, body, sizeof body);
  gf_wr_u32 (&bw, GF_FILEXFER_ATTR_SIZE | 0x80000000u);
  gf_wr_u64 (&bw, 1234);
  gf_wr_u32 (&bw, 1);
  gf_wr_cstring (&bw, "name@x");
  gf_wr_cstring (&bw, "value");
  n = response (b, sizeof b, GF_FXP_ATTRS, id, body, bw.len);
  cli_feed (&w, b, n);
  CHECK_EQ (w.cli_disconnect, 0);
  CHECK_EQ (LAST (&w).attrs.size, 1234);
  world_free (&w);

  /* Requests the client cannot make.  */
  cli_ready_world (&w, NULL);
  CHECK_EQ (gf_sftp_client_stat (w.cli, NULL, NULL, NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_sftp_client_read (w.cli, h, 4, 0, 0, NULL, NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_sftp_client_read (w.cli, h, 4, 0, 1000000, NULL, NULL),
            GF_ERR_INVAL);
  CHECK_EQ (gf_sftp_client_read (w.cli, h, 0, 0, 10, NULL, NULL), GF_ERR_INVAL);
  CHECK_EQ (gf_sftp_client_close (w.cli, h, 300, NULL, NULL), GF_ERR_INVAL);
  {
    static uint8_t huge[300000];

    CHECK_EQ (gf_sftp_client_write (w.cli, h, 4, 0, huge, sizeof huge, NULL,
                                    NULL), GF_ERR_RANGE);
  }
  /* Ids are distinct while outstanding.  */
  {
    uint32_t a, c;

    CHECK_EQ (gf_sftp_client_stat (w.cli, "x", NULL, &a), GF_OK);
    CHECK_EQ (gf_sftp_client_stat (w.cli, "y", NULL, &c), GF_OK);
    CHECK (a != c);
  }
  world_free (&w);

  /* A write that fails ends the session; output not yet taken is kept.  */
  cli_ready_world (&w, NULL);
  w.to_srv.blocked = 1;
  CHECK_EQ (gf_sftp_client_stat (w.cli, "x", NULL, NULL), GF_OK);
  CHECK (gf_sftp_client_pending (w.cli) > 0);
  w.to_srv.blocked = 0;
  CHECK_EQ (gf_sftp_client_writable (w.cli), GF_OK);
  CHECK_EQ (gf_sftp_client_pending (w.cli), 0);
  CHECK (w.to_srv.len > 0);
  world_free (&w);
}

int
main (void)
{
  test_chunking ();
  test_pipelining ();
  test_server_protocol ();
  test_server_responses ();
  test_output_limits ();
  test_client_protocol ();
  TST_DONE ();
}
