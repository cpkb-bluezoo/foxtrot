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
/* Fetch a file over SFTP and write it to standard output.

     sftp-get [-p PORT] [-i KEYFILE] [-k KNOWN_HOSTS] [--trust FINGERPRINT]
              USER@HOST PATH > FILE

   The same login as ssh-run (see there for the key, password and host key),
   then the "sftp" subsystem on a channel, bound to an SFTP client with
   gf_session_sftp_client.  The session carries the channel's data to the
   client and the client's requests to the channel; the program sees only
   SFTP: open, read until the end, close.  Reads are done one after another;
   a program that wants speed keeps several outstanding, as the library
   allows.

   Exit status: 0, or 1 if the file could not be fetched, or 255 for
   anything wrong with the connection.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "example.h"

#define CHUNK 32768

struct get
{
  struct client *c;
  const char *path;
  gf_sftp_client *sftp;
  uint8_t handle[GF_SFTP_MAX_HANDLE];
  size_t hlen;
  uint64_t offset;
  uint32_t chan;
  int done, status;
};

enum { T_OPEN = 1, T_READ, T_CLOSE };

static int
ready (struct client *c)
{
  struct get *g = c->user;

  return gf_chans_open_session (c->chans, &g->chan, 0, 0) != GF_OK;
}

static int
confirmed (void *user, uint32_t id)
{
  struct client *c = user;

  return gf_chans_request_subsystem (c->chans, id, "sftp", 1) != GF_OK;
}

/* SFTP's version has arrived: the first request.  The "tag" of a request
   comes back with its response, so the callback knows what is answered.  */
static int
sftp_ready (void *user)
{
  struct get *g = user;
  gf_sftp_attrs none;

  memset (&none, 0, sizeof none);
  return gf_sftp_client_open (g->sftp, g->path, GF_FXF_READ, &none,
                              (void *) (intptr_t) T_OPEN, NULL) != GF_OK;
}

static int
sftp_response (void *user, const gf_sftp_response *r)
{
  struct get *g = user;

  switch ((int) (intptr_t) r->tag)
    {
    case T_OPEN:
      if (r->type != GF_FXP_HANDLE)
        {
          fprintf (stderr, "cannot open %s (status %u)\n", g->path,
                   (unsigned) r->status);
          g->status = 1;
          g->done = 1;
          return 0;
        }
      memcpy (g->handle, r->handle.data, r->handle.len);
      g->hlen = r->handle.len;
      break;
    case T_READ:
      if (r->type == GF_FXP_DATA)
        {
          fwrite (r->data.data, 1, r->data.len, stdout);
          g->offset += r->data.len;
          break;
        }
      /* The end of the file is a status, EOF; anything else is an error.  */
      if (r->status != GF_FX_EOF)
        {
          fprintf (stderr, "read failed (status %u)\n", (unsigned) r->status);
          g->status = 1;
        }
      return gf_sftp_client_close (g->sftp, g->handle, g->hlen,
                                   (void *) (intptr_t) T_CLOSE, NULL) != GF_OK;
    default:
      g->done = 1;			/* The close was answered.  */
      return 0;
    }
  return gf_sftp_client_read (g->sftp, g->handle, g->hlen, g->offset, CHUNK,
                              (void *) (intptr_t) T_READ, NULL) != GF_OK;
}

static void
sftp_disconnect (void *user, int status)
{
  struct get *g = user;

  if (!g->done)
    fprintf (stderr, "sftp-get: the SFTP session failed (%d)\n", status);
  g->done = 1;
  g->status = 255;
}

/* The subsystem was started: bind an SFTP client to the channel.  */
static int
reply (void *user, uint32_t id, int success)
{
  struct client *c = user;
  struct get *g = c->user;
  gf_sftp_client_config sc;
  gf_sftp_client_events se;

  if (!success)
    {
      fprintf (stderr, "the server has no sftp subsystem\n");
      g->done = 1;
      g->status = 255;
      return 0;
    }
  memset (&sc, 0, sizeof sc);
  memset (&se, 0, sizeof se);
  se.user = g;
  se.ready = sftp_ready;
  se.response = sftp_response;
  se.disconnect = sftp_disconnect;
  return gf_session_sftp_client (c->s, id, &sc, &se, &g->sftp) != GF_OK;
}

static int
closed (void *user, uint32_t id)
{
  struct client *c = user;
  struct get *g = c->user;

  (void) id;
  g->sftp = NULL;			/* The session freed it with the channel.  */
  g->done = 1;
  return 0;
}

static int
finished (void *user)
{
  struct client *c = user;
  struct get *g = c->user;

  return g->done || c->auth_failed;
}

int
main (int argc, char **argv)
{
  struct client c;
  struct get g;
  gf_session_events ev;
  int i;
  char *home = getenv ("HOME"), kh[1024];

  memset (&c, 0, sizeof c);
  memset (&g, 0, sizeof g);
  c.fd = -1;
  c.o.port = "22";
  c.o.password = getenv ("SSH_RUN_PASSWORD");
  c.o.passphrase = getenv ("SSH_RUN_PASSPHRASE");
  c.user = &g;
  g.c = &c;
  g.status = 0;
  for (i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "-p") == 0 && i + 1 < argc)
        c.o.port = argv[++i];
      else if (strcmp (argv[i], "-i") == 0 && i + 1 < argc)
        c.o.identity = argv[++i];
      else if (strcmp (argv[i], "-k") == 0 && i + 1 < argc)
        c.o.known_hosts = argv[++i];
      else if (strcmp (argv[i], "--trust") == 0 && i + 1 < argc)
        c.o.trust = argv[++i];
      else
        break;
    }
  if (argc - i != 2 || client_target (&c.o, argv[i]) != 0)
    {
      fprintf (stderr, "usage: sftp-get [-p PORT] [-i KEYFILE] "
               "[-k KNOWN_HOSTS] [--trust FINGERPRINT] USER@HOST PATH\n");
      return 255;
    }
  g.path = argv[i + 1];
  if (c.o.known_hosts == NULL && home != NULL)
    {
      snprintf (kh, sizeof kh, "%s/.ssh/known_hosts", home);
      c.o.known_hosts = kh;
    }
  memset (&ev, 0, sizeof ev);
  ev.channel_confirmed = confirmed;
  ev.channel_request_reply = reply;
  ev.channel_closed = closed;
  if (client_open (&c, &ev, ready) != 0)
    {
      client_close (&c);
      return 255;
    }
  if (drive (c.s, c.fd, finished, &c, 600000) < 0 && !g.done)
    g.status = 255;
  if (c.auth_failed)
    g.status = 255;
  fflush (stdout);
  client_close (&c);
  return g.status;
}
