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
/* Run a command on a remote host and print what it prints.

     ssh-run [-p PORT] [-i KEYFILE] [-k KNOWN_HOSTS] [--trust FINGERPRINT]
             USER@HOST COMMAND

   The simplest use of a client session: connect, log in, open one channel,
   ask for a command, copy its output to ours and exit with its status.  The
   key is in any file format the library reads (keyinfo(1) shows which);
   without one the password is taken from the environment variable
   SSH_RUN_PASSWORD, and a passphrase for the key from SSH_RUN_PASSPHRASE.
   The host must be in the known_hosts file (default ~/.ssh/known_hosts), or
   its fingerprint given with --trust: nothing is trusted otherwise.

   Exit status: the command's, or 255 if it could not be run.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "example.h"

struct run
{
  const char *command;
  int closed, exit_status, have_status;
  uint32_t chan;
};

/* Logged in: open a session channel.  */
static int
ready (struct client *c)
{
  struct run *r = c->user;

  return gf_chans_open_session (c->chans, &r->chan, 0, 0) != GF_OK;
}

/* The channel is open: ask for the command.  */
static int
confirmed (void *user, uint32_t id)
{
  struct client *c = user;
  struct run *r = c->user;

  return gf_chans_request_exec (c->chans, id, r->command, 1) != GF_OK;
}

static int
failed (void *user, uint32_t id, uint32_t reason, gf_slice text)
{
  struct client *c = user;
  struct run *r = c->user;

  (void) id;
  (void) reason;
  fprintf (stderr, "the server would not open a channel: %.*s\n",
           (int) text.len, (const char *) text.data);
  r->closed = 1;
  return 0;
}

/* The answer to the exec request.  We have no input to send, so say so.  */
static int
reply (void *user, uint32_t id, int success)
{
  struct client *c = user;
  struct run *r = c->user;

  if (!success)
    {
      fprintf (stderr, "the server would not run the command\n");
      r->closed = 1;
      return 0;
    }
  return gf_chans_send_eof (c->chans, id) != GF_OK;
}

/* Output.  The window is given back as it is dealt with, which is what
   keeps a fast server from filling our memory.  */
static int
data (void *user, uint32_t id, const uint8_t *d, size_t n)
{
  struct client *c = user;

  fwrite (d, 1, n, stdout);
  return gf_chans_consumed (c->chans, id, n) != GF_OK;
}

static int
ext_data (void *user, uint32_t id, uint32_t type, const uint8_t *d, size_t n)
{
  struct client *c = user;

  if (type == GF_EXTENDED_DATA_STDERR)
    fwrite (d, 1, n, stderr);
  return gf_chans_consumed (c->chans, id, n) != GF_OK;
}

/* The command's exit status arrives as a request on the channel.  */
static int
request (void *user, const gf_chan_request *q)
{
  struct client *c = user;
  struct run *r = c->user;

  if (q->type == GF_REQ_EXIT_STATUS)
    {
      r->exit_status = (int) q->status;
      r->have_status = 1;
    }
  else if (q->type == GF_REQ_EXIT_SIGNAL)
    {
      r->exit_status = 128;
      r->have_status = 1;
    }
  return 0;
}

static int
closed (void *user, uint32_t id)
{
  struct client *c = user;
  struct run *r = c->user;

  (void) id;
  r->closed = 1;
  return 0;
}

static int
finished (void *user)
{
  struct client *c = user;
  struct run *r = c->user;

  return r->closed || c->auth_failed;
}

int
main (int argc, char **argv)
{
  struct client c;
  struct run r;
  gf_session_events ev;
  int i, rc;
  char *home = getenv ("HOME"), kh[1024];

  memset (&c, 0, sizeof c);
  memset (&r, 0, sizeof r);
  c.fd = -1;
  c.o.port = "22";
  c.o.password = getenv ("SSH_RUN_PASSWORD");
  c.o.passphrase = getenv ("SSH_RUN_PASSPHRASE");
  c.user = &r;
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
      fprintf (stderr, "usage: ssh-run [-p PORT] [-i KEYFILE] [-k KNOWN_HOSTS] "
               "[--trust FINGERPRINT] USER@HOST COMMAND\n");
      return 255;
    }
  r.command = argv[i + 1];
  if (c.o.known_hosts == NULL && home != NULL)
    {
      snprintf (kh, sizeof kh, "%s/.ssh/known_hosts", home);
      c.o.known_hosts = kh;
    }
  memset (&ev, 0, sizeof ev);
  ev.channel_confirmed = confirmed;
  ev.channel_failed = failed;
  ev.channel_request_reply = reply;
  ev.channel_data = data;
  ev.channel_extended_data = ext_data;
  ev.channel_request = request;
  ev.channel_closed = closed;
  if (client_open (&c, &ev, ready) != 0)
    {
      client_close (&c);
      return 255;
    }
  rc = drive (c.s, c.fd, finished, &c, 60000);
  if (!r.have_status)
    {
      if (rc != 0 && !c.auth_failed)
        fprintf (stderr, "ssh-run: the connection failed (%d)\n", rc);
      r.exit_status = 255;
    }
  fflush (stdout);
  client_close (&c);
  return r.exit_status;
}
