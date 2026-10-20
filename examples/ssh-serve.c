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
/* A small SSH server: public key login against an authorized_keys file, and
   a few commands of its own.

     ssh-serve [-p PORT] HOSTKEY AUTHORIZED_KEYS

   HOSTKEY is a private key file (any format keyinfo(1) reads, without a
   passphrase).  AUTHORIZED_KEYS is a file in OpenSSH's format; its options
   (command=, from=, expiry-time=, no-pty, permitopen, restrict ...) are
   honoured by the library as far as a library can, and the rest are passed
   on to the session here.  Any user name is accepted with a key in the file.
   Connections are served one after another.

   Commands (exec requests; a forced command replaces whatever is asked):

     echo TEXT      print TEXT
     whoami         print the user name
     exit N         exit with status N

   Anything else is "unknown command" and status 127.  Shells, ptys,
   forwarding and subsystems are refused.  The server is a model of how the
   pieces fit, not a daemon: it does not drop privileges, log, or limit
   connections.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <arpa/inet.h>
#include <netinet/in.h>

#include "example.h"
#include <foxtrot/authkeys.h>

struct serve
{
  gf_session *s;
  gf_chans *chans;
  int fd;
  gf_authkeys *keys;
  char peer[64];
  char user[256];
  /* The command being answered: its output, and how much has been sent.  */
  uint8_t out[1024];
  size_t outn, sent;
  uint32_t chan;
  int busy, status;
};

static int
on_write (void *user, const uint8_t *data, size_t len)
{
  struct serve *x = user;

  return write_all (x->fd, data, len);
}

/* A login request.  A key the file has is accepted if its signature (the
   library has checked it) is there; a query without a signature is told
   whether the key would do.  The options of the line that restrict the
   session are applied once the user is in: see authenticated.  */
static int
auth_request (void *user, const gf_auth_request *req)
{
  struct serve *x = user;
  gf_authkey_match m;
  time_t now = time (NULL);
  int ok = 0;

  if (req->method == GF_AUTH_PUBLICKEY)
    ok = gf_authkeys_check (x->keys, req, x->peer, NULL,
                            now < 0 ? 0 : (uint64_t) now, &m) == 1;
  if (ok && !req->has_signature)
    return gf_session_auth_pk_ok (x->s) != GF_OK;
  if (ok)
    {
      /* What the line forbids the session, and the command it forces.  */
      static const char *const names[] = {
        GF_CERT_PERMIT_PTY, GF_CERT_PERMIT_PORT_FORWARDING,
        GF_CERT_PERMIT_AGENT_FORWARDING, GF_CERT_PERMIT_X11_FORWARDING,
        GF_CERT_PERMIT_USER_RC
      };
      size_t i;

      snprintf (x->user, sizeof x->user, "%.*s", (int) req->user.len,
                (const char *) req->user.data);
      for (i = 0; i < sizeof names / sizeof names[0]; i++)
        if (!gf_authkey_permits (&m, names[i]))
          gf_session_deny (x->s, names[i]);
      if (m.command != NULL)
        gf_session_force (x->s, m.command);
      return gf_session_auth_accept (x->s) != GF_OK;
    }
  return gf_session_auth_reject (x->s, 0) != GF_OK;
}

static int
open_request (void *user, const gf_chan_open *o)
{
  struct serve *x = user;

  /* Sessions only, one at a time.  (Forwarding channels are refused by the
     session already for a user who may not forward; the rest are ours to
     decline.)  */
  if (o->type != GF_CHAN_SESSION || x->busy)
    return gf_session_channel_reject (x->s, o->id,
                                      GF_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                      "sessions only") != GF_OK;
  x->busy = 1;
  x->chan = o->id;
  x->outn = x->sent = 0;
  return gf_session_channel_accept (x->s, o->id, 0, 0) != GF_OK;
}

/* Send what is left of the output, then the exit status, EOF and close.
   Called when a command has been answered and when the channel can take
   more.  */
static int
flush (struct serve *x)
{
  while (x->sent < x->outn)
    {
      long n = gf_chans_send_data (x->chans, x->chan, x->out + x->sent,
                                   x->outn - x->sent);

      if (n < 0)
        return 1;
      if (n == 0)
        return 0;			/* The writable event says when.  */
      x->sent += (size_t) n;
    }
  if (x->busy == 1)
    {
      x->busy = 2;			/* Finished: said once.  */
      return gf_chans_request_exit_status (x->chans, x->chan,
                                           (uint32_t) x->status) != GF_OK
        || gf_chans_send_eof (x->chans, x->chan) != GF_OK
        || gf_chans_close (x->chans, x->chan) != GF_OK;
    }
  return 0;
}

static int
chan_request (void *user, const gf_chan_request *q)
{
  struct serve *x = user;
  char cmd[512];
  const char *forced = gf_session_force_command (x->s);

  if (q->type != GF_REQ_EXEC)
    return q->want_reply ? gf_chans_reply (x->chans, q->id, 0) != GF_OK : 0;
  /* A command forced on the user is run in place of the one asked for.  */
  if (forced != NULL)
    snprintf (cmd, sizeof cmd, "%s", forced);
  else
    snprintf (cmd, sizeof cmd, "%.*s", (int) q->command.len,
              (const char *) q->command.data);
  x->status = 0;
  if (strncmp (cmd, "echo ", 5) == 0)
    x->outn = (size_t) snprintf ((char *) x->out, sizeof x->out, "%s\n", cmd + 5);
  else if (strcmp (cmd, "whoami") == 0)
    x->outn = (size_t) snprintf ((char *) x->out, sizeof x->out, "%s\n", x->user);
  else if (strncmp (cmd, "exit ", 5) == 0)
    x->status = atoi (cmd + 5);
  else
    {
      x->outn = (size_t) snprintf ((char *) x->out, sizeof x->out,
                                   "unknown command\n");
      x->status = 127;
    }
  if (x->outn >= sizeof x->out)
    x->outn = sizeof x->out - 1;
  x->busy = 1;
  if (q->want_reply && gf_chans_reply (x->chans, q->id, 1) != GF_OK)
    return 1;
  return flush (x);
}

static int
chan_writable (void *user, uint32_t id)
{
  struct serve *x = user;

  (void) id;
  return x->busy ? flush (x) : 0;
}

static int
chan_data (void *user, uint32_t id, const uint8_t *d, size_t n)
{
  struct serve *x = user;

  (void) d;				/* Nothing reads input.  */
  return gf_chans_consumed (x->chans, id, n) != GF_OK;
}

static int
chan_closed (void *user, uint32_t id)
{
  struct serve *x = user;

  (void) id;
  x->busy = 0;
  return 0;
}

static void
on_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  (void) user;
  (void) reason;
  if (error != 0)
    fprintf (stderr, "ssh-serve: connection ended (%d) %.*s\n", error,
             (int) text.len, text.data ? (const char *) text.data : "");
}

static void
serve_one (int fd, gf_key *hostkey, gf_authkeys *keys)
{
  struct serve x;
  gf_session_config cfg;
  gf_session_events ev;
  struct sockaddr_storage ss;
  socklen_t sl = sizeof ss;

  memset (&x, 0, sizeof x);
  x.fd = fd;
  x.keys = keys;
  snprintf (x.peer, sizeof x.peer, "unknown");
  if (getpeername (fd, (struct sockaddr *) &ss, &sl) == 0)
    {
      if (ss.ss_family == AF_INET)
        inet_ntop (AF_INET, &((struct sockaddr_in *) &ss)->sin_addr, x.peer,
                   sizeof x.peer);
      else if (ss.ss_family == AF_INET6)
        inet_ntop (AF_INET6, &((struct sockaddr_in6 *) &ss)->sin6_addr, x.peer,
                   sizeof x.peer);
    }
  memset (&cfg, 0, sizeof cfg);
  cfg.conn.host_keys = &hostkey;
  cfg.conn.nhost_keys = 1;
  cfg.server_auth.methods = GF_AUTH_PUBLICKEY;
  cfg.server_auth.hostbound = 1;
  cfg.conn.announce_hostbound = 1;
  cfg.max_sessions = 1;
  memset (&ev, 0, sizeof ev);
  ev.user = &x;
  ev.write = on_write;
  ev.auth_request = auth_request;
  ev.channel_open = open_request;
  ev.channel_request = chan_request;
  ev.channel_data = chan_data;
  ev.channel_writable = chan_writable;
  ev.channel_closed = chan_closed;
  ev.closed = on_closed;
  if (gf_session_server_new (&x.s, &cfg, &ev) != GF_OK
      || gf_session_start (x.s, now_us ()) != GF_OK)
    {
      fprintf (stderr, "ssh-serve: cannot start a session\n");
      gf_session_free (x.s);
      return;
    }
  x.chans = gf_session_channels (x.s);
  drive (x.s, fd, NULL, NULL, 120000);
  gf_session_free (x.s);
}

int
main (int argc, char **argv)
{
  gf_key *hostkey = NULL;
  gf_authkeys *keys = NULL;
  struct sockaddr_in sa;
  int ls, one = 1, port = 2222, i, rc;
  char *text;
  size_t n, bad = 0;

  for (i = 1; i < argc && strcmp (argv[i], "-p") == 0 && i + 1 < argc; i += 2)
    port = atoi (argv[i + 1]);
  if (argc - i != 2)
    {
      fprintf (stderr, "usage: ssh-serve [-p PORT] HOSTKEY AUTHORIZED_KEYS\n");
      return 2;
    }
  rc = load_key (&hostkey, argv[i], NULL);
  if (rc != GF_OK || !gf_key_has_private (hostkey))
    {
      fprintf (stderr, "ssh-serve: cannot use %s as a host key (%d)\n", argv[i], rc);
      return 2;
    }
  text = read_file (argv[i + 1], &n);
  if (text == NULL || gf_authkeys_new (&keys) != GF_OK
      || gf_authkeys_load (keys, text, n, &bad) != GF_OK)
    {
      fprintf (stderr, "ssh-serve: cannot read %s\n", argv[i + 1]);
      return 2;
    }
  free (text);
  if (bad > 0)
    fprintf (stderr, "ssh-serve: %zu lines of %s were not understood and "
             "are ignored\n", bad, argv[i + 1]);
  ls = socket (AF_INET, SOCK_STREAM, 0);
  setsockopt (ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  memset (&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  sa.sin_port = htons ((uint16_t) port);
  if (bind (ls, (struct sockaddr *) &sa, sizeof sa) < 0 || listen (ls, 4) < 0)
    {
      perror ("ssh-serve");
      return 2;
    }
  {
    char fp[64];

    gf_key_fingerprint (hostkey, fp, sizeof fp);
    printf ("listening on 127.0.0.1:%d, host key %s\n", port, fp);
    fflush (stdout);
  }
  for (;;)
    {
      int fd = accept (ls, NULL, NULL);

      if (fd < 0)
        continue;
      serve_one (fd, hostkey, keys);
      close (fd);
    }
}
