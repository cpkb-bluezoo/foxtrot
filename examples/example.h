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

/* What every program that uses foxtrot has to supply, because the library
   does no I/O: sockets, a clock, a loop that feeds bytes in and runs timers,
   files.  These are the same few dozen lines in each real application; they
   are here once so that the examples can be about the library.

   The client half (struct client) is a client session with host key
   checking against a known_hosts file and a key or password to log in with;
   a program gives it the events of the channels it wants.  */

#ifndef FOXTROT_EXAMPLE_H
#define FOXTROT_EXAMPLE_H

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <foxtrot/status.h>
#include <foxtrot/session.h>
#include <foxtrot/key.h>
#include <foxtrot/keyfmt.h>
#include <foxtrot/knownhosts.h>

/* ---- The clock ---- */

/* The library takes the time as an argument: microseconds on any clock that
   does not go backwards.  */
static inline uint64_t
now_us (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

/* ---- Files ---- */

/* The whole file in a new buffer with a NUL after it, or NULL.  */
static inline char *
read_file (const char *path, size_t *len)
{
  FILE *f = fopen (path, "rb");
  char *buf = NULL;
  size_t cap = 0, n = 0, r;

  if (f == NULL)
    return NULL;
  for (;;)
    {
      if (n + 4096 + 1 > cap)
        {
          char *nb;

          cap = cap ? cap * 2 : 8192;
          nb = realloc (buf, cap);
          if (nb == NULL)
            {
              free (buf);
              fclose (f);
              return NULL;
            }
          buf = nb;
        }
      r = fread (buf + n, 1, 4096, f);
      n += r;
      if (r < 4096)
        break;
      if (n > 4 * 1024 * 1024)		/* No key file is this big.  */
        {
          free (buf);
          fclose (f);
          return NULL;
        }
    }
  fclose (f);
  buf[n] = '\0';
  if (len)
    *len = n;
  return buf;
}

/* A key from a file in whatever format it is in: an OpenSSH public key
   line, an RFC 4716 file, a PEM or DER key of OpenSSL's, a PuTTY file, or an
   OpenSSH private key that has no passphrase (one that has needs the
   application to supply bcrypt-pbkdf, which libgcrypt does not have: see
   gf_key_from_openssh_private_encrypted).  PASSPHRASE is for the formats
   that can be encrypted, or NULL.  Returns GF_OK or a status.  */
static inline int
load_key (gf_key **out, const char *path, const char *passphrase)
{
  size_t n;
  char *t = read_file (path, &n);
  int rc;

  if (t == NULL)
    return GF_ERR_INVAL;
  if (strncmp (t, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0)
    rc = gf_key_from_openssh_private (out, t, n);
  else if (strncmp (t, "-----BEGIN ", 11) == 0)
    rc = gf_key_from_pem (out, t, n, passphrase);
  else if (strncmp (t, "PuTTY-User-Key-File-", 20) == 0)
    rc = gf_key_from_ppk (out, t, n, passphrase, NULL, 0);
  else if (strncmp (t, "---- BEGIN SSH2 PUBLIC KEY ----", 31) == 0)
    rc = gf_key_from_rfc4716 (out, t, n, NULL, 0);
  else
    rc = gf_key_from_text (out, t, n, NULL);
  free (t);
  return rc;
}

/* ---- Sockets ---- */

static inline int
connect_to (const char *host, const char *port)
{
  struct addrinfo hints, *res, *a;
  int fd = -1;

  memset (&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo (host, port, &hints, &res) != 0)
    return -1;
  for (a = res; a != NULL; a = a->ai_next)
    {
      fd = socket (a->ai_family, a->ai_socktype, a->ai_protocol);
      if (fd < 0)
        continue;
      if (connect (fd, a->ai_addr, a->ai_addrlen) == 0)
        break;
      close (fd);
      fd = -1;
    }
  freeaddrinfo (res);
  return fd;
}

static inline int
write_all (int fd, const uint8_t *data, size_t len)
{
  while (len > 0)
    {
      ssize_t n = write (fd, data, len);

      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      data += n;
      len -= (size_t) n;
    }
  return 0;
}

/* ---- The loop ---- */

/* Feed S what arrives on FD and run its timers, until it is closed or DONE
   (if not NULL, called after each wakeup) says it is finished, or TIMEOUT_MS
   passes in all.  Returns 0 for an end the session ordered or DONE did, a
   negative status for a failure of the session, -1 for the socket, -2 for
   the timeout.  The library never blocks and never reads a socket: this
   loop is what an application writes for itself, in poll(2) here, in an
   event loop of its own elsewhere.  */
static inline int
drive (gf_session *s, int fd, int (*done) (void *), void *user, int timeout_ms)
{
  uint64_t deadline = now_us () + (uint64_t) timeout_ms * 1000;

  for (;;)
    {
      struct pollfd pfd = { fd, POLLIN, 0 };
      uint64_t t = gf_session_timeout (s), n = now_us ();
      int wait, r;
      uint8_t buf[16384];
      ssize_t got;

      if (gf_session_phase (s) == GF_PHASE_CLOSED || (done && done (user)))
        return 0;
      if (n >= deadline)
        return -2;
      wait = (int) ((deadline - n) / 1000) + 1;
      if (t != UINT64_MAX)
        {
          /* The library says when it next needs to be woken.  */
          int tw = t > n ? (int) ((t - n) / 1000) + 1 : 0;

          if (tw < wait)
            wait = tw;
        }
      r = poll (&pfd, 1, wait);
      if (r < 0 && errno != EINTR)
        return -1;
      if (r > 0)
        {
          got = read (fd, buf, sizeof buf);
          if (got <= 0)
            return gf_session_phase (s) == GF_PHASE_CLOSED ? 0 : -1;
          r = gf_session_receive (s, now_us (), buf, (size_t) got);
          if (r < 0 && gf_session_phase (s) != GF_PHASE_CLOSED)
            return r;
        }
      else
        {
          r = gf_session_on_timeout (s, now_us ());
          if (r < 0 && gf_session_phase (s) != GF_PHASE_CLOSED)
            return r;
        }
    }
}

/* ---- A client ---- */

struct client;

/* What a program does once it is logged in: usually open a channel.  */
typedef int (*client_ready_fn) (struct client *c);

struct client_opts
{
  const char *user, *host, *port;	/* port is text, as getaddrinfo takes it.  */
  const char *identity;			/* A key file, or NULL.  */
  const char *known_hosts;		/* A known_hosts file, or NULL.  */
  const char *trust;			/* A SHA256:... fingerprint to accept.  */
  const char *passphrase;		/* For the key file.  */
  const char *password;			/* Or to log in with.  */
};

struct client
{
  struct client_opts o;
  gf_session *s;
  gf_chans *chans;
  int fd;
  gf_key *key;
  gf_knownhosts *kh;
  int authenticated, auth_failed;
  client_ready_fn ready;
  void *user;				/* The program's own state.  */
};

/* Whether to trust the host key: known_hosts says, or the fingerprint given
   with trust.  Nothing is trusted by default, and a changed key is refused
   whatever else.  */
static inline int
client_host_key (void *user, const gf_key *key)
{
  struct client *c = user;
  char fp[64];
  time_t now = time (NULL);
  unsigned port = (unsigned) atoi (c->o.port);
  enum gf_hostcheck r = GF_HOST_UNKNOWN;

  gf_key_fingerprint (key, fp, sizeof fp);
  if (c->kh != NULL)
    r = gf_knownhosts_check (c->kh, c->o.host, port, key,
                             now < 0 ? 0 : (uint64_t) now);
  if (r == GF_HOST_MATCH)
    return 0;
  if (r == GF_HOST_CHANGED)
    fprintf (stderr, "WARNING: the host key of %s has CHANGED (now %s)\n",
             c->o.host, fp);
  else if (r == GF_HOST_REVOKED)
    fprintf (stderr, "the host key of %s is REVOKED (%s)\n", c->o.host, fp);
  else if (c->o.trust != NULL && strcmp (c->o.trust, fp) == 0)
    return 0;
  else
    fprintf (stderr, "the host key of %s is not known: %s\n"
             "(add it to known_hosts, or run again with --trust %s)\n",
             c->o.host, fp, fp);
  return 1;
}

static inline int
client_write (void *user, const uint8_t *data, size_t len)
{
  struct client *c = user;

  return write_all (c->fd, data, len);
}

static inline int
client_authenticated (void *user, gf_slice username)
{
  struct client *c = user;

  (void) username;
  c->authenticated = 1;
  return c->ready (c);
}

static inline int
client_auth_failed (void *user)
{
  struct client *c = user;

  fprintf (stderr, "permission denied (the server accepted nothing)\n");
  c->auth_failed = 1;
  return 0;
}

/* Parse USER@HOST (the user may be left out for the login name's, which we
   do not guess: it must be given).  */
static inline int
client_target (struct client_opts *o, char *arg)
{
  char *at = strchr (arg, '@');

  if (at == NULL || at == arg || at[1] == '\0')
    return -1;
  *at = '\0';
  o->user = arg;
  o->host = at + 1;
  return 0;
}

/* Connect, set the session up, start it.  EV has the program's channel
   events; the ones that a client needs everywhere are filled in here.
   Returns 0, or prints a reason and returns nonzero.  */
static inline int
client_open (struct client *c, gf_session_events *ev, client_ready_fn ready)
{
  gf_session_config cfg;
  static enum gf_sigalg algs[16];
  static const gf_key *keys[1];
  int rc;

  c->ready = ready;
  if (c->o.identity != NULL)
    {
      rc = load_key (&c->key, c->o.identity, c->o.passphrase);
      if (rc != GF_OK || !gf_key_has_private (c->key))
        {
          fprintf (stderr, "cannot use %s as a private key (status %d)\n",
                   c->o.identity, rc);
          return 1;
        }
    }
  if (c->o.known_hosts != NULL)
    {
      size_t n;
      char *t = read_file (c->o.known_hosts, &n);

      if (t != NULL)
        {
          if (gf_knownhosts_new (&c->kh) == GF_OK)
            gf_knownhosts_load (c->kh, t, n, NULL);
          free (t);
        }
    }
  c->fd = connect_to (c->o.host, c->o.port);
  if (c->fd < 0)
    {
      fprintf (stderr, "cannot connect to %s port %s\n", c->o.host, c->o.port);
      return 1;
    }
  memset (&cfg, 0, sizeof cfg);
  /* A host we know is asked for the kind of key we know it by, so that it
     cannot answer with another.  */
  if (c->kh != NULL)
    {
      cfg.conn.prefs.nsigalgs = gf_knownhosts_sigalgs (c->kh, c->o.host,
                                                      (unsigned) atoi (c->o.port),
                                                      algs, 16);
      cfg.conn.prefs.sigalgs = algs;
    }
  cfg.client_auth.user = c->o.user;
  keys[0] = c->key;
  cfg.client_auth.keys = c->key ? keys : NULL;
  cfg.client_auth.nkeys = c->key ? 1 : 0;
  cfg.client_auth.password = c->o.password;
  ev->user = c;
  ev->write = client_write;
  ev->host_key = client_host_key;
  ev->authenticated = client_authenticated;
  ev->auth_failed = client_auth_failed;
  if (gf_session_client_new (&c->s, &cfg, ev) != GF_OK
      || gf_session_start (c->s, now_us ()) != GF_OK)
    {
      fprintf (stderr, "cannot start the session\n");
      return 1;
    }
  c->chans = gf_session_channels (c->s);
  return 0;
}

static inline void
client_close (struct client *c)
{
  if (c->s != NULL && gf_session_phase (c->s) != GF_PHASE_CLOSED)
    gf_session_disconnect (c->s, now_us (), GF_DISCONNECT_BY_APPLICATION,
                           "done");
  gf_session_free (c->s);
  gf_key_free (c->key);
  gf_knownhosts_free (c->kh);
  if (c->fd >= 0)
    close (c->fd);
}

#endif /* FOXTROT_EXAMPLE_H */
