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

/* A foxtrot SSH server for the OpenSSH client to talk to.

     interop-server HOSTKEY PORT

   HOSTKEY is an unencrypted OpenSSH private key file.  The server accepts
   one connection on 127.0.0.1:PORT, completes the transport handshake,
   accepts the ssh-userauth service, answers every authentication request
   with a failure that offers only "publickey", and exits when the client
   goes away.  On standard output, "HOSTKEY SHA256:..." is the fingerprint
   to expect, "READY" says the port is listening, and "KEX ..." and
   "CLIENT ..." say what was negotiated and who the peer is.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "interop-util.h"

#include <foxtrot/key.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

struct ctx
{
  int fd;
  gf_conn *c;
  int established;
  int auth_requests;
};

static int
on_established (void *user, const gf_conn_info *info)
{
  struct ctx *x = user;

  printf ("KEX %s %s %s\n", gf_kex_name (info->kex),
          gf_cipher_name (info->cipher_c2s), gf_sigalg_name (info->hostkey_alg));
  printf ("CLIENT %.*s\n", (int) info->peer_software.len,
          (const char *) info->peer_software.data);
  fflush (stdout);
  x->established = 1;
  return 0;
}

static int
on_message (void *user, const uint8_t *p, size_t n)
{
  struct ctx *x = user;
  uint8_t out[128];
  gf_writer w;

  (void) n;
  if (p[0] == 50)		/* USERAUTH_REQUEST.  */
    {
      x->auth_requests++;
      gf_writer_init (&w, out, sizeof out);
      gf_wr_u8 (&w, 51);	/* USERAUTH_FAILURE: methods, partial success.  */
      gf_wr_namelist (&w, "publickey");
      gf_wr_bool (&w, 0);
      return gf_conn_send (x->c, now_us (), out, w.len) != GF_OK;
    }
  return 0;
}

static int
on_write (void *user, const uint8_t *data, size_t len)
{
  return sock_write (((struct ctx *) user)->fd, data, len);
}

static void
on_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  (void) user;
  printf ("CLOSED %d %u %.*s\n", error, (unsigned) reason, (int) text.len,
          text.data ? (const char *) text.data : "");
  fflush (stdout);
}

int
main (int argc, char **argv)
{
  struct sockaddr_in sa;
  int ls, one = 1, port, r;
  char text[8192], fp[64];
  size_t n;
  FILE *f;
  struct ctx x;
  gf_key *key = NULL;
  gf_conn_config cfg;
  gf_conn_events ev;

  if (argc != 3)
    {
      fprintf (stderr, "usage: interop-server HOSTKEY PORT\n");
      return 2;
    }
  port = atoi (argv[2]);
  f = fopen (argv[1], "r");
  if (f == NULL)
    {
      perror (argv[1]);
      return 2;
    }
  n = fread (text, 1, sizeof text, f);
  fclose (f);
  if (gf_key_from_openssh_private (&key, text, n) != GF_OK)
    {
      fprintf (stderr, "cannot read host key\n");
      return 2;
    }
  gf_key_fingerprint (key, fp, sizeof fp);
  printf ("HOSTKEY %s\n", fp);

  ls = socket (AF_INET, SOCK_STREAM, 0);
  setsockopt (ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  memset (&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  sa.sin_port = htons ((uint16_t) port);
  if (bind (ls, (struct sockaddr *) &sa, sizeof sa) < 0 || listen (ls, 1) < 0)
    {
      perror ("bind");
      return 2;
    }
  printf ("READY\n");
  fflush (stdout);
  memset (&x, 0, sizeof x);
  x.fd = accept (ls, NULL, NULL);
  if (x.fd < 0)
    {
      perror ("accept");
      return 2;
    }

  memset (&cfg, 0, sizeof cfg);
  cfg.host_keys = &key;
  cfg.nhost_keys = 1;
  memset (&ev, 0, sizeof ev);
  ev.user = &x;
  ev.write = on_write;
  ev.established = on_established;
  ev.message = on_message;
  ev.closed = on_closed;
  if (gf_conn_server_new (&x.c, &cfg, &ev) != GF_OK
      || gf_conn_start (x.c, now_us ()) != GF_OK)
    {
      fprintf (stderr, "cannot start\n");
      return 2;
    }
  r = drive (x.c, x.fd, NULL, NULL, 20000);
  printf ("DONE %d auth_requests=%d\n", r, x.auth_requests);
  gf_conn_free (x.c);
  gf_key_free (key);
  close (x.fd);
  return x.established && r >= 0 ? 0 : 1;
}
