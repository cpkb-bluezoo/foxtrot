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

     interop-server HOSTKEY PORT [--auth-key PRIVATEKEY] [--password PW]
                                 [--code CODE] [--hostbound]

   HOSTKEY is an unencrypted OpenSSH private key file.  The server accepts
   one connection on 127.0.0.1:PORT, completes the transport handshake and
   accepts the ssh-userauth service.  Users authenticate with the public key
   of the private key file given by --auth-key, with the password PW, or by
   answering a keyboard-interactive question with CODE, as given.  Once
   authentication succeeds it says so and disconnects.  On standard
   output, "HOSTKEY SHA256:..." is the fingerprint to expect, "READY" says
   the port is listening, "KEX ..." and "CLIENT ..." say what was
   negotiated and who the peer is, and "AUTH OK user method" or "AUTH
   FAILED" how it ended.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "interop-util.h"

#include <foxtrot/auth.h>
#include <foxtrot/key.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

struct ctx
{
  int fd;
  gf_conn *c;
  gf_auth_server *auth;
  gf_key *authorized;
  const char *password, *code;
  int established, authed, hostbound_used;
  const char *method;
};

static int
on_established (void *user, const gf_conn_info *info)
{
  struct ctx *x = user;
  size_t bl;
  const uint8_t *blob = gf_key_blob (info->host_key, &bl);

  printf ("KEX %s %s %s\n", gf_kex_name (info->kex),
          gf_cipher_name (info->cipher_c2s), gf_sigalg_name (info->hostkey_alg));
  printf ("CLIENT %.*s\n", (int) info->peer_software.len,
          (const char *) info->peer_software.data);
  fflush (stdout);
  x->established = 1;
  return gf_auth_server_start (x->auth, now_us (), info->session_id,
                               info->session_id_len, blob, bl) != GF_OK;
}

static int
on_message (void *user, const uint8_t *p, size_t n)
{
  struct ctx *x = user;

  if (p[0] >= 50 && p[0] <= 79)
    {
      int r = gf_auth_server_input (x->auth, now_us (), p, n);

      return r != GF_OK && r != GF_ERR_AUTH;
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

static int
auth_send (void *user, const uint8_t *p, size_t n)
{
  struct ctx *x = user;

  return gf_conn_send (x->c, now_us (), p, n) != GF_OK;
}

static int
auth_request (void *user, const gf_auth_request *req)
{
  struct ctx *x = user;
  int ok = 0;

  switch (req->method)
    {
    case GF_AUTH_PUBLICKEY:
      x->method = req->hostbound ? "publickey-hostbound" : "publickey";
      ok = x->authorized && gf_key_equal (x->authorized, req->key);
      if (!req->has_signature)
        return (ok ? gf_auth_server_pk_ok (x->auth, now_us ())
                   : gf_auth_server_reject (x->auth, now_us (), 0)) != GF_OK;
      break;
    case GF_AUTH_PASSWORD:
      x->method = "password";
      ok = x->password && req->password.len == strlen (x->password)
        && memcmp (req->password.data, x->password, req->password.len) == 0;
      break;
    case GF_AUTH_KBDINT:
      {
        static const char *const prompts[] = { "Code: " };
        static const int echo[] = { 0 };

        x->method = "keyboard-interactive";
        return gf_auth_server_kbdint_prompt (x->auth, now_us (), "", "", 1,
                                             prompts, echo) != GF_OK;
      }
    default:
      break;
    }
  printf ("REQUEST %s %s\n", x->method ? x->method : "?", ok ? "yes" : "no");
  return (ok ? gf_auth_server_accept (x->auth, now_us ())
             : gf_auth_server_reject (x->auth, now_us (), 0)) != GF_OK;
}

static int
auth_kbd_response (void *user, const gf_slice *r, size_t n)
{
  struct ctx *x = user;
  int ok = n == 1 && x->code && r[0].len == strlen (x->code)
    && memcmp (r[0].data, x->code, r[0].len) == 0;

  return (ok ? gf_auth_server_accept (x->auth, now_us ())
             : gf_auth_server_reject (x->auth, now_us (), 0)) != GF_OK;
}

static int
auth_done (void *user, gf_slice username)
{
  struct ctx *x = user;

  printf ("AUTH OK %.*s %s\n", (int) username.len,
          (const char *) username.data, x->method);
  fflush (stdout);
  x->authed = 1;
  /* The connection protocol is not here yet: say goodbye.  */
  return gf_conn_disconnect (x->c, now_us (), GF_DISCONNECT_BY_APPLICATION,
                             "authenticated") != GF_OK;
}

static int
auth_disconnect (void *user, uint32_t reason)
{
  struct ctx *x = user;

  printf ("AUTH FAILED %u\n", (unsigned) reason);
  fflush (stdout);
  gf_conn_disconnect (x->c, now_us (), reason, NULL);
  return 0;
}

static gf_key *
read_key (const char *file)
{
  char text[8192];
  FILE *f = fopen (file, "r");
  size_t n;
  gf_key *key = NULL;

  if (f == NULL)
    return NULL;
  n = fread (text, 1, sizeof text, f);
  fclose (f);
  if (gf_key_from_openssh_private (&key, text, n) != GF_OK)
    return NULL;
  return key;
}

int
main (int argc, char **argv)
{
  struct sockaddr_in sa;
  int ls, one = 1, port, r, i, hostbound = 0;
  char fp[64];
  struct ctx x;
  gf_key *key;
  gf_conn_config cfg;
  gf_conn_events ev;
  gf_auth_server_config ac;
  gf_auth_server_events ae;

  if (argc < 3)
    {
      fprintf (stderr, "usage: interop-server HOSTKEY PORT [options]\n");
      return 2;
    }
  memset (&x, 0, sizeof x);
  port = atoi (argv[2]);
  key = read_key (argv[1]);
  if (key == NULL)
    {
      fprintf (stderr, "cannot read host key\n");
      return 2;
    }
  for (i = 3; i < argc; i++)
    {
      if (strcmp (argv[i], "--auth-key") == 0 && i + 1 < argc)
        {
          x.authorized = read_key (argv[++i]);
          if (x.authorized == NULL)
            return 2;
        }
      else if (strcmp (argv[i], "--password") == 0 && i + 1 < argc)
        x.password = argv[++i];
      else if (strcmp (argv[i], "--code") == 0 && i + 1 < argc)
        x.code = argv[++i];
      else if (strcmp (argv[i], "--hostbound") == 0)
        hostbound = 1;
      else
        {
          fprintf (stderr, "bad option %s\n", argv[i]);
          return 2;
        }
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
  x.fd = accept (ls, NULL, NULL);
  if (x.fd < 0)
    {
      perror ("accept");
      return 2;
    }

  memset (&cfg, 0, sizeof cfg);
  cfg.host_keys = &key;
  cfg.nhost_keys = 1;
  cfg.announce_hostbound = hostbound;
  memset (&ev, 0, sizeof ev);
  ev.user = &x;
  ev.write = on_write;
  ev.established = on_established;
  ev.message = on_message;
  ev.closed = on_closed;
  memset (&ac, 0, sizeof ac);
  ac.methods = (x.authorized ? GF_AUTH_PUBLICKEY : 0)
    | (x.password ? GF_AUTH_PASSWORD : 0) | (x.code ? GF_AUTH_KBDINT : 0);
  ac.hostbound = hostbound;
  memset (&ae, 0, sizeof ae);
  ae.user = &x;
  ae.send = auth_send;
  ae.request = auth_request;
  ae.kbdint_response = auth_kbd_response;
  ae.authenticated = auth_done;
  ae.disconnect = auth_disconnect;
  if (gf_conn_server_new (&x.c, &cfg, &ev) != GF_OK
      || gf_auth_server_new (&x.auth, &ac, &ae) != GF_OK
      || gf_conn_start (x.c, now_us ()) != GF_OK)
    {
      fprintf (stderr, "cannot start\n");
      return 2;
    }
  r = drive (x.c, x.fd, NULL, NULL, 20000);
  printf ("DONE %d\n", r);
  gf_auth_server_free (x.auth);
  gf_conn_free (x.c);
  gf_key_free (key);
  gf_key_free (x.authorized);
  close (x.fd);
  return x.established ? 0 : 1;
}
