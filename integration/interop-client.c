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

/* A foxtrot SSH client for talking to OpenSSH's sshd.

     interop-client PORT [--kex NAME] [--cipher NAME] [--hostkey ALG]
                         [--fingerprint SHA256:...] [--no-auth]
                         [--user NAME] [--key FILE] [--password PW]
                         [--kbd ANSWER] [--rekey]

   Connects to 127.0.0.1:PORT, completes the transport handshake with the
   given algorithms (default: the policy's), asks the application to trust
   the host key (it does, unless --fingerprint says which one to expect),
   and requests the ssh-userauth service.  With --no-auth it stops there.
   Otherwise it authenticates as NAME (default "nobody") with the OpenSSH
   private key in FILE, the password PW, or by answering every
   keyboard-interactive prompt with ANSWER, as given; with --rekey it then
   forces a key exchange and waits for it.  Prints "KEX ...", "HOSTKEY ...",
   "SERVICE ...", "AUTH OK" or "AUTH FAILED", "REKEYED ..." and "DONE", and
   exits 0 if all that was asked went well.  */

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
  gf_auth_client *auth;
  const char *expect_fp, *kbd_answer;
  int rekey, no_auth;
  int established, service, authed, auth_failed, rekeyed, banners;
};

static int
on_write (void *user, const uint8_t *data, size_t len)
{
  return sock_write (((struct ctx *) user)->fd, data, len);
}

static int
on_host_key (void *user, const gf_key *key)
{
  struct ctx *x = user;
  char fp[64];

  gf_key_fingerprint (key, fp, sizeof fp);
  printf ("HOSTKEY %s %s\n", gf_key_type_name (key), fp);
  if (x->expect_fp && strcmp (x->expect_fp, fp) != 0)
    {
      printf ("HOSTKEY MISMATCH\n");
      return 1;
    }
  return 0;
}

static int
on_established (void *user, const gf_conn_info *info)
{
  struct ctx *x = user;

  printf ("KEX %s %s %s\n", gf_kex_name (info->kex),
          gf_cipher_name (info->cipher_c2s), gf_sigalg_name (info->hostkey_alg));
  printf ("SERVER %.*s\n", (int) info->peer_software.len,
          (const char *) info->peer_software.data);
  x->established = 1;
  return gf_conn_request_service (x->c, now_us (), "ssh-userauth") != GF_OK;
}

static int
on_extension (void *user, gf_slice name, gf_slice value)
{
  struct ctx *x = user;

  return x->auth && gf_auth_client_extension (x->auth, name, value) != GF_OK;
}

static int
on_service_accepted (void *user, gf_slice name)
{
  struct ctx *x = user;
  const gf_conn_info *info = gf_conn_get_info (x->c);
  size_t bl;
  const uint8_t *blob = gf_key_blob (info->host_key, &bl);

  printf ("SERVICE %.*s\n", (int) name.len, (const char *) name.data);
  x->service = 1;
  if (x->no_auth)
    return 0;
  return gf_auth_client_start (x->auth, now_us (), info->session_id,
                               info->session_id_len, blob, bl) != GF_OK;
}

static int
on_rekeyed (void *user, const gf_conn_info *info)
{
  struct ctx *x = user;

  printf ("REKEYED %s\n", gf_kex_name (info->kex));
  x->rekeyed++;
  return 0;
}

static int
on_message (void *user, const uint8_t *p, size_t n)
{
  struct ctx *x = user;

  if (p[0] >= 50 && p[0] <= 79 && x->auth)
    {
      int r = gf_auth_client_input (x->auth, now_us (), p, n);

      if (r != GF_OK && r != GF_ERR_AUTH)
        printf ("AUTH ERROR %d\n", r);
      return r != GF_OK && r != GF_ERR_AUTH;
    }
  return 0;
}

static void
on_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  (void) user;
  printf ("CLOSED %d %u %.*s\n", error, (unsigned) reason, (int) text.len,
          text.data ? (const char *) text.data : "");
}

static int
auth_send (void *user, const uint8_t *p, size_t n)
{
  struct ctx *x = user;

  return gf_conn_send (x->c, now_us (), p, n) != GF_OK;
}

static void
auth_banner (void *user, gf_slice text)
{
  (void) text;
  ((struct ctx *) user)->banners++;
}

static int
auth_kbdint (void *user, gf_slice name, gf_slice instr, size_t n,
             const gf_slice *prompts, const int *echo)
{
  struct ctx *x = user;
  const char *answers[GF_AUTH_MAX_PROMPTS];
  size_t i;

  (void) name;
  (void) instr;
  (void) prompts;
  (void) echo;
  for (i = 0; i < n; i++)
    answers[i] = x->kbd_answer;
  return gf_auth_client_kbdint_respond (x->auth, now_us (), n, answers)
    != GF_OK;
}

static int
auth_ok (void *user)
{
  struct ctx *x = user;

  printf ("AUTH OK\n");
  x->authed = 1;
  if (x->rekey)
    return gf_conn_rekey (x->c, now_us ()) != GF_OK;
  return 0;
}

static int
auth_failed (void *user)
{
  printf ("AUTH FAILED\n");
  ((struct ctx *) user)->auth_failed = 1;
  return 0;
}

static int
finished (void *user)
{
  struct ctx *x = user;

  if (x->no_auth)
    return x->service;
  if (x->auth_failed)
    return 1;
  return x->authed && (!x->rekey || x->rekeyed);
}

int
main (int argc, char **argv)
{
  struct sockaddr_in sa;
  struct ctx x;
  gf_conn_config cfg;
  gf_conn_events ev;
  gf_auth_client_config ac;
  gf_auth_client_events ae;
  enum gf_kex kex = 0;
  enum gf_cipher cipher = 0;
  enum gf_sigalg alg = 0;
  const char *user = "nobody", *keyfile = NULL, *password = NULL;
  gf_key *key = NULL;
  const gf_key *keys[1];
  int i, r;

  if (argc < 2)
    {
      fprintf (stderr, "usage: interop-client PORT [options]\n");
      return 2;
    }
  memset (&x, 0, sizeof x);
  memset (&cfg, 0, sizeof cfg);
  for (i = 2; i < argc; i++)
    {
      if (strcmp (argv[i], "--kex") == 0 && i + 1 < argc)
        {
          kex = gf_kex_from_name (argv[i + 1], strlen (argv[i + 1]));
          i++;
        }
      else if (strcmp (argv[i], "--cipher") == 0 && i + 1 < argc)
        {
          cipher = gf_cipher_from_name (argv[i + 1], strlen (argv[i + 1]));
          i++;
        }
      else if (strcmp (argv[i], "--hostkey") == 0 && i + 1 < argc)
        {
          alg = gf_sigalg_from_name (argv[i + 1], strlen (argv[i + 1]));
          i++;
        }
      else if (strcmp (argv[i], "--fingerprint") == 0 && i + 1 < argc)
        x.expect_fp = argv[++i];
      else if (strcmp (argv[i], "--user") == 0 && i + 1 < argc)
        user = argv[++i];
      else if (strcmp (argv[i], "--key") == 0 && i + 1 < argc)
        keyfile = argv[++i];
      else if (strcmp (argv[i], "--password") == 0 && i + 1 < argc)
        password = argv[++i];
      else if (strcmp (argv[i], "--kbd") == 0 && i + 1 < argc)
        x.kbd_answer = argv[++i];
      else if (strcmp (argv[i], "--rekey") == 0)
        x.rekey = 1;
      else if (strcmp (argv[i], "--no-auth") == 0)
        x.no_auth = 1;
      else
        {
          fprintf (stderr, "bad option %s\n", argv[i]);
          return 2;
        }
    }
  if (kex)
    {
      cfg.prefs.kex = &kex;
      cfg.prefs.nkex = 1;
    }
  if (cipher)
    {
      cfg.prefs.ciphers = &cipher;
      cfg.prefs.nciphers = 1;
    }
  if (alg)
    {
      cfg.prefs.sigalgs = &alg;
      cfg.prefs.nsigalgs = 1;
    }
  if (keyfile)
    {
      char text[8192];
      FILE *f = fopen (keyfile, "r");
      size_t n;

      if (f == NULL)
        {
          perror (keyfile);
          return 2;
        }
      n = fread (text, 1, sizeof text, f);
      fclose (f);
      if (gf_key_from_openssh_private (&key, text, n) != GF_OK)
        {
          fprintf (stderr, "cannot read %s\n", keyfile);
          return 2;
        }
      keys[0] = key;
    }

  x.fd = socket (AF_INET, SOCK_STREAM, 0);
  memset (&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  sa.sin_port = htons ((uint16_t) atoi (argv[1]));
  if (connect (x.fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      perror ("connect");
      return 2;
    }
  memset (&ev, 0, sizeof ev);
  ev.user = &x;
  ev.write = on_write;
  ev.host_key = on_host_key;
  ev.established = on_established;
  ev.rekeyed = on_rekeyed;
  ev.service_accepted = on_service_accepted;
  ev.extension = on_extension;
  ev.message = on_message;
  ev.closed = on_closed;
  if (gf_conn_client_new (&x.c, &cfg, &ev) != GF_OK)
    {
      fprintf (stderr, "cannot start\n");
      return 2;
    }
  if (!x.no_auth)
    {
      memset (&ac, 0, sizeof ac);
      ac.user = user;
      ac.keys = keyfile ? keys : NULL;
      ac.nkeys = keyfile ? 1 : 0;
      ac.password = password;
      memset (&ae, 0, sizeof ae);
      ae.user = &x;
      ae.send = auth_send;
      ae.banner = auth_banner;
      ae.kbdint = x.kbd_answer ? auth_kbdint : NULL;
      ae.authenticated = auth_ok;
      ae.failed = auth_failed;
      if (gf_auth_client_new (&x.auth, &ac, &ae) != GF_OK)
        {
          fprintf (stderr, "cannot start authentication\n");
          return 2;
        }
    }
  if (gf_conn_start (x.c, now_us ()) != GF_OK)
    return 2;
  r = drive (x.c, x.fd, finished, &x, 20000);
  if (!gf_conn_is_closed (x.c))
    gf_conn_disconnect (x.c, now_us (), GF_DISCONNECT_BY_APPLICATION, "done");
  printf ("DONE %d authed=%d rekeyed=%d\n", r, x.authed, x.rekeyed);
  gf_auth_client_free (x.auth);
  gf_conn_free (x.c);
  gf_key_free (key);
  close (x.fd);
  if (x.no_auth)
    return x.service && r >= 0 ? 0 : 1;
  return x.authed && r >= 0 && (!x.rekey || x.rekeyed) ? 0 : 1;
}
