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
                         [--fingerprint SHA256:...] [--rekey]

   Connects to 127.0.0.1:PORT, completes the transport handshake with the
   given algorithms (default: the policy's), asks the application to trust
   the host key (it does, unless --fingerprint says which one to expect),
   requests the ssh-userauth service and sends an authentication request
   with the method "none", which sshd answers with the list of methods it
   offers.  With --rekey it then forces a key exchange and sends the request
   again.  Prints "FAILURE methods" for each answer, "KEX ..." and "HOSTKEY
   ..." once the transport is established, and exits 0 if all went well.  */

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
  const char *expect_fp;
  int rekey;
  int established, rekeyed, failures, wanted_failures, bad;
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
send_none (struct ctx *x)
{
  uint8_t m[128];
  gf_writer w;

  gf_writer_init (&w, m, sizeof m);
  gf_wr_u8 (&w, 50);		/* USERAUTH_REQUEST.  */
  gf_wr_cstring (&w, "nobody");
  gf_wr_cstring (&w, "ssh-connection");
  gf_wr_cstring (&w, "none");
  return gf_conn_send (x->c, now_us (), m, w.len);
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
on_rekeyed (void *user, const gf_conn_info *info)
{
  struct ctx *x = user;

  printf ("REKEYED %s\n", gf_kex_name (info->kex));
  x->rekeyed++;
  return send_none (x) != GF_OK;
}

static int
on_service_accepted (void *user, gf_slice name)
{
  struct ctx *x = user;

  printf ("SERVICE %.*s\n", (int) name.len, (const char *) name.data);
  return send_none (x) != GF_OK;
}

static int
on_message (void *user, const uint8_t *p, size_t n)
{
  struct ctx *x = user;
  gf_reader r;
  gf_slice methods;
  int partial;

  gf_reader_init (&r, p + 1, n - 1);
  if (p[0] == 51 && gf_rd_namelist (&r, &methods) == GF_OK
      && gf_rd_bool (&r, &partial) == GF_OK)
    {
      printf ("FAILURE %.*s\n", (int) methods.len, (const char *) methods.data);
      x->failures++;
      if (x->rekey && x->failures == 1)
        return gf_conn_rekey (x->c, now_us ()) != GF_OK;
      return 0;
    }
  x->bad = 1;
  printf ("UNEXPECTED %d\n", p[0]);
  return 1;
}

static void
on_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  (void) user;
  printf ("CLOSED %d %u %.*s\n", error, (unsigned) reason, (int) text.len,
          text.data ? (const char *) text.data : "");
}

static int
finished (void *user)
{
  struct ctx *x = user;

  return x->failures >= (x->rekey ? 2 : 1);
}

int
main (int argc, char **argv)
{
  struct sockaddr_in sa;
  struct ctx x;
  gf_conn_config cfg;
  gf_conn_events ev;
  enum gf_kex kex = 0;
  enum gf_cipher cipher = 0;
  enum gf_sigalg alg = 0;
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
      else if (strcmp (argv[i], "--rekey") == 0)
        x.rekey = 1;
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
  ev.message = on_message;
  ev.closed = on_closed;
  if (gf_conn_client_new (&x.c, &cfg, &ev) != GF_OK
      || gf_conn_start (x.c, now_us ()) != GF_OK)
    {
      fprintf (stderr, "cannot start\n");
      return 2;
    }
  r = drive (x.c, x.fd, finished, &x, 20000);
  if (!gf_conn_is_closed (x.c))
    gf_conn_disconnect (x.c, now_us (), GF_DISCONNECT_BY_APPLICATION, "done");
  printf ("DONE %d failures=%d rekeyed=%d\n", r, x.failures, x.rekeyed);
  gf_conn_free (x.c);
  close (x.fd);
  return finished (&x) && !x.bad && r >= 0 && (!x.rekey || x.rekeyed) ? 0 : 1;
}
