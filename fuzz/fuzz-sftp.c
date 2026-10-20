#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/wire.h>
#include <foxtrot/sftp.h>

#include "fuzz-common.h"

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  return 0;
}

struct ctx
{
  gf_sftp_server *s;
  gf_sftp_client *c;
  unsigned schedule, counter;
  int stop;
};

static long
w_write (void *u, const uint8_t *d, size_t n)
{
  struct ctx *x = u;

  (void) d;
  /* A peer that takes part of it, now and then.  */
  if (x->schedule & 0x80 && (x->counter++ % 3) == 0 && n > 1)
    return (long) (n / 2);
  return (long) n;
}

static void
w_disconnect (void *u, int status)
{
  struct ctx *x = u;

  (void) status;
  x->stop = 1;
}

static int
s_request (void *u, const gf_sftp_request *r)
{
  struct ctx *x = u;
  static const gf_sftp_attrs attrs = { GF_FILEXFER_ATTR_SIZE | GF_FILEXFER_ATTR_PERMISSIONS,
                                       1234, 0, 0, 0644, 0, 0 };
  gf_sftp_name name;

  /* Every kind of answer, whether or not it fits: the library has to say so.  */
  switch ((x->counter++ + r->type) % 6)
    {
    case 0:
      (void) gf_sftp_server_status (x->s, r->id, GF_FX_OK, "ok");
      return 0;
    case 1:
      (void) gf_sftp_server_handle (x->s, r->id, (const uint8_t *) "h", 1);
      return 0;
    case 2:
      (void) gf_sftp_server_data (x->s, r->id, (const uint8_t *) "data", 4);
      return 0;
    case 3:
      memset (&name, 0, sizeof name);
      name.filename = (gf_slice) { (const uint8_t *) "f", 1 };
      name.longname = (gf_slice) { (const uint8_t *) "-rw f", 5 };
      name.attrs = attrs;
      (void) gf_sftp_server_names (x->s, r->id, 1, &name);
      return 0;
    case 4:
      (void) gf_sftp_server_attrs (x->s, r->id, &attrs);
      return 0;
    default:
      (void) gf_sftp_server_status (x->s, r->id, GF_FX_FAILURE, "no");
      return 0;
    }
}

static int
c_ready (void *u)
{
  struct ctx *x = u;
  uint8_t h[1] = { 'h' };
  gf_sftp_attrs a;

  memset (&a, 0, sizeof a);
  /* A burst of requests, so that the replies fed in have something to answer. */
  (void) gf_sftp_client_stat (x->c, "/a", NULL, NULL);
  (void) gf_sftp_client_open (x->c, "/a", 1, &a, NULL, NULL);
  (void) gf_sftp_client_opendir (x->c, "/", NULL, NULL);
  (void) gf_sftp_client_readdir (x->c, h, 1, NULL, NULL);
  (void) gf_sftp_client_read (x->c, h, 1, 0, 100, NULL, NULL);
  (void) gf_sftp_client_write (x->c, h, 1, 0, (const uint8_t *) "abc", 3, NULL, NULL);
  (void) gf_sftp_client_realpath (x->c, ".", NULL, NULL);
  (void) gf_sftp_client_readlink (x->c, "/l", NULL, NULL);
  (void) gf_sftp_client_extended (x->c, "x@y", (const uint8_t *) "z", 1, NULL, NULL);
  (void) gf_sftp_client_close (x->c, h, 1, NULL, NULL);
  return 0;
}

static int
c_response (void *u, const gf_sftp_response *r)
{
  gf_sftp_response copy = *r;
  gf_sftp_name n;
  unsigned count = 0;

  (void) u;
  while (copy.type == GF_FXP_NAME && gf_sftp_response_next_name (&copy, &n))
    if (++count > 100000)
      abort ();
  return 0;
}

/* The server side: raw bytes of requests in pieces.  The client side: the
   server's VERSION and then raw bytes of replies, after a burst of
   requests.  The first byte says which, and how the pieces are cut.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct ctx x;
  size_t chunk, pos = 0;

  if (size < 3)
    return 0;
  memset (&x, 0, sizeof x);
  x.schedule = data[1];
  chunk = 1 + data[2] % 100;
  if (!(data[0] & 1))
    {
      gf_sftp_server_config cfg;
      gf_sftp_server_events ev;

      memset (&cfg, 0, sizeof cfg);
      cfg.max_packet = 4096;
      cfg.max_requests = 8;
      cfg.max_output = 8192;
      memset (&ev, 0, sizeof ev);
      ev.user = &x;
      ev.write = w_write;
      ev.request = s_request;
      ev.disconnect = w_disconnect;
      if (gf_sftp_server_new (&x.s, &cfg, &ev) != GF_OK)
        abort ();
      data += 3;
      size -= 3;
      while (!x.stop && pos < size)
        {
          size_t n = size - pos < chunk ? size - pos : chunk;

          (void) gf_sftp_server_input (x.s, data + pos, n);
          (void) gf_sftp_server_writable (x.s);
          pos += n;
        }
      gf_sftp_server_free (x.s);
    }
  else
    {
      gf_sftp_client_config cfg;
      gf_sftp_client_events ev;
      static const uint8_t version[] = { 0, 0, 0, 5, 2, 0, 0, 0, 3 };

      memset (&cfg, 0, sizeof cfg);
      cfg.max_packet = 4096;
      cfg.max_requests = 16;
      cfg.max_output = 8192;
      memset (&ev, 0, sizeof ev);
      ev.user = &x;
      ev.write = w_write;
      ev.ready = c_ready;
      ev.response = c_response;
      ev.disconnect = w_disconnect;
      if (gf_sftp_client_new (&x.c, &cfg, &ev) != GF_OK)
        abort ();
      data += 3;
      size -= 3;
      if (gf_sftp_client_start (x.c) == GF_OK
          && gf_sftp_client_input (x.c, version, sizeof version) == GF_OK)
        while (!x.stop && pos < size)
          {
            size_t n = size - pos < chunk ? size - pos : chunk;

            (void) gf_sftp_client_input (x.c, data + pos, n);
            (void) gf_sftp_client_writable (x.c);
            pos += n;
          }
      gf_sftp_client_free (x.c);
    }
  return 0;
}
