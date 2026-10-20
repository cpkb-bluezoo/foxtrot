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

  /* An extension: every kind of reply, right or wrong for it.  */
  if (r->type == GF_FXP_EXTENDED)
    {
      gf_sftp_ext_request e;
      static const char *nm[GF_SFTP_MAX_IDS];
      size_t k;
      gf_sftp_statvfs sv;
      gf_sftp_limits lim;

      memset (&sv, 0, sizeof sv);
      memset (&lim, 0, sizeof lim);
      for (k = 0; k < GF_SFTP_MAX_IDS; k++)
        nm[k] = "a";
      if (gf_sftp_request_extension (r, &e) == GF_OK
          && e.which != GF_SFTPX_UNKNOWN)
        switch (x->counter++ % 6)
          {
          case 0:
            (void) gf_sftp_server_statvfs (x->s, r->id, &sv);
            return 0;
          case 1:
            (void) gf_sftp_server_limits (x->s, r->id, &lim);
            return 0;
          case 2:
            (void) gf_sftp_server_users_groups (x->s, r->id, e.uids.len / 4 > 2 ? 2 : e.uids.len / 4,
                                                nm, e.gids.len / 4 > 2 ? 2 : e.gids.len / 4, nm);
            (void) gf_sftp_server_users_groups (x->s, r->id, e.uids.len / 4, nm, e.gids.len / 4, nm);
            return 0;
          case 3:
            (void) gf_sftp_server_extended_reply (x->s, r->id, (const uint8_t *) "x", 1);
            return 0;
          default:
            break;
          }
    }
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
  (void) gf_sftp_client_posix_rename (x->c, "/a", "/b", NULL, NULL);
  (void) gf_sftp_client_statvfs (x->c, "/", NULL, NULL);
  (void) gf_sftp_client_fstatvfs (x->c, h, 1, NULL, NULL);
  (void) gf_sftp_client_hardlink (x->c, "/a", "/b", NULL, NULL);
  (void) gf_sftp_client_fsync (x->c, h, 1, NULL, NULL);
  (void) gf_sftp_client_lsetstat (x->c, "/a", &a, NULL, NULL);
  (void) gf_sftp_client_limits (x->c, NULL, NULL);
  (void) gf_sftp_client_expand_path (x->c, "~", NULL, NULL);
  (void) gf_sftp_client_copy_data (x->c, h, 1, 0, 0, h, 1, 0, NULL, NULL);
  {
    static const uint32_t ids[2] = { 0, 1 };

    (void) gf_sftp_client_users_groups_by_id (x->c, ids, 2, ids, 1, NULL, NULL);
  }
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
  {
    gf_sftp_statvfs sv;
    gf_sftp_limits lim;
    gf_slice us, gs, one;

    (void) gf_sftp_response_statvfs (r, &sv);
    (void) gf_sftp_response_limits (r, &lim);
    if (gf_sftp_response_users_groups (r, &us, &gs))
      {
        while (gf_sftp_string_next (&us, &one))
          count++;
        while (gf_sftp_string_next (&gs, &one))
          count++;
      }
  }
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
      cfg.extensions = gf_sftp_standard_extensions (&cfg.nextensions);
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
      uint8_t version[1024];
      gf_writer vw;
      size_t ne, ei;
      const gf_sftp_extension *ex = gf_sftp_standard_extensions (&ne);

      /* The server's VERSION, with every extension it can have.  */
      gf_writer_init (&vw, version, sizeof version);
      gf_wr_u32 (&vw, 0);
      gf_wr_u8 (&vw, 2);
      gf_wr_u32 (&vw, 3);
      for (ei = 0; ei < ne; ei++)
        {
          gf_wr_cstring (&vw, ex[ei].name);
          gf_wr_cstring (&vw, ex[ei].data);
        }
      version[0] = (uint8_t) ((vw.len - 4) >> 24);
      version[1] = (uint8_t) ((vw.len - 4) >> 16);
      version[2] = (uint8_t) ((vw.len - 4) >> 8);
      version[3] = (uint8_t) (vw.len - 4);

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
          && gf_sftp_client_input (x.c, version, vw.len) == GF_OK)
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
