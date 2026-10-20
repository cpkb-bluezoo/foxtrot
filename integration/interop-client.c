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
                         [--kbd ANSWER] [--rekey] [--rekey-bytes N]
                         [--exec COMMAND [--send N] [--check-pattern]]
                         [--sftp "COMMAND; COMMAND; ..."]

   Connects to 127.0.0.1:PORT, completes the transport handshake with the
   given algorithms (default: the policy's), asks the application to trust
   the host key (it does, unless --fingerprint says which one to expect),
   and requests the ssh-userauth service.  With --no-auth it stops there.
   Otherwise it authenticates as NAME (default "nobody") with the OpenSSH
   private key in FILE, the password PW, or by answering every
   keyboard-interactive prompt with ANSWER, as given; with --rekey it then
   forces a key exchange and waits for it; --rekey-bytes N makes the
   connection rekey by itself every N bytes.  With --exec it then runs
   COMMAND in a session channel, sends N bytes of the test pattern to its
   input (--send), checks that what it prints is the test pattern too
   (--check-pattern), and waits for the exit status and the end of the
   channel.  With --sftp it runs the commands in an SFTP session instead:

     put LOCAL REMOTE      get REMOTE LOCAL      ls DIR
     mkdir DIR   rmdir DIR   rm FILE   mv OLD NEW   ln TARGET LINK
     stat PATH   lstat PATH   realpath PATH   readlink PATH   chmod OCTAL PATH

   with up to 16 reads or writes of 32 KiB in flight, and prints
   "RESULT command status" (0 is success), and for a listing "LS name size
   perms", "STAT size=n perms=o", "NAME name".  Prints "KEX ...", "HOSTKEY ...", "SERVICE ...", "AUTH OK" or
   "AUTH FAILED", "REKEYED ...", "OUT text" (output of up to 200 bytes),
   "RECEIVED n", "STDERR n", "SENT n", "EXIT status" and "DONE", and exits 0
   if all that was asked went well.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "interop-util.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <foxtrot/auth.h>
#include <foxtrot/chan.h>
#include <foxtrot/sftp.h>
#include <foxtrot/key.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

struct ctx
{
  int fd;
  gf_conn *c;
  gf_auth_client *auth;
  gf_chans *chans;
  const char *expect_fp, *kbd_answer, *command;
  int rekey, no_auth, check_pattern;
  int established, service, authed, auth_failed, rekeyed, banners;
  uint64_t send_total, sent, received, stderr_bytes;
  uint32_t chan;
  int opened, exited, chan_closed, bad_data, eof_sent;
  uint32_t exit_status;
  char out[256];
  size_t outn;
  /* SFTP.  */
  const char *sftp_script;
  gf_sftp_client *sftp;
  char *cmds[64];
  size_t ncmds, cur;
  int sftp_done;
  /* The transfer or listing in progress.  */
  int lfd;
  uint8_t handle[GF_SFTP_MAX_HANDLE];
  size_t hlen;
  uint64_t xoff, xtotal;
  unsigned outstanding;
  int eof, failed_cmd, closing;
  char *argv_[4];
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
  return x->chans && x->authed && gf_chans_resume (x->chans) != GF_OK;
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
  if (p[0] >= 80 && p[0] <= 100 && x->chans && x->authed)
    return gf_chans_input (x->chans, p, n) != GF_OK;
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
  if (x->command || x->sftp_script)
    return gf_chans_open_session (x->chans, &x->chan, 0, 0) != GF_OK;
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
chans_send (void *user, const uint8_t *p, size_t n)
{
  struct ctx *x = user;

  return gf_conn_send (x->c, now_us (), p, n);
}

static int
chans_disconnect (void *user, uint32_t reason)
{
  struct ctx *x = user;

  gf_conn_disconnect (x->c, now_us (), reason, NULL);
  return 0;
}

/* Send as much of the input as the window allows, then EOF.  */
static int
push (struct ctx *x)
{
  uint8_t buf[16384];

  while (x->sent < x->send_total)
    {
      size_t n = sizeof buf, i;
      long r;

      if (n > x->send_total - x->sent)
        n = (size_t) (x->send_total - x->sent);
      for (i = 0; i < n; i++)
        buf[i] = pattern_at (x->sent + i);
      r = gf_chans_send_data (x->chans, x->chan, buf, n);
      if (r == GF_ERR_AGAIN || r == 0)
        return 0;
      if (r < 0)
        return 1;
      x->sent += (uint64_t) r;
      if ((size_t) r < n)
        return 0;
    }
  if (!x->eof_sent && x->send_total > 0)
    {
      x->eof_sent = 1;
      return gf_chans_send_eof (x->chans, x->chan) != GF_OK;
    }
  return 0;
}

static int
chan_confirmed (void *user, uint32_t id)
{
  struct ctx *x = user;

  (void) id;
  x->opened = 1;
  if (x->sftp_script)
    return gf_chans_request_subsystem (x->chans, x->chan, "sftp", 1) != GF_OK;
  return gf_chans_request_exec (x->chans, x->chan, x->command, 1) != GF_OK;
}

static int
chan_failed (void *user, uint32_t id, uint32_t reason, gf_slice text)
{
  (void) user;
  (void) id;
  printf ("OPEN FAILED %u %.*s\n", (unsigned) reason, (int) text.len,
          (const char *) text.data);
  return 0;
}

static int
chan_reply (void *user, uint32_t id, int ok)
{
  struct ctx *x = user;

  (void) id;
  if (!ok)
    {
      printf ("EXEC REFUSED\n");
      return 1;
    }
  if (x->sftp_script)
    return gf_sftp_client_start (x->sftp) != GF_OK;
  return push (x);
}

static int
chan_writable (void *user, uint32_t id)
{
  struct ctx *x = user;

  (void) id;
  if (x->sftp_script)
    return x->sftp && gf_sftp_client_writable (x->sftp) != GF_OK;
  return push (x);
}

static int
chan_data (void *user, uint32_t id, const uint8_t *d, size_t n)
{
  struct ctx *x = user;
  size_t i;

  if (x->sftp_script)
    {
      if (gf_sftp_client_input (x->sftp, d, n) != GF_OK)
        return gf_chans_close (x->chans, x->chan) != GF_OK;
      return gf_chans_consumed (x->chans, id, n) != GF_OK;
    }
  for (i = 0; i < n; i++)
    {
      if (x->check_pattern && d[i] != pattern_at (x->received + i))
        x->bad_data = 1;
      if (x->outn < sizeof x->out - 1)
        x->out[x->outn++] = (char) d[i];
    }
  x->received += n;
  return gf_chans_consumed (x->chans, id, n) != GF_OK;
}

static int
chan_ext (void *user, uint32_t id, uint32_t type, const uint8_t *d, size_t n)
{
  struct ctx *x = user;

  (void) type;
  (void) d;
  x->stderr_bytes += n;
  return gf_chans_consumed (x->chans, id, n) != GF_OK;
}

static int
chan_eof (void *user, uint32_t id)
{
  (void) user;
  (void) id;
  return 0;
}

static int
chan_request (void *user, const gf_chan_request *q)
{
  struct ctx *x = user;

  if (q->type == GF_REQ_EXIT_STATUS)
    {
      x->exit_status = q->status;
      x->exited = 1;
    }
  return 0;
}

static int
chan_closed (void *user, uint32_t id)
{
  struct ctx *x = user;

  (void) id;
  x->chan_closed = 1;
  return 0;
}


/* ---- SFTP ---- */

enum { T_OPEN = 1, T_CLOSE, T_XFER, T_READDIR, T_PLAIN };

struct tag
{
  int kind;
  uint64_t offset;
  uint32_t len;
};

static struct tag *
mktag (int kind, uint64_t offset, uint32_t len)
{
  struct tag *t = malloc (sizeof *t);

  t->kind = kind;
  t->offset = offset;
  t->len = len;
  return t;
}

static long
sftp_write_cb (void *user, const uint8_t *d, size_t n)
{
  struct ctx *x = user;
  /* Offer it all: the library takes what the window allows, and a short
     result is what makes it tell us when to try again.  */
  long r = gf_chans_send_data (x->chans, x->chan, d, n);

  return r == GF_ERR_AGAIN ? 0 : r;
}

static int next_command (struct ctx *x);

static int
finish_command (struct ctx *x, const char *name, uint32_t status)
{
  printf ("RESULT %s %u\n", name, (unsigned) status);
  if (x->lfd >= 0)
    {
      close (x->lfd);
      x->lfd = -1;
    }
  x->cur++;
  return next_command (x);
}

/* Parse command CUR into words.  */
static int
words (struct ctx *x, char **w, int max)
{
  char *p = x->cmds[x->cur];
  int n = 0;

  while (*p && n < max)
    {
      while (*p == ' ')
        p++;
      if (!*p)
        break;
      w[n++] = p;
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = '\0';
    }
  return n;
}

static int
pump_xfer (struct ctx *x, int put)
{
  while (!x->eof && x->outstanding < 16)
    {
      uint8_t buf[32768];

      if (put)
        {
          ssize_t n = pread (x->lfd, buf, sizeof buf, (off_t) x->xoff);
          int r;

          if (n <= 0)
            {
              x->eof = 1;
              break;
            }
          r = gf_sftp_client_write (x->sftp, x->handle, x->hlen, x->xoff, buf,
                                    (size_t) n, mktag (T_XFER, x->xoff, (uint32_t) n),
                                    NULL);
          if (r == GF_ERR_AGAIN)
            {
              x->eof = 0;
              return 0;
            }
          if (r != GF_OK)
            return 1;
          x->xoff += (uint64_t) n;
        }
      else
        {
          int r = gf_sftp_client_read (x->sftp, x->handle, x->hlen, x->xoff,
                                       32768, mktag (T_XFER, x->xoff, 32768),
                                       NULL);

          if (r == GF_ERR_AGAIN)
            return 0;
          if (r != GF_OK)
            return 1;
          x->xoff += 32768;
        }
      x->outstanding++;
    }
  if (x->eof && x->outstanding == 0 && !x->closing)
    {
      x->closing = 1;
      return gf_sftp_client_close (x->sftp, x->handle, x->hlen,
                                   mktag (T_CLOSE, 0, 0), NULL) != GF_OK;
    }
  return 0;
}

static int
next_command (struct ctx *x)
{
  char *w[4];
  int n;
  gf_sftp_attrs a;
  void *t;
  int r = GF_OK;

  if (x->cur >= x->ncmds)
    {
      x->sftp_done = 1;
      return 0;
    }
  memset (w, 0, sizeof w);
  n = words (x, w, 4);
  if (n == 0)
    return 1;
  memset (&a, 0, sizeof a);
  x->closing = x->eof = 0;
  x->outstanding = 0;
  x->xoff = 0;
  t = mktag (T_PLAIN, 0, 0);
  if (strcmp (w[0], "put") == 0 && n == 3)
    {
      x->lfd = open (w[1], O_RDONLY);
      if (x->lfd < 0)
        return finish_command (x, "put", 255);
      a.flags = GF_FILEXFER_ATTR_PERMISSIONS;
      a.permissions = 0644;
      free (t);
      r = gf_sftp_client_open (x->sftp, w[2], GF_FXF_WRITE | GF_FXF_CREAT
                               | GF_FXF_TRUNC, &a, mktag (T_OPEN, 0, 0), NULL);
    }
  else if (strcmp (w[0], "get") == 0 && n == 3)
    {
      free (t);
      r = gf_sftp_client_open (x->sftp, w[1], GF_FXF_READ, &a,
                               mktag (T_OPEN, 0, 0), NULL);
    }
  else if (strcmp (w[0], "ls") == 0 && n == 2)
    {
      free (t);
      r = gf_sftp_client_opendir (x->sftp, w[1], mktag (T_OPEN, 0, 0), NULL);
    }
  else if (strcmp (w[0], "mkdir") == 0 && n == 2)
    r = gf_sftp_client_mkdir (x->sftp, w[1], &a, t, NULL);
  else if (strcmp (w[0], "rmdir") == 0 && n == 2)
    r = gf_sftp_client_rmdir (x->sftp, w[1], t, NULL);
  else if (strcmp (w[0], "rm") == 0 && n == 2)
    r = gf_sftp_client_remove (x->sftp, w[1], t, NULL);
  else if (strcmp (w[0], "mv") == 0 && n == 3)
    r = gf_sftp_client_rename (x->sftp, w[1], w[2], t, NULL);
  else if (strcmp (w[0], "ln") == 0 && n == 3)
    r = gf_sftp_client_symlink (x->sftp, w[2], w[1], t, NULL);
  else if (strcmp (w[0], "stat") == 0 && n == 2)
    r = gf_sftp_client_stat (x->sftp, w[1], t, NULL);
  else if (strcmp (w[0], "lstat") == 0 && n == 2)
    r = gf_sftp_client_lstat (x->sftp, w[1], t, NULL);
  else if (strcmp (w[0], "realpath") == 0 && n == 2)
    r = gf_sftp_client_realpath (x->sftp, w[1], t, NULL);
  else if (strcmp (w[0], "readlink") == 0 && n == 2)
    r = gf_sftp_client_readlink (x->sftp, w[1], t, NULL);
  else if (strcmp (w[0], "chmod") == 0 && n == 3)
    {
      a.flags = GF_FILEXFER_ATTR_PERMISSIONS;
      a.permissions = (uint32_t) strtoul (w[1], NULL, 8);
      r = gf_sftp_client_setstat (x->sftp, w[2], &a, t, NULL);
    }
  else
    {
      free (t);
      printf ("BAD COMMAND %s\n", w[0]);
      return 1;
    }
  x->argv_[0] = w[0];
  x->argv_[1] = w[1];
  x->argv_[2] = n > 2 ? w[2] : NULL;
  return r != GF_OK;
}

static int
sftp_ready (void *user)
{
  return next_command (user);
}

static int
sftp_response (void *user, const gf_sftp_response *rr)
{
  struct ctx *x = user;
  gf_sftp_response copy = *rr;
  struct tag *t = rr->tag;
  int kind = t->kind, put;
  uint64_t off = t->offset;
  uint32_t len = t->len;
  const char *cmd = x->argv_[0];

  free (t);
  put = strcmp (cmd, "put") == 0;
  switch (kind)
    {
    case T_OPEN:
      if (rr->type == GF_FXP_STATUS)
        return finish_command (x, cmd, rr->status);
      memcpy (x->handle, rr->handle.data, rr->handle.len);
      x->hlen = rr->handle.len;
      if (strcmp (cmd, "ls") == 0)
        return gf_sftp_client_readdir (x->sftp, x->handle, x->hlen,
                                       mktag (T_READDIR, 0, 0), NULL) != GF_OK;
      if (!put)
        {
          x->lfd = open (x->argv_[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
          if (x->lfd < 0)
            return 1;
        }
      return pump_xfer (x, put);
    case T_XFER:
      x->outstanding--;
      if (put)
        {
          if (rr->type == GF_FXP_STATUS && rr->status != GF_FX_OK)
            x->failed_cmd = (int) rr->status;
        }
      else if (rr->type == GF_FXP_DATA)
        {
          if (rr->data.len > 0
              && pwrite (x->lfd, rr->data.data, rr->data.len, (off_t) off)
                 != (ssize_t) rr->data.len)
            return 1;
          x->xtotal += rr->data.len;
          if (rr->data.len < len)
            x->eof = 1;		/* A short read: the end of the file.  */
        }
      else if (rr->status == GF_FX_EOF)
        x->eof = 1;
      else
        {
          x->failed_cmd = (int) rr->status;
          x->eof = 1;
        }
      if (x->failed_cmd)
        x->eof = 1;
      return pump_xfer (x, put);
    case T_CLOSE:
      return finish_command (x, cmd, x->failed_cmd ? (uint32_t) x->failed_cmd
                                                    : rr->status);
    case T_READDIR:
      if (rr->type == GF_FXP_STATUS)
        {
          x->closing = 1;
          return gf_sftp_client_close (x->sftp, x->handle, x->hlen,
                                       mktag (T_CLOSE, 0, 0), NULL) != GF_OK;
        }
      {
        gf_sftp_name nm;

        while (gf_sftp_response_next_name (&copy, &nm))
          printf ("LS %.*s %llu %o\n", (int) nm.filename.len,
                  (const char *) nm.filename.data,
                  (unsigned long long) nm.attrs.size,
                  (unsigned) nm.attrs.permissions & 07777);
      }
      return gf_sftp_client_readdir (x->sftp, x->handle, x->hlen,
                                     mktag (T_READDIR, 0, 0), NULL) != GF_OK;
    default:
      if (rr->type == GF_FXP_ATTRS)
        {
          printf ("STAT size=%llu perms=%o\n",
                  (unsigned long long) rr->attrs.size,
                  (unsigned) rr->attrs.permissions & 07777);
          return finish_command (x, cmd, 0);
        }
      if (rr->type == GF_FXP_NAME)
        {
          gf_sftp_name nm;

          if (gf_sftp_response_next_name (&copy, &nm))
            printf ("NAME %.*s\n", (int) nm.filename.len,
                    (const char *) nm.filename.data);
          return finish_command (x, cmd, 0);
        }
      return finish_command (x, cmd, rr->status);
    }
}

static void
sftp_disconnect (void *user, int status)
{
  (void) user;
  printf ("SFTP ENDED %d\n", status);
}

static void
sftp_setup (struct ctx *x)
{
  char *copy = strdup (x->sftp_script), *p = copy;

  while (p && *p && x->ncmds < 64)
    {
      char *semi = strchr (p, ';');

      if (semi)
        *semi = '\0';
      while (*p == ' ')
        p++;
      if (*p)
        x->cmds[x->ncmds++] = p;
      if (!semi)
        break;
      p = semi + 1;
    }
  x->lfd = -1;
}

static int
finished (void *user)
{
  struct ctx *x = user;

  if (x->no_auth)
    return x->service;
  if (x->auth_failed)
    return 1;
  if (x->sftp_script)
    {
      if (x->sftp_done && !x->chan_closed && x->opened)
        {
          x->opened = 0;
          gf_chans_close (x->chans, x->chan);
        }
      return x->chan_closed;
    }
  if (x->command)
    {
      /* sshd reports the exit status as soon as the command exits, while its
         output may still be waiting for our window: wait for it to close.  */
      return x->chan_closed;
    }
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
      else if (strcmp (argv[i], "--rekey-bytes") == 0 && i + 1 < argc)
        cfg.rekey_bytes = strtoull (argv[++i], NULL, 10);
      else if (strcmp (argv[i], "--exec") == 0 && i + 1 < argc)
        x.command = argv[++i];
      else if (strcmp (argv[i], "--sftp") == 0 && i + 1 < argc)
        x.sftp_script = argv[++i];
      else if (strcmp (argv[i], "--send") == 0 && i + 1 < argc)
        x.send_total = strtoull (argv[++i], NULL, 10);
      else if (strcmp (argv[i], "--check-pattern") == 0)
        x.check_pattern = 1;
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
  if (x.sftp_script)
    {
      gf_sftp_client_config sc;
      gf_sftp_client_events se;

      sftp_setup (&x);
      memset (&sc, 0, sizeof sc);
      memset (&se, 0, sizeof se);
      se.user = &x;
      se.write = sftp_write_cb;
      se.ready = sftp_ready;
      se.response = sftp_response;
      se.disconnect = sftp_disconnect;
      if (gf_sftp_client_new (&x.sftp, &sc, &se) != GF_OK)
        return 2;
    }
  if (x.command || x.sftp_script)
    {
      gf_chans_config cc;
      gf_chans_events ce;

      memset (&cc, 0, sizeof cc);
      memset (&ce, 0, sizeof ce);
      ce.user = &x;
      ce.send = chans_send;
      ce.disconnect = chans_disconnect;
      ce.open_confirmed = chan_confirmed;
      ce.open_failed = chan_failed;
      ce.request_reply = chan_reply;
      ce.writable = chan_writable;
      ce.data = chan_data;
      ce.extended_data = chan_ext;
      ce.eof = chan_eof;
      ce.request = chan_request;
      ce.closed = chan_closed;
      if (gf_chans_new (&x.chans, &cc, &ce) != GF_OK)
        return 2;
    }
  if (gf_conn_start (x.c, now_us ()) != GF_OK)
    return 2;
  r = drive (x.c, x.fd, finished, &x, 20000);
  if (!gf_conn_is_closed (x.c))
    gf_conn_disconnect (x.c, now_us (), GF_DISCONNECT_BY_APPLICATION, "done");
  if (x.command && !x.sftp_script)
    {
      if (x.outn < 200)
        {
          size_t k;

          x.out[x.outn] = '\0';
          for (k = 0; k < x.outn; k++)
            if (x.out[k] == '\n')
              x.out[k] = ' ';
          printf ("OUT %s\n", x.out);
        }
      printf ("RECEIVED %llu\nSTDERR %llu\nSENT %llu\nEXIT %u\n",
              (unsigned long long) x.received,
              (unsigned long long) x.stderr_bytes,
              (unsigned long long) x.sent, (unsigned) x.exit_status);
      if (x.bad_data)
        printf ("BAD DATA\n");
    }
  printf ("DONE %d authed=%d rekeyed=%d\n", r, x.authed, x.rekeyed);
  gf_sftp_client_free (x.sftp);
  gf_chans_free (x.chans);
  gf_auth_client_free (x.auth);
  gf_conn_free (x.c);
  gf_key_free (key);
  close (x.fd);
  if (x.no_auth)
    return x.service && r >= 0 ? 0 : 1;
  if (x.sftp_script)
    return x.sftp_done && x.chan_closed && r >= 0 ? 0 : 1;
  if (x.command)
    return x.chan_closed && x.exited && !x.bad_data && r >= 0 ? 0 : 1;
  return x.authed && r >= 0 && (!x.rekey || x.rekeyed) ? 0 : 1;
}
