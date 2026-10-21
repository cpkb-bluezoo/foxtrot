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
                         [--cert FILE] [--known-hosts FILE] [--host-name NAME]
                         [--sk-token FILE [--print-sk-pub]]

   Connects to 127.0.0.1:PORT, completes the transport handshake with the
   given algorithms (default: the policy's), asks the application to trust
   the host key (it does, unless --fingerprint says which one to expect, or
   --known-hosts names a known_hosts file, which must then say MATCH for the
   name given by --host-name, default 127.0.0.1, and the port, and limits the
   host key algorithms offered to what the file knows of that host),
   and requests the ssh-userauth service.  With --no-auth it stops there.
   Otherwise it authenticates as NAME (default "nobody") with the OpenSSH
   private key in FILE (with the certificate in the file given by --cert, if
   any), the password PW, a FIDO security key held by a token in software
   (--sk-token: FILE is an Ed25519 or P-256 OpenSSH private key that stands
   for the token's credential; the key offered is the security key
   "sk-ssh-ed25519@openssh.com" or "sk-ecdsa-sha2-nistp256@openssh.com" made
   from its public part, application "ssh:", with a key handle; the signature
   is made as a token and a FIDO library would give it, raw or DER, and
   packed by the library; --print-sk-pub prints the key as an
   authorized_keys line and exits), or by answering every
   keyboard-interactive prompt with ANSWER, as given; with --rekey it then
   forces a key exchange and waits for it; --rekey-bytes N makes the
   connection rekey by itself every N bytes.  With --exec it then runs
   COMMAND in a session channel, sends N bytes of the test pattern to its
   input (--send), checks that what it prints is the test pattern too
   (--check-pattern), and waits for the exit status and the end of the
   channel.  With --direct-streamlocal PATH it opens a direct-streamlocal
   channel to the Unix socket PATH on the server's side instead, sends a line
   and prints "STREAMLOCAL-ECHO line" for the answer; with
   --streamlocal-forward PATH it asks the server to listen on PATH, prints
   "STREAMLOCAL-FORWARD OK" or "REFUSED", echoes the first connection that
   comes ("FORWARDED-STREAMLOCAL PATH") and finishes when it closes.  With --sftp it runs the commands in an SFTP session instead:

     put LOCAL REMOTE      get REMOTE LOCAL      ls DIR
     mkdir DIR   rmdir DIR   rm FILE   mv OLD NEW   ln TARGET LINK
     stat PATH   lstat PATH   realpath PATH   readlink PATH   chmod OCTAL PATH

   and the OpenSSH extensions:

     prename OLD NEW   hardlink OLD NEW   lsetstat OCTAL PATH   statvfs PATH
     limits   expand PATH   fsync FILE   copydata SRC DST   idnames UID GID
     has NAME

   (each prints "RESULT command 253" if the server did not advertise it, and
   "STATVFS ...", "LIMITS ...", "IDNAMES user group", "HAS name 0|1").

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

#include <foxtrot/session.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>
#include <foxtrot/knownhosts.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

struct ctx
{
  int fd;
  gf_session *s;
  gf_chans *chans;
  const char *expect_fp, *kbd_answer, *command;
  gf_knownhosts *kh;
  const gf_key *token;		/* --sk-token: the credential's private key.  */
  uint32_t token_counter;
  const char *host_name;	/* The name looked up in it.  */
  unsigned port;
  int rekey, no_auth, check_pattern;
  int established, service, authed, auth_failed, rekeyed, banners;
  uint64_t send_total, sent, received, stderr_bytes;
  uint32_t chan;
  int opened, exited, chan_closed, bad_data, eof_sent;
  uint32_t exit_status;
  char out[256];
  size_t outn;
  /* Unix socket forwarding: --direct-streamlocal opens a channel to a socket
     on the server's side and checks it is echoed; --streamlocal-forward asks
     the server to listen on one, and echoes the first connection.  */
  const char *dsl_path, *fsl_path;
  int fsl_refused;
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
  uint8_t handle2[GF_SFTP_MAX_HANDLE];
  size_t hlen2;
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
  if (gf_key_is_certificate (key))
    {
      gf_cert_info ci;

      gf_key_certificate_info (key, &ci);
      printf ("HOSTCERT serial=%llu id=%.*s\n", (unsigned long long) ci.serial,
              (int) ci.key_id.len, (const char *) ci.key_id.data);
    }
  if (x->kh != NULL)
    {
      static const char *const names[] = { "UNKNOWN", "MATCH", "CHANGED", "REVOKED" };
      time_t now = time (NULL);
      enum gf_hostcheck r = gf_knownhosts_check (x->kh,
                                                 x->host_name ? x->host_name : "127.0.0.1",
                                                 x->port, key,
                                                 now < 0 ? 0 : (uint64_t) now);

      printf ("HOSTCHECK %s\n", names[r]);
      if (r != GF_HOST_MATCH)
        return 1;
    }
  else if (gf_key_is_certificate (key))
    {
      /* A certificate is trusted only because of a CA in a known_hosts file.  */
      printf ("HOSTCHECK UNTRUSTED\n");
      return 1;
    }
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
  x->service = 1;		/* --no-auth stops here.  */
  return 0;
}

static int
on_rekeyed (void *user, const gf_conn_info *info)
{
  struct ctx *x = user;

  printf ("REKEYED %s\n", gf_kex_name (info->kex));
  x->rekeyed++;
  return 0;
}

static void
on_closed (void *user, int error, uint32_t reason, gf_slice text)
{
  (void) user;
  printf ("CLOSED %d %u %.*s\n", error, (unsigned) reason, (int) text.len,
          text.data ? (const char *) text.data : "");
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
  return gf_session_auth_kbdint_respond (x->s, n, answers) != GF_OK;
}

static int
auth_ok (void *user, gf_slice none)
{
  struct ctx *x = user;

  (void) none;
  printf ("AUTH OK\n");
  x->authed = 1;
  if (x->rekey)
    return gf_conn_rekey (gf_session_conn (x->s), now_us ()) != GF_OK;
  if (x->dsl_path)
    return gf_chans_open_direct_streamlocal (x->chans, &x->chan, x->dsl_path,
                                             0, 0) != GF_OK;
  if (x->fsl_path)
    return gf_chans_request_streamlocal_forward (x->chans, x->fsl_path) != GF_OK;
  if (x->command || x->sftp_script)
    return gf_chans_open_session (x->chans, &x->chan, 0, 0) != GF_OK;
  return 0;
}

/* A FIDO token in software.  It is given what a FIDO library is: the
   application and key handle of the key (checked to be the ones this token
   has), and the challenge, SHA256(data), and answers with what the
   authenticator signed: SHA256(application) || flags || counter ||
   challenge, with the flags and counter in the answer too.  Ed25519 comes
   as 64 raw bytes and ECDSA as DER.  */
static int
sk_sign (void *user, const gf_key *key, enum gf_sigalg alg, gf_slice data)
{
  struct ctx *x = user;
  uint8_t buf[69], sig[GF_SIG_MAX], raw[80], out[GF_SIG_MAX];
  uint8_t flags = GF_SK_USER_PRESENT;
  const uint8_t *app, *h;
  size_t al, hl, sl, rl, n;
  gf_reader r, rr;
  gf_slice name, body, ri, si;
  int ed = gf_key_type (x->token) == GF_KEY_ED25519;
  uint32_t counter = ++x->token_counter;

  app = gf_key_application (key, &al);
  h = gf_key_sk_handle (key, &hl);
  if (app == NULL || h == NULL || hl == 0)
    return gf_session_auth_sign_fail (x->s) != GF_OK;
  if (gf_hash_compute (GF_HASH_SHA256, app, al, buf, 32) != GF_OK)
    return 1;
  buf[32] = flags;
  buf[33] = (uint8_t) (counter >> 24);
  buf[34] = (uint8_t) (counter >> 16);
  buf[35] = (uint8_t) (counter >> 8);
  buf[36] = (uint8_t) counter;
  if (gf_hash_compute (GF_HASH_SHA256, data.data, data.len, buf + 37, 32) != GF_OK
      || gf_key_sign (x->token, ed ? GF_SIG_ED25519 : GF_SIG_ECDSA_NISTP256, buf,
                      sizeof buf, sig, sizeof sig, &sl) != GF_OK)
    return 1;
  gf_reader_init (&r, sig, sl);
  if (gf_rd_string (&r, &name) != GF_OK || gf_rd_string (&r, &body) != GF_OK)
    return 1;
  if (ed)
    {
      memcpy (raw, body.data, body.len);
      rl = body.len;
    }
  else
    {
      /* The mpints of the SSH form are the contents of DER integers.  */
      gf_reader_init (&rr, body.data, body.len);
      if (gf_rd_string (&rr, &ri) != GF_OK || gf_rd_string (&rr, &si) != GF_OK
          || ri.len > 33 || si.len > 33)
        return 1;
      raw[0] = 0x30;
      raw[1] = (uint8_t) (4 + ri.len + si.len);
      raw[2] = 0x02;
      raw[3] = (uint8_t) ri.len;
      memcpy (raw + 4, ri.data, ri.len);
      raw[4 + ri.len] = 0x02;
      raw[5 + ri.len] = (uint8_t) si.len;
      memcpy (raw + 6 + ri.len, si.data, si.len);
      rl = 6 + ri.len + si.len;
    }
  if (gf_sk_signature_pack (key, alg, raw, rl, flags, counter, out, sizeof out,
                            &n) != GF_OK)
    return 1;
  return gf_session_auth_sign_respond (x->s, out, n) != GF_OK;
}

static int
auth_failed (void *user)
{
  printf ("AUTH FAILED\n");
  ((struct ctx *) user)->auth_failed = 1;
  return 0;
}

static int sftp_ready (void *user);
static int sftp_response (void *user, const gf_sftp_response *rr);
static void sftp_disconnect (void *user, int status);
static void sftp_setup (struct ctx *x);

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
  if (x->dsl_path)
    {
      static const uint8_t ping[] = "streamlocal ping\n";

      return gf_chans_send_data (x->chans, x->chan, ping, sizeof ping - 1) < 0;
    }
  if (x->sftp_script)
    return gf_chans_request_subsystem (x->chans, x->chan, "sftp", 1) != GF_OK;
  return gf_chans_request_exec (x->chans, x->chan, x->command, 1) != GF_OK;
}

static int
chan_failed (void *user, uint32_t id, uint32_t reason, gf_slice text)
{
  (void) id;
  ((struct ctx *) user)->fsl_refused = 1;	/* Nothing more will happen.  */
  printf ("OPEN FAILED %u %.*s\n", (unsigned) reason, (int) text.len,
          (const char *) text.data);
  return 0;
}

static int
chan_open (void *user, const gf_chan_open *o)
{
  struct ctx *x = user;

  if (x->fsl_path && o->type == GF_CHAN_FORWARDED_STREAMLOCAL)
    {
      printf ("FORWARDED-STREAMLOCAL %.*s\n", (int) o->path.len,
              (const char *) o->path.data);
      return gf_session_channel_accept (x->s, o->id, 0, 0) != GF_OK;
    }
  return gf_session_channel_reject (x->s, o->id,
                                    GF_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                    "not expected") != GF_OK;
}

static int
global_reply (void *user, int ok, uint32_t port)
{
  struct ctx *x = user;

  (void) port;
  printf ("STREAMLOCAL-FORWARD %s\n", ok ? "OK" : "REFUSED");
  fflush (stdout);
  if (!ok)
    x->fsl_refused = 1;
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
    {
      gf_sftp_client_config sc;
      gf_sftp_client_events se;

      sftp_setup (x);
      memset (&sc, 0, sizeof sc);
      memset (&se, 0, sizeof se);
      se.user = x;
      se.ready = sftp_ready;
      se.response = sftp_response;
      se.disconnect = sftp_disconnect;
      return gf_session_sftp_client (x->s, x->chan, &sc, &se, &x->sftp)
        != GF_OK;
    }
  return push (x);
}

static int
chan_writable (void *user, uint32_t id)
{
  struct ctx *x = user;

  (void) id;
  return push (x);
}

static int
chan_data (void *user, uint32_t id, const uint8_t *d, size_t n)
{
  struct ctx *x = user;
  size_t i;

  if (x->fsl_path)
    {
      /* A connection to the socket the server listens on: echo it.  */
      if (gf_chans_send_data (x->chans, id, d, n) < 0)
        return 1;
      return gf_chans_consumed (x->chans, id, n) != GF_OK;
    }
  if (x->dsl_path)
    {
      for (i = 0; i < n && x->outn < sizeof x->out - 1; i++)
        x->out[x->outn++] = (char) d[i];
      x->out[x->outn] = '\0';
      if (gf_chans_consumed (x->chans, id, n) != GF_OK)
        return 1;
      if (strchr (x->out, '\n') != NULL)
        {
          printf ("STREAMLOCAL-ECHO %s", x->out);
          return gf_chans_close (x->chans, id) != GF_OK;
        }
      return 0;
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
  x->sftp = NULL;		/* The session freed it.  */
  return 0;
}


/* ---- SFTP ---- */

enum { T_OPEN = 1, T_CLOSE, T_XFER, T_READDIR, T_PLAIN, T_OPEN2, T_COPY,
       T_CLOSE2, T_FSYNC };

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
  else if (strcmp (w[0], "prename") == 0 && n == 3)
    r = gf_sftp_client_posix_rename (x->sftp, w[1], w[2], t, NULL);
  else if (strcmp (w[0], "hardlink") == 0 && n == 3)
    r = gf_sftp_client_hardlink (x->sftp, w[1], w[2], t, NULL);
  else if (strcmp (w[0], "lsetstat") == 0 && n == 3)
    {
      a.flags = GF_FILEXFER_ATTR_PERMISSIONS;
      a.permissions = (uint32_t) strtoul (w[1], NULL, 8);
      r = gf_sftp_client_lsetstat (x->sftp, w[2], &a, t, NULL);
    }
  else if (strcmp (w[0], "statvfs") == 0 && n == 2)
    r = gf_sftp_client_statvfs (x->sftp, w[1], t, NULL);
  else if (strcmp (w[0], "limits") == 0 && n == 1)
    r = gf_sftp_client_limits (x->sftp, t, NULL);
  else if (strcmp (w[0], "expand") == 0 && n == 2)
    r = gf_sftp_client_expand_path (x->sftp, w[1], t, NULL);
  else if (strcmp (w[0], "idnames") == 0 && n == 3)
    {
      uint32_t uid = (uint32_t) strtoul (w[1], NULL, 10);
      uint32_t gid = (uint32_t) strtoul (w[2], NULL, 10);

      r = gf_sftp_client_users_groups_by_id (x->sftp, &uid, 1, &gid, 1, t, NULL);
    }
  else if (strcmp (w[0], "has") == 0 && n == 2)
    {
      free (t);
      printf ("HAS %s %d\n", w[1], gf_sftp_client_extension (x->sftp, w[1], NULL));
      return finish_command (x, "has", 0);
    }
  else if ((strcmp (w[0], "fsync") == 0 && n == 2)
           || (strcmp (w[0], "copydata") == 0 && n == 3))
    {
      /* Several requests: the file is opened first.  */
      free (t);
      x->failed_cmd = 0;
      if (!gf_sftp_client_extension (x->sftp, w[0][0] == 'f'
                                     ? GF_SFTP_EXT_FSYNC : GF_SFTP_EXT_COPY_DATA,
                                     NULL))
        return finish_command (x, w[0], 253);
      a.flags = GF_FILEXFER_ATTR_PERMISSIONS;
      a.permissions = 0644;
      r = gf_sftp_client_open (x->sftp, w[1], w[0][0] == 'f'
                               ? GF_FXF_READ | GF_FXF_WRITE : GF_FXF_READ,
                               &a, mktag (T_OPEN, 0, 0), NULL);
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
  if (r == GF_ERR_UNSUPPORTED)
    return finish_command (x, w[0], 253);
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
      if (strcmp (cmd, "fsync") == 0)
        return gf_sftp_client_fsync (x->sftp, x->handle, x->hlen,
                                     mktag (T_FSYNC, 0, 0), NULL) != GF_OK;
      if (strcmp (cmd, "copydata") == 0)
        {
          gf_sftp_attrs a2;

          memset (&a2, 0, sizeof a2);
          a2.flags = GF_FILEXFER_ATTR_PERMISSIONS;
          a2.permissions = 0644;
          return gf_sftp_client_open (x->sftp, x->argv_[2], GF_FXF_WRITE
                                      | GF_FXF_CREAT | GF_FXF_TRUNC, &a2,
                                      mktag (T_OPEN2, 0, 0), NULL) != GF_OK;
        }
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
    case T_FSYNC:
      x->failed_cmd = (int) rr->status;
      x->closing = 1;
      return gf_sftp_client_close (x->sftp, x->handle, x->hlen,
                                   mktag (T_CLOSE, 0, 0), NULL) != GF_OK;
    case T_OPEN2:
      if (rr->type == GF_FXP_STATUS)
        {
          x->failed_cmd = (int) rr->status;
          return gf_sftp_client_close (x->sftp, x->handle, x->hlen,
                                       mktag (T_CLOSE, 0, 0), NULL) != GF_OK;
        }
      memcpy (x->handle2, rr->handle.data, rr->handle.len);
      x->hlen2 = rr->handle.len;
      return gf_sftp_client_copy_data (x->sftp, x->handle, x->hlen, 0, 0,
                                       x->handle2, x->hlen2, 0,
                                       mktag (T_COPY, 0, 0), NULL) != GF_OK;
    case T_COPY:
      x->failed_cmd = (int) rr->status;
      return gf_sftp_client_close (x->sftp, x->handle2, x->hlen2,
                                   mktag (T_CLOSE2, 0, 0), NULL) != GF_OK;
    case T_CLOSE2:
      return gf_sftp_client_close (x->sftp, x->handle, x->hlen,
                                   mktag (T_CLOSE, 0, 0), NULL) != GF_OK;
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
      if (rr->type == GF_FXP_EXTENDED_REPLY)
        {
          gf_sftp_statvfs sv;
          gf_sftp_limits lm;
          gf_slice us, gs, un, gn;

          if (strcmp (cmd, "statvfs") == 0 && gf_sftp_response_statvfs (rr, &sv))
            printf ("STATVFS bsize=%llu frsize=%llu blocks=%llu bfree=%llu "
                    "namemax=%llu\n", (unsigned long long) sv.bsize,
                    (unsigned long long) sv.frsize,
                    (unsigned long long) sv.blocks,
                    (unsigned long long) sv.bfree,
                    (unsigned long long) sv.namemax);
          else if (strcmp (cmd, "limits") == 0
                   && gf_sftp_response_limits (rr, &lm))
            printf ("LIMITS packet=%llu read=%llu write=%llu handles=%llu\n",
                    (unsigned long long) lm.max_packet,
                    (unsigned long long) lm.max_read,
                    (unsigned long long) lm.max_write,
                    (unsigned long long) lm.max_open_handles);
          else if (strcmp (cmd, "idnames") == 0
                   && gf_sftp_response_users_groups (rr, &us, &gs)
                   && gf_sftp_string_next (&us, &un)
                   && gf_sftp_string_next (&gs, &gn))
            printf ("IDNAMES %.*s %.*s\n", (int) un.len, (const char *) un.data,
                    (int) gn.len, (const char *) gn.data);
          return finish_command (x, cmd, 0);
        }
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
  if (x->dsl_path || x->fsl_path)
    return x->chan_closed || x->fsl_refused;
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
  gf_session_config cfg;
  gf_session_events ev;
  enum gf_kex kex = 0;
  enum gf_cipher cipher = 0;
  enum gf_sigalg alg = 0;
  const char *user = "nobody", *keyfile = NULL, *certfile = NULL, *password = NULL;
  const char *tokenfile = NULL;
  int print_sk_pub = 0;
  gf_key *key = NULL, *token = NULL;
  const gf_key *keys[1];
  enum gf_sigalg known_algs[16];
  gf_key *ckey = NULL;		/* The key with its certificate.  */
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
      else if (strcmp (argv[i], "--sk-token") == 0 && i + 1 < argc)
        tokenfile = argv[++i];
      else if (strcmp (argv[i], "--print-sk-pub") == 0)
        print_sk_pub = 1;
      else if (strcmp (argv[i], "--password") == 0 && i + 1 < argc)
        password = argv[++i];
      else if (strcmp (argv[i], "--kbd") == 0 && i + 1 < argc)
        x.kbd_answer = argv[++i];
      else if (strcmp (argv[i], "--rekey") == 0)
        x.rekey = 1;
      else if (strcmp (argv[i], "--rekey-bytes") == 0 && i + 1 < argc)
        cfg.conn.rekey_bytes = strtoull (argv[++i], NULL, 10);
      else if (strcmp (argv[i], "--exec") == 0 && i + 1 < argc)
        x.command = argv[++i];
      else if (strcmp (argv[i], "--sftp") == 0 && i + 1 < argc)
        x.sftp_script = argv[++i];
      else if (strcmp (argv[i], "--direct-streamlocal") == 0 && i + 1 < argc)
        x.dsl_path = argv[++i];
      else if (strcmp (argv[i], "--streamlocal-forward") == 0 && i + 1 < argc)
        x.fsl_path = argv[++i];
      else if (strcmp (argv[i], "--send") == 0 && i + 1 < argc)
        x.send_total = strtoull (argv[++i], NULL, 10);
      else if (strcmp (argv[i], "--check-pattern") == 0)
        x.check_pattern = 1;
      else if (strcmp (argv[i], "--cert") == 0 && i + 1 < argc)
        certfile = argv[++i];
      else if (strcmp (argv[i], "--known-hosts") == 0 && i + 1 < argc)
        {
          char text[65536];
          FILE *f = fopen (argv[++i], "r");
          size_t n;

          if (f == NULL)
            {
              perror (argv[i]);
              return 2;
            }
          n = fread (text, 1, sizeof text, f);
          fclose (f);
          if (gf_knownhosts_new (&x.kh) != GF_OK
              || gf_knownhosts_load (x.kh, text, n, NULL) != GF_OK)
            return 2;
        }
      else if (strcmp (argv[i], "--host-name") == 0 && i + 1 < argc)
        x.host_name = argv[++i];
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
      cfg.conn.prefs.kex = &kex;
      cfg.conn.prefs.nkex = 1;
    }
  if (cipher)
    {
      cfg.conn.prefs.ciphers = &cipher;
      cfg.conn.prefs.nciphers = 1;
    }
  x.port = (unsigned) atoi (argv[1]);
  if (alg)
    {
      cfg.conn.prefs.sigalgs = &alg;
      cfg.conn.prefs.nsigalgs = 1;
    }
  else if (x.kh != NULL)
    {
      /* Ask only for what the file knows of the host.  */
      cfg.conn.prefs.nsigalgs = gf_knownhosts_sigalgs (x.kh,
        x.host_name ? x.host_name : "127.0.0.1", x.port, known_algs, 16);
      cfg.conn.prefs.sigalgs = known_algs;
    }
  if (tokenfile)
    {
      /* The security key of a token in software: its public part is the
         credential's, with the application and a key handle.  */
      static const uint8_t handle[] = "foxtrot interop credential id 0123456789abcdef";
      char text[8192], line[1024];
      uint8_t b[512];
      FILE *f = fopen (tokenfile, "r");
      size_t n, kl;
      const uint8_t *kb;
      gf_reader rd;
      gf_slice s, point, curve = { NULL, 0 };
      gf_writer w;

      if (f == NULL)
        {
          perror (tokenfile);
          return 2;
        }
      n = fread (text, 1, sizeof text, f);
      fclose (f);
      if (gf_key_from_openssh_private (&token, text, n) != GF_OK
          || (gf_key_type (token) != GF_KEY_ED25519
              && gf_key_type (token) != GF_KEY_ECDSA_P256))
        {
          fprintf (stderr, "cannot use %s as a token\n", tokenfile);
          return 2;
        }
      kb = gf_key_blob (token, &kl);
      gf_reader_init (&rd, kb, kl);
      if (gf_rd_string (&rd, &s) != GF_OK
          || (gf_key_type (token) == GF_KEY_ECDSA_P256
              && gf_rd_string (&rd, &curve) != GF_OK)
          || gf_rd_string (&rd, &point) != GF_OK)
        return 2;
      gf_writer_init (&w, b, sizeof b);
      if (gf_key_type (token) == GF_KEY_ED25519)
        gf_wr_cstring (&w, "sk-ssh-ed25519@openssh.com");
      else
        {
          gf_wr_cstring (&w, "sk-ecdsa-sha2-nistp256@openssh.com");
          gf_wr_string (&w, curve.data, curve.len);
        }
      gf_wr_string (&w, point.data, point.len);
      gf_wr_string (&w, "ssh:", 4);
      if (gf_wr_status (&w) != GF_OK || gf_key_from_blob (&key, b, w.len) != GF_OK
          || gf_key_sk_attach_handle (key, GF_SK_USER_PRESENT, handle,
                                      sizeof handle - 1) != GF_OK)
        {
          fprintf (stderr, "cannot make a security key from %s\n", tokenfile);
          return 2;
        }
      if (print_sk_pub)
        {
          if (gf_key_to_text (key, line, sizeof line, NULL) != GF_OK)
            return 2;
          printf ("%s\n", line);
          return 0;
        }
      x.token = token;
      keys[0] = key;
      keyfile = tokenfile;		/* There is a key to offer.  */
    }
  else
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
      if (certfile != NULL)
        {
          gf_key *cert = read_pub (certfile);

          if (cert == NULL || gf_key_with_certificate (key, cert, &ckey) != GF_OK)
            {
              fprintf (stderr, "cannot use certificate %s\n", certfile);
              return 2;
            }
          gf_key_free (cert);
          keys[0] = ckey;
        }
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
  cfg.client_auth.user = user;
  cfg.client_auth.keys = keyfile ? keys : NULL;
  cfg.client_auth.nkeys = keyfile ? 1 : 0;
  cfg.client_auth.password = password;
  memset (&ev, 0, sizeof ev);
  ev.user = &x;
  ev.write = on_write;
  ev.host_key = on_host_key;
  ev.established = on_established;
  ev.rekeyed = on_rekeyed;
  ev.auth_banner = auth_banner;
  ev.auth_kbdint = x.kbd_answer ? auth_kbdint : NULL;
  ev.auth_sign = x.token ? sk_sign : NULL;
  ev.authenticated = auth_ok;
  ev.auth_failed = auth_failed;
  ev.channel_open = chan_open;
  ev.global_reply = global_reply;
  ev.channel_confirmed = chan_confirmed;
  ev.channel_failed = chan_failed;
  ev.channel_request_reply = chan_reply;
  ev.channel_writable = chan_writable;
  ev.channel_data = chan_data;
  ev.channel_extended_data = chan_ext;
  ev.channel_eof = chan_eof;
  ev.channel_request = chan_request;
  ev.channel_closed = chan_closed;
  ev.closed = on_closed;
  if (gf_session_client_new (&x.s, &cfg, &ev) != GF_OK
      || gf_session_start (x.s, now_us ()) != GF_OK)
    {
      fprintf (stderr, "cannot start\n");
      return 2;
    }
  x.chans = gf_session_channels (x.s);
  r = drive (x.s, x.fd, finished, &x, 20000);
  if (gf_session_phase (x.s) != GF_PHASE_CLOSED)
    gf_session_disconnect (x.s, now_us (), GF_DISCONNECT_BY_APPLICATION, "done");
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
  gf_session_free (x.s);
  gf_key_free (ckey);
  gf_key_free (key);
  gf_knownhosts_free (x.kh);
  close (x.fd);
  if (x.no_auth)
    return x.service && r >= 0 ? 0 : 1;
  if (x.sftp_script)
    return x.sftp_done && x.chan_closed && r >= 0 ? 0 : 1;
  if (x.command)
    return x.chan_closed && x.exited && !x.bad_data && r >= 0 ? 0 : 1;
  return x.authed && r >= 0 && (!x.rekey || x.rekeyed) ? 0 : 1;
}
