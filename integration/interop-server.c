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
                                 [--rekey-bytes N] [--sftp-root DIR]

   HOSTKEY is an unencrypted OpenSSH private key file.  The server accepts
   one connection on 127.0.0.1:PORT, completes the transport handshake and
   accepts the ssh-userauth service.  Users authenticate with the public key
   of the private key file given by --auth-key, with the password PW, or by
   answering a keyboard-interactive question with CODE, as given.  Once
   authentication succeeds it says so and serves session channels with a
   few commands of its own:

     true, exit N       exit with status 0 or N
     echo TEXT          print TEXT
     stderr TEXT        print TEXT on standard error
     cat                send back what it is sent, until EOF
     bytes N            send N bytes of the test pattern

   the "sftp" subsystem, serving the directory given with --sftp-root
   (paths are confined to it lexically; this is a test program, not a model
   of a file server), and direct-tcpip channels, which it simply echoes (so that ssh -L can be
   tried without a network); tcpip-forward requests are granted.  On
   standard output, "HOSTKEY SHA256:..." is the fingerprint to expect, "READY" says
   the port is listening, "KEX ..." and "CLIENT ..." say what was
   negotiated and who the peer is, and "AUTH OK user method" or "AUTH
   FAILED" how it ended.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "interop-util.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

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
  gf_auth_server *auth;
  gf_chans *chans;
  gf_key *authorized;
  const char *password, *code;
  int established, authed, hostbound_used;
  const char *method;
  /* The one channel being served.  */
  uint32_t chan;
  int active, tcpip;
  enum { M_NONE, M_TRUE, M_CAT, M_BYTES, M_ECHO, M_SFTP } mode;
  uint32_t exit_status;
  uint64_t bytes_left, produced;
  uint8_t *out;			/* Data not yet accepted by the peer.  */
  size_t outn, outcap;
  int finishing;
  const char *sftp_root;
  gf_sftp_server *sftp;
  struct sftp_handle { int used, is_dir; int fd; DIR *dir; } handles[64];
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
on_rekeyed (void *user, const gf_conn_info *info)
{
  struct ctx *x = user;

  (void) info;
  return x->authed && gf_chans_resume (x->chans) != GF_OK;
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
  if (p[0] >= 80 && p[0] <= 100 && x->authed)
    return gf_chans_input (x->chans, p, n) != GF_OK;
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
  return 0;
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


/* ---- channels ---- */

static int
chans_send (void *user, const uint8_t *p, size_t n)
{
  return gf_conn_send (((struct ctx *) user)->c, now_us (), p, n);
}

static int
chans_disconnect (void *user, uint32_t reason)
{
  struct ctx *x = user;

  gf_conn_disconnect (x->c, now_us (), reason, NULL);
  return 0;
}

/* Queue data for the peer and send what the window takes.  */
static int
out_flush (struct ctx *x)
{
  size_t done = 0;

  while (done < x->outn)
    {
      long r = gf_chans_send_data (x->chans, x->chan, x->out + done,
                                   x->outn - done);

      if (r == GF_ERR_AGAIN || r == 0)
        break;
      if (r < 0)
        return 1;
      done += (size_t) r;
    }
  memmove (x->out, x->out + done, x->outn - done);
  x->outn -= done;
  return 0;
}

static int
out_add (struct ctx *x, const uint8_t *d, size_t n)
{
  if (x->outn + n > x->outcap)
    {
      x->outcap = (x->outn + n) * 2;
      x->out = realloc (x->out, x->outcap);
      if (x->out == NULL)
        return 1;
    }
  memcpy (x->out + x->outn, d, n);
  x->outn += n;
  return out_flush (x);
}

/* Produce more of "bytes N" while the window allows.  */
static int
produce (struct ctx *x)
{
  while (x->mode == M_BYTES && x->bytes_left > 0 && x->outn < 65536)
    {
      uint8_t buf[8192];
      size_t n = sizeof buf, i;

      if (n > x->bytes_left)
        n = (size_t) x->bytes_left;
      for (i = 0; i < n; i++)
        buf[i] = pattern_at (x->produced + i);
      x->produced += n;
      x->bytes_left -= n;
      if (out_add (x, buf, n))
        return 1;
    }
  return 0;
}

/* The command is done once its output has gone: exit status, EOF, close.  */
static int
maybe_finish (struct ctx *x)
{
  if (!x->active || x->tcpip || x->finishing)
    return 0;
  if (x->mode == M_BYTES && x->bytes_left > 0)
    return 0;
  if (x->outn > 0)
    return 0;
  if (x->mode == M_CAT && !x->finishing && x->mode != M_NONE)
    {
      /* cat ends with the peer's EOF; see chan_eof.  */
      return 0;
    }
  x->finishing = 1;
  if (gf_chans_request_exit_status (x->chans, x->chan, x->exit_status))
    return 1;
  if (gf_chans_send_eof (x->chans, x->chan))
    return 1;
  return gf_chans_close (x->chans, x->chan) != GF_OK;
}


/* ---- SFTP over a directory ---- */

/* Map an SFTP path to a path under the root: absolute or relative to the
   root, "." and ".." resolved lexically without going above it.  */
static int
map_path (struct ctx *x, gf_slice p, char *out, size_t cap)
{
  char norm[PATH_MAX];
  size_t n = 0, i = 0;

  /* Resolve into a stack of components in NORM, "/"-separated.  */
  norm[0] = '\0';
  while (i < p.len)
    {
      size_t j = i;
      size_t clen;

      while (j < p.len && p.data[j] != '/')
        j++;
      clen = j - i;
      if (clen == 0 || (clen == 1 && p.data[i] == '.'))
        ;
      else if (clen == 2 && p.data[i] == '.' && p.data[i + 1] == '.')
        {
          while (n > 0 && norm[n - 1] != '/')
            n--;
          if (n > 0)
            n--;
          norm[n] = '\0';
        }
      else
        {
          if (n + clen + 2 >= sizeof norm)
            return -1;
          norm[n++] = '/';
          memcpy (norm + n, p.data + i, clen);
          n += clen;
          norm[n] = '\0';
        }
      i = j + 1;
    }
  if (snprintf (out, cap, "%s%s", x->sftp_root, norm) >= (int) cap)
    return -1;
  return 0;
}

static uint32_t
errno_status (int e)
{
  switch (e)
    {
    case 0:		return GF_FX_OK;
    case ENOENT:
    case ENOTDIR:	return GF_FX_NO_SUCH_FILE;
    case EACCES:
    case EPERM:
    case EROFS:		return GF_FX_PERMISSION_DENIED;
    default:		return GF_FX_FAILURE;
    }
}

static int
sftp_status (struct ctx *x, uint32_t id, int e)
{
  return gf_sftp_server_status (x->sftp, id, errno_status (e),
                                e ? strerror (e) : "ok") != GF_OK;
}

static void
stat_to_attrs (const struct stat *st, gf_sftp_attrs *a)
{
  memset (a, 0, sizeof *a);
  a->flags = GF_FILEXFER_ATTR_SIZE | GF_FILEXFER_ATTR_UIDGID
    | GF_FILEXFER_ATTR_PERMISSIONS | GF_FILEXFER_ATTR_ACMODTIME;
  a->size = (uint64_t) st->st_size;
  a->uid = st->st_uid;
  a->gid = st->st_gid;
  a->permissions = st->st_mode;
  a->atime = (uint32_t) st->st_atime;
  a->mtime = (uint32_t) st->st_mtime;
}

static int
new_handle (struct ctx *x, int is_dir, int fd, DIR *dir, uint8_t out[2])
{
  int i;

  for (i = 0; i < 64; i++)
    if (!x->handles[i].used)
      {
        x->handles[i].used = 1;
        x->handles[i].is_dir = is_dir;
        x->handles[i].fd = fd;
        x->handles[i].dir = dir;
        out[0] = 'h';
        out[1] = (uint8_t) i;
        return 0;
      }
  return -1;
}

static struct sftp_handle *
get_handle (struct ctx *x, gf_slice h)
{
  if (h.len != 2 || h.data[0] != 'h' || h.data[1] >= 64
      || !x->handles[h.data[1]].used)
    return NULL;
  return &x->handles[h.data[1]];
}

static int
sftp_request (void *user, const gf_sftp_request *q)
{
  struct ctx *x = user;
  char path[PATH_MAX], path2[PATH_MAX];
  struct stat st;
  gf_sftp_attrs a;
  struct sftp_handle *h;
  uint8_t hb[2];
  int fd, flags;

  if ((q->path.len || q->type == GF_FXP_REALPATH)
      && map_path (x, q->path, path, sizeof path))
    return sftp_status (x, q->id, ENAMETOOLONG);
  if (q->path2.len && map_path (x, q->path2, path2, sizeof path2))
    return sftp_status (x, q->id, ENAMETOOLONG);

  switch (q->type)
    {
    case GF_FXP_OPEN:
      flags = 0;
      if ((q->pflags & GF_FXF_READ) && (q->pflags & GF_FXF_WRITE))
        flags = O_RDWR;
      else if (q->pflags & GF_FXF_WRITE)
        flags = O_WRONLY;
      if (q->pflags & GF_FXF_APPEND)
        flags |= O_APPEND;
      if (q->pflags & GF_FXF_CREAT)
        flags |= O_CREAT;
      if (q->pflags & GF_FXF_TRUNC)
        flags |= O_TRUNC;
      if (q->pflags & GF_FXF_EXCL)
        flags |= O_EXCL;
      fd = open (path, flags, (q->attrs.flags & GF_FILEXFER_ATTR_PERMISSIONS)
                 ? q->attrs.permissions & 0777 : 0644);
      if (fd < 0 || new_handle (x, 0, fd, NULL, hb) < 0)
        return sftp_status (x, q->id, fd < 0 ? errno : EMFILE);
      return gf_sftp_server_handle (x->sftp, q->id, hb, 2) != GF_OK;
    case GF_FXP_CLOSE:
      h = get_handle (x, q->handle);
      if (h == NULL)
        return sftp_status (x, q->id, EBADF);
      if (h->is_dir)
        closedir (h->dir);
      else
        close (h->fd);
      h->used = 0;
      return sftp_status (x, q->id, 0);
    case GF_FXP_READ:
      {
        static uint8_t buf[GF_SFTP_DEFAULT_MAX_PACKET];
        ssize_t n;
        size_t want = q->length;

        h = get_handle (x, q->handle);
        if (h == NULL || h->is_dir)
          return sftp_status (x, q->id, EBADF);
        if (want > 65536)
          want = 65536;
        n = pread (h->fd, buf, want, (off_t) q->offset);
        if (n < 0)
          return sftp_status (x, q->id, errno);
        if (n == 0)
          return gf_sftp_server_status (x->sftp, q->id, GF_FX_EOF, "eof") != GF_OK;
        return gf_sftp_server_data (x->sftp, q->id, buf, (size_t) n) != GF_OK;
      }
    case GF_FXP_WRITE:
      h = get_handle (x, q->handle);
      if (h == NULL || h->is_dir)
        return sftp_status (x, q->id, EBADF);
      if (pwrite (h->fd, q->data.data, q->data.len, (off_t) q->offset)
          != (ssize_t) q->data.len)
        return sftp_status (x, q->id, errno ? errno : EIO);
      return sftp_status (x, q->id, 0);
    case GF_FXP_STAT:
    case GF_FXP_LSTAT:
      if ((q->type == GF_FXP_STAT ? stat (path, &st) : lstat (path, &st)) < 0)
        return sftp_status (x, q->id, errno);
      stat_to_attrs (&st, &a);
      return gf_sftp_server_attrs (x->sftp, q->id, &a) != GF_OK;
    case GF_FXP_FSTAT:
      h = get_handle (x, q->handle);
      if (h == NULL || h->is_dir || fstat (h->fd, &st) < 0)
        return sftp_status (x, q->id, h ? errno : EBADF);
      stat_to_attrs (&st, &a);
      return gf_sftp_server_attrs (x->sftp, q->id, &a) != GF_OK;
    case GF_FXP_SETSTAT:
    case GF_FXP_FSETSTAT:
      {
        int e = 0;

        if (q->type == GF_FXP_FSETSTAT)
          {
            h = get_handle (x, q->handle);
            if (h == NULL || h->is_dir)
              return sftp_status (x, q->id, EBADF);
            if ((q->attrs.flags & GF_FILEXFER_ATTR_PERMISSIONS)
                && fchmod (h->fd, q->attrs.permissions & 07777) < 0)
              e = errno;
            if (!e && (q->attrs.flags & GF_FILEXFER_ATTR_SIZE)
                && ftruncate (h->fd, (off_t) q->attrs.size) < 0)
              e = errno;
          }
        else
          {
            if ((q->attrs.flags & GF_FILEXFER_ATTR_PERMISSIONS)
                && chmod (path, q->attrs.permissions & 07777) < 0)
              e = errno;
            if (!e && (q->attrs.flags & GF_FILEXFER_ATTR_SIZE)
                && truncate (path, (off_t) q->attrs.size) < 0)
              e = errno;
          }
        return sftp_status (x, q->id, e);
      }
    case GF_FXP_OPENDIR:
      {
        DIR *d = opendir (path);

        if (d == NULL || new_handle (x, 1, -1, d, hb) < 0)
          return sftp_status (x, q->id, d ? EMFILE : errno);
        return gf_sftp_server_handle (x->sftp, q->id, hb, 2) != GF_OK;
      }
    case GF_FXP_READDIR:
      {
        enum { BATCH = 16 };
        gf_sftp_name names[BATCH];
        static char fn[BATCH][NAME_MAX + 1], ln[BATCH][NAME_MAX + 100];
        size_t n = 0;
        struct dirent *de;

        h = get_handle (x, q->handle);
        if (h == NULL || !h->is_dir)
          return sftp_status (x, q->id, EBADF);
        while (n < BATCH && (de = readdir (h->dir)) != NULL)
          {
            char full[PATH_MAX];

            snprintf (fn[n], sizeof fn[n], "%s", de->d_name);
            snprintf (full, sizeof full, "%s", de->d_name);
            memset (&st, 0, sizeof st);
            /* Relative to the directory read: look it up through fd.  */
            if (fstatat (dirfd (h->dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW)
                < 0)
              continue;
            snprintf (ln[n], sizeof ln[n], "%c%o %lld %s",
                      S_ISDIR (st.st_mode) ? 'd' : '-',
                      (unsigned) st.st_mode & 07777,
                      (long long) st.st_size, de->d_name);
            names[n].filename.data = (const uint8_t *) fn[n];
            names[n].filename.len = strlen (fn[n]);
            names[n].longname.data = (const uint8_t *) ln[n];
            names[n].longname.len = strlen (ln[n]);
            stat_to_attrs (&st, &names[n].attrs);
            n++;
          }
        if (n == 0)
          return gf_sftp_server_status (x->sftp, q->id, GF_FX_EOF, "eof") != GF_OK;
        return gf_sftp_server_names (x->sftp, q->id, n, names) != GF_OK;
      }
    case GF_FXP_REMOVE:
      return sftp_status (x, q->id, unlink (path) < 0 ? errno : 0);
    case GF_FXP_RMDIR:
      return sftp_status (x, q->id, rmdir (path) < 0 ? errno : 0);
    case GF_FXP_MKDIR:
      return sftp_status (x, q->id, mkdir (path, (q->attrs.flags
                          & GF_FILEXFER_ATTR_PERMISSIONS)
                          ? q->attrs.permissions & 0777 : 0755) < 0 ? errno : 0);
    case GF_FXP_RENAME:
      /* v3 RENAME does not replace.  */
      if (lstat (path2, &st) == 0)
        return sftp_status (x, q->id, EEXIST);
      return sftp_status (x, q->id, rename (path, path2) < 0 ? errno : 0);
    case GF_FXP_REALPATH:
      {
        gf_sftp_name nm;
        char virt[PATH_MAX];

        /* The virtual path: what map_path made, without the root.  */
        snprintf (virt, sizeof virt, "%s", path + strlen (x->sftp_root));
        if (virt[0] == '\0')
          snprintf (virt, sizeof virt, "/");
        nm.filename.data = (const uint8_t *) virt;
        nm.filename.len = strlen (virt);
        nm.longname = nm.filename;
        memset (&nm.attrs, 0, sizeof nm.attrs);
        return gf_sftp_server_names (x->sftp, q->id, 1, &nm) != GF_OK;
      }
    case GF_FXP_SYMLINK:
      {
        /* The target is kept as given: path2 was mapped, so use the raw
           text.  */
        char target[PATH_MAX];

        snprintf (target, sizeof target, "%.*s", (int) q->path2.len,
                  (const char *) q->path2.data);
        return sftp_status (x, q->id, symlink (target, path) < 0 ? errno : 0);
      }
    case GF_FXP_READLINK:
      {
        char target[PATH_MAX];
        ssize_t n = readlink (path, target, sizeof target - 1);
        gf_sftp_name nm;

        if (n < 0)
          return sftp_status (x, q->id, errno);
        target[n] = '\0';
        nm.filename.data = (const uint8_t *) target;
        nm.filename.len = (size_t) n;
        nm.longname = nm.filename;
        memset (&nm.attrs, 0, sizeof nm.attrs);
        return gf_sftp_server_names (x->sftp, q->id, 1, &nm) != GF_OK;
      }
    case GF_FXP_EXTENDED:
      if (q->ext_name.len == 24
          && memcmp (q->ext_name.data, "posix-rename@openssh.com", 24) == 0)
        {
          gf_reader rd;
          gf_slice a1, a2;
          char p1[PATH_MAX], p2[PATH_MAX];

          gf_reader_init (&rd, q->ext_data.data, q->ext_data.len);
          if (gf_rd_string (&rd, &a1) != GF_OK || gf_rd_string (&rd, &a2) != GF_OK
              || map_path (x, a1, p1, sizeof p1) || map_path (x, a2, p2, sizeof p2))
            return gf_sftp_server_status (x->sftp, q->id, GF_FX_BAD_MESSAGE,
                                          "bad") != GF_OK;
          return sftp_status (x, q->id, rename (p1, p2) < 0 ? errno : 0);
        }
      return gf_sftp_server_status (x->sftp, q->id, GF_FX_OP_UNSUPPORTED,
                                    "unsupported") != GF_OK;
    default:
      return gf_sftp_server_status (x->sftp, q->id, GF_FX_OP_UNSUPPORTED,
                                    "unsupported") != GF_OK;
    }
}

static long
sftp_write (void *user, const uint8_t *d, size_t n)
{
  struct ctx *x = user;
  /* Offer it all: the library takes what the window allows, and a short
     result is what makes it tell us when to try again.  */
  long r = gf_chans_send_data (x->chans, x->chan, d, n);

  return r == GF_ERR_AGAIN ? 0 : r;
}

static void
sftp_disconnect (void *user, int status)
{
  struct ctx *x = user;

  printf ("SFTP ENDED %d\n", status);
  fflush (stdout);
  gf_chans_close (x->chans, x->chan);
}

static int
chan_open_request (void *user, const gf_chan_open *o)
{
  struct ctx *x = user;

  if (x->active)
    return gf_chans_open_reject (x->chans, o->id,
                                 GF_OPEN_RESOURCE_SHORTAGE, "busy") != GF_OK;
  if (o->type == GF_CHAN_DIRECT_TCPIP)
    {
      printf ("FORWARD %.*s %u\n", (int) o->host.len,
              (const char *) o->host.data, (unsigned) o->port);
      fflush (stdout);
      x->mode = M_ECHO;
      x->tcpip = 1;
    }
  else if (o->type != GF_CHAN_SESSION)
    return gf_chans_open_reject (x->chans, o->id,
                                 GF_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                 "not here") != GF_OK;
  else
    {
      x->mode = M_NONE;
      x->tcpip = 0;
    }
  x->chan = o->id;
  x->active = 1;
  x->finishing = 0;
  x->outn = 0;
  x->exit_status = 0;
  return gf_chans_open_accept (x->chans, o->id, 0, 0) != GF_OK;
}

static int
chan_request (void *user, const gf_chan_request *q)
{
  struct ctx *x = user;
  int ok = 1;
  char cmd[256];

  switch (q->type)
    {
    case GF_REQ_EXEC:
      snprintf (cmd, sizeof cmd, "%.*s", (int) q->command.len,
                (const char *) q->command.data);
      printf ("EXEC %s\n", cmd);
      fflush (stdout);
      if (strcmp (cmd, "true") == 0)
        x->mode = M_TRUE;
      else if (strncmp (cmd, "exit ", 5) == 0)
        {
          x->mode = M_TRUE;
          x->exit_status = (uint32_t) atoi (cmd + 5);
        }
      else if (strncmp (cmd, "echo ", 5) == 0)
        {
          x->mode = M_TRUE;
          if (gf_chans_reply (x->chans, q->id, 1) != GF_OK)
            return 1;
          cmd[strlen (cmd)] = '\0';
          strcat (cmd, "\n");
          return out_add (x, (const uint8_t *) cmd + 5, strlen (cmd + 5))
            || maybe_finish (x);
        }
      else if (strncmp (cmd, "stderr ", 7) == 0)
        {
          x->mode = M_TRUE;
          if (gf_chans_reply (x->chans, q->id, 1) != GF_OK)
            return 1;
          return gf_chans_send_extended (x->chans, x->chan, 1,
                                         (const uint8_t *) cmd + 7,
                                         strlen (cmd + 7)) < 0
            || maybe_finish (x);
        }
      else if (strcmp (cmd, "cat") == 0)
        x->mode = M_CAT;
      else if (strncmp (cmd, "bytes ", 6) == 0)
        {
          x->mode = M_BYTES;
          x->bytes_left = strtoull (cmd + 6, NULL, 10);
          x->produced = 0;
        }
      else
        ok = 0;
      break;
    case GF_REQ_SUBSYSTEM:
      if (x->sftp_root && q->command.len == 4
          && memcmp (q->command.data, "sftp", 4) == 0 && x->sftp == NULL)
        {
          gf_sftp_server_config sc;
          gf_sftp_server_events se;

          memset (&sc, 0, sizeof sc);
          memset (&se, 0, sizeof se);
          se.user = x;
          se.write = sftp_write;
          se.request = sftp_request;
          se.disconnect = sftp_disconnect;
          if (gf_sftp_server_new (&x->sftp, &sc, &se) != GF_OK)
            ok = 0;
          else
            {
              x->mode = M_SFTP;
              printf ("SFTP START\n");
              fflush (stdout);
            }
        }
      else
        ok = 0;
      break;
    case GF_REQ_ENV:
    case GF_REQ_PTY:
    case GF_REQ_WINDOW_CHANGE:
    case GF_REQ_SIGNAL:
      break;
    default:
      ok = 0;
      break;
    }
  if (q->want_reply && gf_chans_reply (x->chans, q->id, ok) != GF_OK)
    return 1;
  if (ok && q->type == GF_REQ_EXEC)
    return produce (x) || maybe_finish (x);
  return 0;
}

static int
chan_data (void *user, uint32_t id, const uint8_t *d, size_t n)
{
  struct ctx *x = user;

  if ((x->mode == M_CAT || x->mode == M_ECHO) && out_add (x, d, n))
    return 1;
  if (x->mode == M_SFTP && x->sftp)
    {
      if (gf_sftp_server_input (x->sftp, d, n) != GF_OK)
        return 0;			/* It asked for the channel to close.  */
    }
  return gf_chans_consumed (x->chans, id, n) != GF_OK;
}

static int
chan_eof (void *user, uint32_t id)
{
  struct ctx *x = user;

  (void) id;
  if (x->mode == M_SFTP)
    return gf_chans_close (x->chans, x->chan) != GF_OK;
  if (x->mode == M_ECHO)
    return out_flush (x) || gf_chans_close (x->chans, x->chan) != GF_OK;
  if (x->mode == M_CAT)
    {
      x->mode = M_TRUE;		/* All input is in; finish when it is out.  */
      return out_flush (x) || maybe_finish (x);
    }
  return 0;
}

static int
chan_writable (void *user, uint32_t id)
{
  struct ctx *x = user;

  (void) id;
  if (x->mode == M_SFTP && x->sftp)
    return gf_sftp_server_writable (x->sftp) != GF_OK;
  return out_flush (x) || produce (x) || maybe_finish (x);
}

static int
chan_closed (void *user, uint32_t id)
{
  struct ctx *x = user;

  (void) id;
  x->active = 0;
  if (x->sftp)
    {
      gf_sftp_server_free (x->sftp);
      x->sftp = NULL;
      memset (x->handles, 0, sizeof x->handles);
    }
  printf ("CHANNEL CLOSED\n");
  fflush (stdout);
  return 0;
}

static int
chan_global (void *user, const gf_global_request *r)
{
  struct ctx *x = user;

  if (r->type == GF_GLOBAL_TCPIP_FORWARD)
    {
      printf ("TCPIP-FORWARD %.*s %u\n", (int) r->addr.len,
              (const char *) r->addr.data, (unsigned) r->port);
      fflush (stdout);
    }
  if (!r->want_reply)
    return 0;
  return gf_chans_global_reply (x->chans, 1, r->port == 0 ? 40000 : 0) != GF_OK;
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
  uint64_t rekey_bytes = 0;
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
      else if (strcmp (argv[i], "--rekey-bytes") == 0 && i + 1 < argc)
        rekey_bytes = strtoull (argv[++i], NULL, 10);
      else if (strcmp (argv[i], "--sftp-root") == 0 && i + 1 < argc)
        x.sftp_root = argv[++i];
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
  cfg.rekey_bytes = rekey_bytes;
  memset (&ev, 0, sizeof ev);
  ev.user = &x;
  ev.write = on_write;
  ev.established = on_established;
  ev.rekeyed = on_rekeyed;
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
  {
    gf_chans_config cc;
    gf_chans_events ce;

    memset (&cc, 0, sizeof cc);
    memset (&ce, 0, sizeof ce);
    ce.user = &x;
    ce.send = chans_send;
    ce.disconnect = chans_disconnect;
    ce.open_request = chan_open_request;
    ce.request = chan_request;
    ce.data = chan_data;
    ce.eof = chan_eof;
    ce.writable = chan_writable;
    ce.closed = chan_closed;
    ce.global_request = chan_global;
    if (gf_chans_new (&x.chans, &cc, &ce) != GF_OK)
      return 2;
  }
  if (gf_conn_server_new (&x.c, &cfg, &ev) != GF_OK
      || gf_auth_server_new (&x.auth, &ac, &ae) != GF_OK
      || gf_conn_start (x.c, now_us ()) != GF_OK)
    {
      fprintf (stderr, "cannot start\n");
      return 2;
    }
  r = drive (x.c, x.fd, NULL, NULL, 20000);
  printf ("DONE %d\n", r);
  gf_chans_free (x.chans);
  free (x.out);
  gf_auth_server_free (x.auth);
  gf_conn_free (x.c);
  gf_key_free (key);
  gf_key_free (x.authorized);
  close (x.fd);
  return x.established ? 0 : 1;
}
