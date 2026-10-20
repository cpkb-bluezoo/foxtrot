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
                                 [--streamlocal-callback]
                                 [--ca-key PUBFILE] [--host-cert CERTFILE]

   HOSTKEY is an unencrypted OpenSSH private key file.  The server accepts
   one connection on 127.0.0.1:PORT, completes the transport handshake and
   accepts the ssh-userauth service.  Users authenticate with the public key
   of the private key file given by --auth-key, with a certificate signed by
   the CA whose public key file is given by --ca-key (the user must be a
   principal; the peer address is 127.0.0.1), with the password PW, or by
   answering a keyboard-interactive question with CODE, as given.  With
   --host-cert the host key is presented with that certificate.  If the
   user's certificate forces a command, "FORCE command" is printed and that
   command is run for any exec request.  Once
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
   tried without a network) and direct-streamlocal ones (the same, for
   ssh -L with a Unix socket: "STREAMLOCAL path"); tcpip-forward and
   streamlocal-forward requests are granted ("STREAMLOCAL-FORWARD path"), and
   with --streamlocal-callback a granted streamlocal-forward is followed by a
   forwarded-streamlocal channel to the client, on which "hello from
   foxtrot" is sent and the first line the client's socket answers is
   printed as "FORWARDED-DATA line".  On
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
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <limits.h>

#include <foxtrot/session.h>
#include <foxtrot/key.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

struct ctx
{
  int fd;
  gf_session *s;
  gf_chans *chans;
  gf_key *authorized;
  const char *password, *code;
  const char *forced;
  int established, authed, hostbound_used;
  const char *method;
  /* The one channel being served.  */
  uint32_t chan;
  int active, tcpip;
  /* With --streamlocal-callback: the channel we open to the client when it
     asks us to listen on a Unix socket, and what it says on it.  */
  int sl_callback, fchan_open;
  uint32_t fchan;
  char fbuf[256];
  size_t fn;
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

  printf ("KEX %s %s %s\n", gf_kex_name (info->kex),
          gf_cipher_name (info->cipher_c2s), gf_sigalg_name (info->hostkey_alg));
  printf ("CLIENT %.*s\n", (int) info->peer_software.len,
          (const char *) info->peer_software.data);
  fflush (stdout);
  x->established = 1;
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
auth_request (void *user, const gf_auth_request *req)
{
  struct ctx *x = user;
  int ok = 0;

  switch (req->method)
    {
    case GF_AUTH_PUBLICKEY:
      x->method = req->hostbound ? "publickey-hostbound" : "publickey";
      ok = (x->authorized && gf_key_equal (x->authorized, req->key))
        || req->certificate;
      if (req->certificate && req->has_signature)
        {
          gf_cert_info ci;

          gf_key_certificate_info (req->key, &ci);
          printf ("CERT serial=%llu id=%.*s\n", (unsigned long long) ci.serial,
                  (int) ci.key_id.len, (const char *) ci.key_id.data);
        }
      if (!req->has_signature)
        return (ok ? gf_session_auth_pk_ok (x->s)
                   : gf_session_auth_reject (x->s, 0)) != GF_OK;
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
        return gf_session_auth_kbdint_prompt (x->s, "", "", 1, prompts, echo)
          != GF_OK;
      }
    default:
      break;
    }
  printf ("REQUEST %s %s\n", x->method ? x->method : "?", ok ? "yes" : "no");
  return (ok ? gf_session_auth_accept (x->s)
             : gf_session_auth_reject (x->s, 0)) != GF_OK;
}

static int
auth_kbd_response (void *user, const gf_slice *r, size_t n)
{
  struct ctx *x = user;
  int ok = n == 1 && x->code && r[0].len == strlen (x->code)
    && memcmp (r[0].data, x->code, r[0].len) == 0;

  return (ok ? gf_session_auth_accept (x->s)
             : gf_session_auth_reject (x->s, 0)) != GF_OK;
}

static int
auth_done (void *user, gf_slice username)
{
  struct ctx *x = user;

  printf ("AUTH OK %.*s %s\n", (int) username.len,
          (const char *) username.data, x->method);
  fflush (stdout);
  x->authed = 1;
  x->forced = gf_session_force_command (x->s);
  if (x->forced)
    printf ("FORCE %s\n", x->forced);
  fflush (stdout);
  return 0;
}

/* ---- channels ---- */

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

/* The OpenSSH extensions, on the real file system under the root.  */
static int
sftp_extension (struct ctx *x, const gf_sftp_request *q)
{
  gf_sftp_ext_request e;
  char p1[PATH_MAX], p2[PATH_MAX];
  struct sftp_handle *h, *h2;

  if (gf_sftp_request_extension (q, &e) != GF_OK)
    return gf_sftp_server_status (x->sftp, q->id, GF_FX_BAD_MESSAGE, "bad") != GF_OK;
  if ((e.path.len && map_path (x, e.path, p1, sizeof p1))
      || (e.path2.len && map_path (x, e.path2, p2, sizeof p2)))
    return sftp_status (x, q->id, ENAMETOOLONG);
  switch (e.which)
    {
    case GF_SFTPX_POSIX_RENAME:
      return sftp_status (x, q->id, rename (p1, p2) < 0 ? errno : 0);
    case GF_SFTPX_HARDLINK:
      return sftp_status (x, q->id, link (p1, p2) < 0 ? errno : 0);
    case GF_SFTPX_FSYNC:
      h = get_handle (x, e.handle);
      if (h == NULL || h->is_dir)
        return sftp_status (x, q->id, EBADF);
      return sftp_status (x, q->id, fsync (h->fd) < 0 ? errno : 0);
    case GF_SFTPX_LSETSTAT:
      if ((e.attrs.flags & GF_FILEXFER_ATTR_PERMISSIONS)
          && fchmodat (AT_FDCWD, p1, e.attrs.permissions & 07777,
                       AT_SYMLINK_NOFOLLOW) < 0)
        return sftp_status (x, q->id, errno);
      return sftp_status (x, q->id, 0);
    case GF_SFTPX_STATVFS:
    case GF_SFTPX_FSTATVFS:
      {
        struct statvfs vs;
        gf_sftp_statvfs sv;
        int rc;

        if (e.which == GF_SFTPX_STATVFS)
          rc = statvfs (p1, &vs);
        else
          {
            h = get_handle (x, e.handle);
            if (h == NULL || h->is_dir)
              return sftp_status (x, q->id, EBADF);
            rc = fstatvfs (h->fd, &vs);
          }
        if (rc < 0)
          return sftp_status (x, q->id, errno);
        sv.bsize = vs.f_bsize;
        sv.frsize = vs.f_frsize;
        sv.blocks = vs.f_blocks;
        sv.bfree = vs.f_bfree;
        sv.bavail = vs.f_bavail;
        sv.files = vs.f_files;
        sv.ffree = vs.f_ffree;
        sv.favail = vs.f_favail;
        sv.fsid = vs.f_fsid;
        sv.flag = (vs.f_flag & ST_RDONLY ? GF_SFTP_ST_RDONLY : 0)
          | (vs.f_flag & ST_NOSUID ? GF_SFTP_ST_NOSUID : 0);
        sv.namemax = vs.f_namemax;
        return gf_sftp_server_statvfs (x->sftp, q->id, &sv) != GF_OK;
      }
    case GF_SFTPX_LIMITS:
      {
        gf_sftp_limits l = { GF_SFTP_DEFAULT_MAX_PACKET, 65536, 65536, 64 };

        return gf_sftp_server_limits (x->sftp, q->id, &l) != GF_OK;
      }
    case GF_SFTPX_EXPAND_PATH:
      {
        gf_sftp_name nm;
        char virt[PATH_MAX];

        /* "~" and "~/x" are the root of what is served.  */
        if (e.path.len >= 1 && e.path.data[0] == '~')
          {
            gf_slice rest = { e.path.data + 1, e.path.len - 1 };

            if (rest.len > 0 && rest.data[0] != '/')
              return sftp_status (x, q->id, ENOENT);	/* ~user: no.  */
            if (rest.len == 0)
              snprintf (virt, sizeof virt, "/");
            else if (map_path (x, rest, p2, sizeof p2))
              return sftp_status (x, q->id, ENAMETOOLONG);
            else
              snprintf (virt, sizeof virt, "%s", p2 + strlen (x->sftp_root));
          }
        else
          snprintf (virt, sizeof virt, "%s", p1 + strlen (x->sftp_root));
        if (virt[0] == '\0')
          snprintf (virt, sizeof virt, "/");
        nm.filename.data = (const uint8_t *) virt;
        nm.filename.len = strlen (virt);
        nm.longname = nm.filename;
        memset (&nm.attrs, 0, sizeof nm.attrs);
        return gf_sftp_server_names (x->sftp, q->id, 1, &nm) != GF_OK;
      }
    case GF_SFTPX_COPY_DATA:
      h = get_handle (x, e.handle);
      h2 = get_handle (x, e.handle2);
      if (h == NULL || h2 == NULL || h->is_dir || h2->is_dir)
        return sftp_status (x, q->id, EBADF);
      {
        uint8_t buf[65536];
        uint64_t left = e.length, off = e.offset, woff = e.offset2;
        int to_end = e.length == 0;

        while (to_end || left > 0)
          {
            size_t want = sizeof buf;
            ssize_t n;

            if (!to_end && left < want)
              want = (size_t) left;
            n = pread (h->fd, buf, want, (off_t) off);
            if (n < 0)
              return sftp_status (x, q->id, errno);
            if (n == 0)
              {
                if (to_end)
                  break;
                return sftp_status (x, q->id, EIO);
              }
            if (pwrite (h2->fd, buf, (size_t) n, (off_t) woff) != n)
              return sftp_status (x, q->id, errno ? errno : EIO);
            off += (uint64_t) n;
            woff += (uint64_t) n;
            if (!to_end)
              left -= (uint64_t) n;
          }
        return sftp_status (x, q->id, 0);
      }
    case GF_SFTPX_USERS_GROUPS:
      {
        static char names[2 * GF_SFTP_MAX_IDS][64];
        const char *users[GF_SFTP_MAX_IDS], *groups[GF_SFTP_MAX_IDS];
        size_t nu = 0, ng = 0;
        uint32_t v;
        gf_slice l;

        for (l = e.uids; gf_sftp_u32_next (&l, &v); nu++)
          {
            struct passwd *pw = getpwuid ((uid_t) v);

            snprintf (names[nu], sizeof names[nu], "%s", pw ? pw->pw_name : "");
            users[nu] = names[nu];
          }
        for (l = e.gids; gf_sftp_u32_next (&l, &v); ng++)
          {
            struct group *gr = getgrgid ((gid_t) v);

            snprintf (names[GF_SFTP_MAX_IDS + ng], 64, "%s", gr ? gr->gr_name : "");
            groups[ng] = names[GF_SFTP_MAX_IDS + ng];
          }
        return gf_sftp_server_users_groups (x->sftp, q->id, nu, users, ng, groups)
          != GF_OK;
      }
    case GF_SFTPX_UNKNOWN:
      break;
    }
  return gf_sftp_server_status (x->sftp, q->id, GF_FX_OP_UNSUPPORTED,
                                "unsupported") != GF_OK;
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
      return sftp_extension (x, q);
    default:
      return gf_sftp_server_status (x->sftp, q->id, GF_FX_OP_UNSUPPORTED,
                                    "unsupported") != GF_OK;
    }
}

static void
sftp_disconnect (void *user, int status)
{
  struct ctx *x = user;

  (void) x;
  printf ("SFTP ENDED %d\n", status);
  fflush (stdout);
}

static int
chan_open_request (void *user, const gf_chan_open *o)
{
  struct ctx *x = user;

  if (x->active)
    return gf_session_channel_reject (x->s, o->id, GF_OPEN_RESOURCE_SHORTAGE,
                                      "busy") != GF_OK;
  if (o->type == GF_CHAN_DIRECT_TCPIP)
    {
      printf ("FORWARD %.*s %u\n", (int) o->host.len,
              (const char *) o->host.data, (unsigned) o->port);
      fflush (stdout);
      x->mode = M_ECHO;
      x->tcpip = 1;
    }
  else if (o->type == GF_CHAN_DIRECT_STREAMLOCAL)
    {
      printf ("STREAMLOCAL %.*s\n", (int) o->path.len, (const char *) o->path.data);
      fflush (stdout);
      x->mode = M_ECHO;
      x->tcpip = 1;
    }
  else if (o->type != GF_CHAN_SESSION)
    return gf_session_channel_reject (x->s, o->id,
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
  return gf_session_channel_accept (x->s, o->id, 0, 0) != GF_OK;
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
      /* A certificate that forces a command gets that and nothing else.  */
      if (x->forced)
        snprintf (cmd, sizeof cmd, "%s", x->forced);
      else
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
          sc.extensions = gf_sftp_standard_extensions (&sc.nextensions);
          se.user = x;
          se.request = sftp_request;
          se.disconnect = sftp_disconnect;
          /* The reply must go before the first SFTP byte can arrive.  */
          if (gf_chans_reply (x->chans, q->id, 1) != GF_OK
              || gf_session_sftp_server (x->s, q->id, &sc, &se, &x->sftp)
                 != GF_OK)
            return 1;
          x->mode = M_SFTP;
          printf ("SFTP START\n");
          fflush (stdout);
          return 0;
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

  if (x->fchan_open && id == x->fchan)
    {
      /* What the client's local socket said on a channel we opened.  */
      size_t i;

      for (i = 0; i < n && x->fn < sizeof x->fbuf - 1; i++)
        x->fbuf[x->fn++] = (char) d[i];
      x->fbuf[x->fn] = '\0';
      if (strchr (x->fbuf, '\n') != NULL)
        {
          printf ("FORWARDED-DATA %s", x->fbuf);
          fflush (stdout);
          if (gf_chans_consumed (x->chans, id, n) != GF_OK)
            return 1;
          return gf_chans_close (x->chans, id) != GF_OK;
        }
      return gf_chans_consumed (x->chans, id, n) != GF_OK;
    }
  if ((x->mode == M_CAT || x->mode == M_ECHO) && out_add (x, d, n))
    return 1;
  return gf_chans_consumed (x->chans, id, n) != GF_OK;
}

static int
chan_eof (void *user, uint32_t id)
{
  struct ctx *x = user;

  (void) id;
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
  return out_flush (x) || produce (x) || maybe_finish (x);
}

static int
chan_closed (void *user, uint32_t id)
{
  struct ctx *x = user;

  if (x->fchan_open && id == x->fchan)
    {
      x->fchan_open = 0;
      printf ("FORWARDED CLOSED\n");
      fflush (stdout);
      return 0;
    }
  x->active = 0;
  x->sftp = NULL;			/* The session freed it.  */
  memset (x->handles, 0, sizeof x->handles);
  printf ("CHANNEL CLOSED\n");
  fflush (stdout);
  return 0;
}

static int
chan_confirmed (void *user, uint32_t id)
{
  struct ctx *x = user;
  static const uint8_t hello[] = "hello from foxtrot\n";

  if (!x->fchan_open || id != x->fchan)
    return 0;
  printf ("FORWARDED OPEN\n");
  fflush (stdout);
  return gf_chans_send_data (x->chans, id, hello, sizeof hello - 1) < 0;
}

static int
chan_failed (void *user, uint32_t id, uint32_t reason, gf_slice text)
{
  struct ctx *x = user;

  (void) reason;
  if (x->fchan_open && id == x->fchan)
    {
      x->fchan_open = 0;
      printf ("FORWARDED FAILED %.*s\n", (int) text.len, (const char *) text.data);
      fflush (stdout);
    }
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
  if (r->type == GF_GLOBAL_STREAMLOCAL_FORWARD
      || r->type == GF_GLOBAL_CANCEL_STREAMLOCAL_FORWARD)
    {
      char path[GF_MAX_SOCKET_PATH + 1];

      snprintf (path, sizeof path, "%.*s", (int) r->path.len,
                (const char *) r->path.data);
      printf ("%s %s\n", r->type == GF_GLOBAL_STREAMLOCAL_FORWARD
              ? "STREAMLOCAL-FORWARD" : "CANCEL-STREAMLOCAL-FORWARD", path);
      fflush (stdout);
      if (r->want_reply && gf_chans_global_reply (x->chans, 1, 0) != GF_OK)
        return 1;
      /* A connection to the socket, as if one came: tell the client.  */
      if (r->type == GF_GLOBAL_STREAMLOCAL_FORWARD && x->sl_callback
          && !x->fchan_open)
        {
          if (gf_chans_open_forwarded_streamlocal (x->chans, &x->fchan, path,
                                                   0, 0) != GF_OK)
            return 1;
          x->fchan_open = 1;
          x->fn = 0;
        }
      return 0;
    }
  if (!r->want_reply)
    return 0;
  return gf_chans_global_reply (x->chans, 1,
                                r->type == GF_GLOBAL_TCPIP_FORWARD
                                && r->port == 0 ? 40000 : 0) != GF_OK;
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
  gf_key *user_ca = NULL, *host_cert = NULL;
  const gf_key *cas[1];
  char fp[64];
  struct ctx x;
  gf_key *key;
  gf_session_config cfg;
  gf_session_events ev;

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
      else if (strcmp (argv[i], "--streamlocal-callback") == 0)
        x.sl_callback = 1;
      else if (strcmp (argv[i], "--sftp-root") == 0 && i + 1 < argc)
        x.sftp_root = argv[++i];
      else if (strcmp (argv[i], "--ca-key") == 0 && i + 1 < argc)
        {
          user_ca = read_pub (argv[++i]);
          if (user_ca == NULL)
            {
              fprintf (stderr, "cannot read the CA key\n");
              return 2;
            }
        }
      else if (strcmp (argv[i], "--host-cert") == 0 && i + 1 < argc)
        {
          host_cert = read_pub (argv[++i]);
          if (host_cert == NULL)
            {
              fprintf (stderr, "cannot read the host certificate\n");
              return 2;
            }
        }
      else
        {
          fprintf (stderr, "bad option %s\n", argv[i]);
          return 2;
        }
    }
  if (host_cert != NULL)
    {
      gf_key *both = NULL;

      if (gf_key_with_certificate (key, host_cert, &both) != GF_OK)
        {
          fprintf (stderr, "the certificate is not for the host key\n");
          return 2;
        }
      gf_key_free (key);
      key = both;
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
  cfg.conn.host_keys = &key;
  cfg.conn.nhost_keys = 1;
  cfg.conn.rekey_bytes = rekey_bytes;
  cfg.server_auth.methods = (x.authorized ? GF_AUTH_PUBLICKEY : 0)
    | (x.password ? GF_AUTH_PASSWORD : 0) | (x.code ? GF_AUTH_KBDINT : 0);
  cfg.server_auth.hostbound = hostbound;
  if (user_ca != NULL)
    {
      cas[0] = user_ca;
      cfg.server_auth.trusted_user_cas = cas;
      cfg.server_auth.ntrusted_user_cas = 1;
      cfg.server_auth.peer_address = "127.0.0.1";
      cfg.server_auth.methods |= GF_AUTH_PUBLICKEY;
    }
  memset (&ev, 0, sizeof ev);
  ev.user = &x;
  ev.write = on_write;
  ev.established = on_established;
  ev.auth_request = auth_request;
  ev.auth_kbdint_response = auth_kbd_response;
  ev.authenticated = auth_done;
  ev.channel_open = chan_open_request;
  ev.channel_request = chan_request;
  ev.channel_data = chan_data;
  ev.channel_eof = chan_eof;
  ev.channel_writable = chan_writable;
  ev.channel_closed = chan_closed;
  ev.global_request = chan_global;
  ev.channel_confirmed = chan_confirmed;
  ev.channel_failed = chan_failed;
  ev.closed = on_closed;
  if (gf_session_server_new (&x.s, &cfg, &ev) != GF_OK
      || gf_session_start (x.s, now_us ()) != GF_OK)
    {
      fprintf (stderr, "cannot start\n");
      return 2;
    }
  x.chans = gf_session_channels (x.s);
  r = drive (x.s, x.fd, NULL, NULL, 20000);
  printf ("DONE %d\n", r);
  free (x.out);
  gf_session_free (x.s);
  gf_key_free (key);
  gf_key_free (x.authorized);
  gf_key_free (user_ca);
  gf_key_free (host_cert);
  close (x.fd);
  return x.established ? 0 : 1;
}
