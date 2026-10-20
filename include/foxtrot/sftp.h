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

/* SFTP version 3 (draft-ietf-secsh-filexfer-02), the version every
   implementation speaks, as client and server state machines over the
   byte stream of a channel running the "sftp" subsystem.

   The file system is not here.  A server hands each request to the
   application as a parsed structure and the application answers it, now or
   later, with the response functions; a client turns calls into requests and
   delivers each response, with the tag its request carried, to a callback.
   Both ends frame the stream themselves: gf_sftp_server_input and
   gf_sftp_client_input take bytes as they come, in any chunking, and the
   write callback gets the bytes to send.  The write callback may take less
   than it is offered (a channel with a full window does): the rest is
   kept, up to a limit, and sent when gf_sftp_*_writable is called.

   What the library enforces:
     - the first packet is INIT, version 3 is what is spoken, and a peer
       that cannot speak it is refused;
     - packets are at most max_packet bytes (default 256 KiB), checked when
       the length is readable, before the body arrives;
     - a client's request ids are its own and each response must name one
       that is outstanding and be a response that kind of request can have
       (a READ is answered with DATA or STATUS, never NAME), and DATA is no
       longer than was asked for;
     - a server answers each request once, with a response that fits it;
       an id it does not know, or one answered already, is an error of the
       application;
     - handles are at most 256 bytes; paths and names cannot hold a NUL;
       counts are bounded by the packet that carries them;
     - a client refuses a directory listing with an empty name, or a name
       with a slash in it, which could only be an attempt to have a file
       written outside the directory being copied.
   A malformed request that can be named by its id is answered with
   SSH_FX_BAD_MESSAGE and the session goes on; one that cannot, or a
   protocol violation by the peer, ends the session (the disconnect event).

   Extensions (OpenSSH's PROTOCOL, the ones its sftp client and server use:
   posix-rename, statvfs, fstatvfs, hardlink, fsync, lsetstat, limits,
   expand-path, copy-data and users-groups-by-id) are typed: a server lists
   the ones it implements in its configuration, which become the extension
   pairs of its VERSION, and decodes a request with gf_sftp_request_extension
   (a request of a known extension that is malformed is answered
   SSH_FX_BAD_MESSAGE by the library, so the application sees well-formed
   ones; one it did not advertise it should answer SSH_FX_OP_UNSUPPORTED); a
   client learns what the server advertised and its typed requests are
   refused (GF_ERR_UNSUPPORTED) for an extension the server did not, as
   OpenSSH's client does.  The replies of the extensions are checked as
   strictly as the replies of the base requests: an answer of the wrong kind
   or shape ends the session.  Other extensions pass through as before
   (gf_sftp_client_extended, and the ext_name and ext_data of a request).

   Path handling is the application's, and it is where the security of an
   SFTP server is: nothing here confines a path to a directory.  */

#ifndef FOXTROT_SFTP_H
#define FOXTROT_SFTP_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/wire.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GF_SFTP_VERSION 3
#define GF_SFTP_MAX_HANDLE 256
#define GF_SFTP_MAX_PATH 4096
#define GF_SFTP_DEFAULT_MAX_PACKET (256 * 1024)

enum gf_sftp_type
{
  GF_FXP_INIT = 1,
  GF_FXP_VERSION = 2,
  GF_FXP_OPEN = 3,
  GF_FXP_CLOSE = 4,
  GF_FXP_READ = 5,
  GF_FXP_WRITE = 6,
  GF_FXP_LSTAT = 7,
  GF_FXP_FSTAT = 8,
  GF_FXP_SETSTAT = 9,
  GF_FXP_FSETSTAT = 10,
  GF_FXP_OPENDIR = 11,
  GF_FXP_READDIR = 12,
  GF_FXP_REMOVE = 13,
  GF_FXP_MKDIR = 14,
  GF_FXP_RMDIR = 15,
  GF_FXP_REALPATH = 16,
  GF_FXP_STAT = 17,
  GF_FXP_RENAME = 18,
  GF_FXP_READLINK = 19,
  GF_FXP_SYMLINK = 20,
  GF_FXP_STATUS = 101,
  GF_FXP_HANDLE = 102,
  GF_FXP_DATA = 103,
  GF_FXP_NAME = 104,
  GF_FXP_ATTRS = 105,
  GF_FXP_EXTENDED = 200,
  GF_FXP_EXTENDED_REPLY = 201
};

enum gf_sftp_status
{
  GF_FX_OK = 0,
  GF_FX_EOF = 1,
  GF_FX_NO_SUCH_FILE = 2,
  GF_FX_PERMISSION_DENIED = 3,
  GF_FX_FAILURE = 4,
  GF_FX_BAD_MESSAGE = 5,
  GF_FX_NO_CONNECTION = 6,
  GF_FX_CONNECTION_LOST = 7,
  GF_FX_OP_UNSUPPORTED = 8
};

/* Open flags.  */
#define GF_FXF_READ 0x01
#define GF_FXF_WRITE 0x02
#define GF_FXF_APPEND 0x04
#define GF_FXF_CREAT 0x08
#define GF_FXF_TRUNC 0x10
#define GF_FXF_EXCL 0x20

/* Which attributes are present.  */
#define GF_FILEXFER_ATTR_SIZE 0x01
#define GF_FILEXFER_ATTR_UIDGID 0x02
#define GF_FILEXFER_ATTR_PERMISSIONS 0x04
#define GF_FILEXFER_ATTR_ACMODTIME 0x08

typedef struct gf_sftp_attrs
{
  uint32_t flags;
  uint64_t size;
  uint32_t uid, gid;
  uint32_t permissions;
  uint32_t atime, mtime;
} gf_sftp_attrs;

/* One entry of a directory listing or a path answer.  */
typedef struct gf_sftp_name
{
  gf_slice filename;
  gf_slice longname;
  gf_sftp_attrs attrs;
} gf_sftp_name;

/* ================================================================== */
/* Extensions                                                         */
/* ================================================================== */

#define GF_SFTP_EXT_POSIX_RENAME "posix-rename@openssh.com"
#define GF_SFTP_EXT_STATVFS "statvfs@openssh.com"
#define GF_SFTP_EXT_FSTATVFS "fstatvfs@openssh.com"
#define GF_SFTP_EXT_HARDLINK "hardlink@openssh.com"
#define GF_SFTP_EXT_FSYNC "fsync@openssh.com"
#define GF_SFTP_EXT_LSETSTAT "lsetstat@openssh.com"
#define GF_SFTP_EXT_LIMITS "limits@openssh.com"
#define GF_SFTP_EXT_EXPAND_PATH "expand-path@openssh.com"
#define GF_SFTP_EXT_COPY_DATA "copy-data"
#define GF_SFTP_EXT_USERS_GROUPS "users-groups-by-id@openssh.com"

enum gf_sftp_ext
{
  GF_SFTPX_UNKNOWN = 0,
  GF_SFTPX_POSIX_RENAME,
  GF_SFTPX_STATVFS,
  GF_SFTPX_FSTATVFS,
  GF_SFTPX_HARDLINK,
  GF_SFTPX_FSYNC,
  GF_SFTPX_LSETSTAT,
  GF_SFTPX_LIMITS,
  GF_SFTPX_EXPAND_PATH,
  GF_SFTPX_COPY_DATA,
  GF_SFTPX_USERS_GROUPS
};

/* An extension pair of VERSION: a name and its data (a version, "1" or
   "2").  Both are NUL-terminated text.  */
typedef struct gf_sftp_extension
{
  const char *name;
  const char *data;
} gf_sftp_extension;

/* The ten above, with the versions OpenSSH advertises, for a server that
   implements them all.  *N receives their number.  */
const gf_sftp_extension *gf_sftp_standard_extensions (size_t *n);

/* statvfs@openssh.com and fstatvfs@openssh.com.  */
#define GF_SFTP_ST_RDONLY 0x1
#define GF_SFTP_ST_NOSUID 0x2
typedef struct gf_sftp_statvfs
{
  uint64_t bsize, frsize, blocks, bfree, bavail, files, ffree, favail;
  uint64_t fsid, flag, namemax;
} gf_sftp_statvfs;

/* limits@openssh.com: what the server is prepared for (0 is no limit).  */
typedef struct gf_sftp_limits
{
  uint64_t max_packet, max_read, max_write, max_open_handles;
} gf_sftp_limits;

/* The most user or group ids a users-groups-by-id request may carry.  */
#define GF_SFTP_MAX_IDS 1024

/* A decoded request of an extension.  Which members are set depends on
   WHICH:
     POSIX_RENAME, HARDLINK   path (old), path2 (new)
     STATVFS, EXPAND_PATH     path
     FSTATVFS, FSYNC          handle
     LSETSTAT                 path, attrs
     LIMITS                   nothing
     COPY_DATA                handle and offset and length (to read from),
                              handle2 and offset2 (to write to); a length of
                              0 is to the end of the file
     USERS_GROUPS             uids and gids, each a packed list of uint32
                              read with gf_sftp_u32_next
   Everything points into the request.  */
typedef struct gf_sftp_ext_request
{
  enum gf_sftp_ext which;
  gf_slice path, path2;
  gf_slice handle, handle2;
  gf_sftp_attrs attrs;
  uint64_t offset, length, offset2;
  gf_slice uids, gids;
} gf_sftp_ext_request;

/* Read the next uint32 of a packed list (uids or gids), or the next string
   of a packed list of names (gf_sftp_string_next); advance the list.
   Return 1, or 0 at the end.  */
int gf_sftp_u32_next (gf_slice *list, uint32_t *v);
int gf_sftp_string_next (gf_slice *list, gf_slice *s);

/* ================================================================== */
/* Server                                                             */
/* ================================================================== */

typedef struct gf_sftp_request
{
  uint32_t id;
  enum gf_sftp_type type;
  gf_slice path;		/* OPEN, OPENDIR, LSTAT, STAT, SETSTAT, REMOVE,
				   MKDIR, RMDIR, REALPATH, READLINK; RENAME:
				   the old name; SYMLINK: the link to make.  */
  gf_slice path2;		/* RENAME: the new name; SYMLINK: the target
				   the link points to.  */
  gf_slice handle;		/* CLOSE, READ, WRITE, FSTAT, FSETSTAT,
				   READDIR.  */
  uint32_t pflags;		/* OPEN.  */
  gf_sftp_attrs attrs;		/* OPEN, SETSTAT, FSETSTAT, MKDIR.  */
  uint64_t offset;		/* READ, WRITE.  */
  uint32_t length;		/* READ: at most this many bytes.  */
  gf_slice data;		/* WRITE.  */
  gf_slice ext_name;		/* EXTENDED.  */
  gf_slice ext_data;		/* EXTENDED: the rest of the request.  */
} gf_sftp_request;

/* Decode the request REQ, which is an EXTENDED one.  GF_OK with WHICH set,
   or GF_SFTPX_UNKNOWN for a name that is none of these (the generic
   ext_name and ext_data are then the application's); GF_ERR_ENCODING for
   one of these that is malformed.  */
int gf_sftp_request_extension (const gf_sftp_request *req,
                               gf_sftp_ext_request *out);

typedef struct gf_sftp_server_events
{
  void *user;
  /* Bytes to send on the channel.  Return how many were taken, 0 to LEN;
     the rest is kept and offered again from gf_sftp_server_writable.
     Return a negative value to fail the session.  Required.  */
  long (*write) (void *user, const uint8_t *data, size_t len);
  /* A request to answer.  Everything the request points to is valid only
     during the call (copy what you keep).  Required.  Nonzero fails the
     session.  */
  int (*request) (void *user, const gf_sftp_request *req);
  /* The session must end; the application closes the channel.  */
  void (*disconnect) (void *user, int status);
} gf_sftp_server_events;

typedef struct gf_sftp_server_config
{
  uint32_t max_packet;		/* 0: GF_SFTP_DEFAULT_MAX_PACKET.  */
  unsigned max_requests;	/* Unanswered at once; 0: 128.  */
  size_t max_output;		/* Bytes kept for a peer that is not
				   reading; 0: 4 MiB.  */
  /* The extensions the server implements, sent in its VERSION (copied).
     At most 64, each name and data of up to 128 characters, no name twice.
     NULL: none.  */
  const gf_sftp_extension *extensions;
  size_t nextensions;
} gf_sftp_server_config;

typedef struct gf_sftp_server gf_sftp_server;

int gf_sftp_server_new (gf_sftp_server **out,
                        const gf_sftp_server_config *config,
                        const gf_sftp_server_events *events);
void gf_sftp_server_free (gf_sftp_server *s);

/* Bytes from the client's side of the channel.  */
int gf_sftp_server_input (gf_sftp_server *s, const uint8_t *data, size_t len);
/* The channel can take more: send what was kept.  */
int gf_sftp_server_writable (gf_sftp_server *s);
/* Bytes kept for sending.  */
size_t gf_sftp_server_pending (const gf_sftp_server *s);

/* Answers.  ID names an outstanding request; the kind of response must fit
   the request (GF_ERR_INVAL if not, GF_ERR_STATE if the id is not
   outstanding).  GF_ERR_AGAIN: the output limit is reached; try later.  */
int gf_sftp_server_status (gf_sftp_server *s, uint32_t id, uint32_t code,
                           const char *message);
int gf_sftp_server_handle (gf_sftp_server *s, uint32_t id, const uint8_t *handle,
                           size_t len);
int gf_sftp_server_data (gf_sftp_server *s, uint32_t id, const uint8_t *data,
                         size_t len);
int gf_sftp_server_names (gf_sftp_server *s, uint32_t id, size_t count,
                          const gf_sftp_name *names);
int gf_sftp_server_attrs (gf_sftp_server *s, uint32_t id,
                          const gf_sftp_attrs *attrs);
/* The reply of an extension that is not one of the typed ones; for a typed
   one use its own below (GF_ERR_INVAL otherwise), or gf_sftp_server_status.
   The expand-path reply is gf_sftp_server_names with one name.  */
int gf_sftp_server_extended_reply (gf_sftp_server *s, uint32_t id,
                                   const uint8_t *data, size_t len);
int gf_sftp_server_statvfs (gf_sftp_server *s, uint32_t id,
                            const gf_sftp_statvfs *sv);
int gf_sftp_server_limits (gf_sftp_server *s, uint32_t id,
                           const gf_sftp_limits *limits);
/* The answer to users-groups-by-id: the name of each user id asked for, in
   order, and the name of each group id, "" for one that has none.  The
   counts must be those of the request.  */
int gf_sftp_server_users_groups (gf_sftp_server *s, uint32_t id,
                                 size_t nusers, const char *const *users,
                                 size_t ngroups, const char *const *groups);

/* ================================================================== */
/* Client                                                             */
/* ================================================================== */

typedef struct gf_sftp_response
{
  uint32_t id;
  void *tag;			/* From the request.  */
  enum gf_sftp_type type;	/* STATUS, HANDLE, DATA, NAME, ATTRS or
				   EXTENDED_REPLY.  */
  uint32_t status;		/* STATUS.  */
  gf_slice message;		/* STATUS: the server's words.  */
  gf_slice handle;		/* HANDLE.  */
  gf_slice data;		/* DATA, EXTENDED_REPLY.  */
  gf_sftp_attrs attrs;		/* ATTRS.  */
  uint32_t count;		/* NAME: entries; read with
				   gf_sftp_response_next_name.  */
  gf_slice names_;		/* Internal.  */
} gf_sftp_response;

/* The next entry of a NAME response; returns 1, or 0 at the end or if the
   rest is malformed.  */
int gf_sftp_response_next_name (gf_sftp_response *r, gf_sftp_name *out);

/* The typed replies of the extensions.  Each returns 1 if the response is
   that reply, 0 if not; the client has already checked its shape.  The
   users-groups reply is two packed lists of names (gf_sftp_string_next), one
   entry for each id asked for.  */
int gf_sftp_response_statvfs (const gf_sftp_response *r, gf_sftp_statvfs *sv);
int gf_sftp_response_limits (const gf_sftp_response *r, gf_sftp_limits *l);
int gf_sftp_response_users_groups (const gf_sftp_response *r, gf_slice *users,
                                   gf_slice *groups);

typedef struct gf_sftp_client_events
{
  void *user;
  long (*write) (void *user, const uint8_t *data, size_t len);
  /* The server's VERSION arrived: the session is ready for requests.  */
  int (*ready) (void *user);
  /* The answer to a request.  Valid only during the call.  Nonzero fails
     the session.  */
  int (*response) (void *user, const gf_sftp_response *r);
  void (*disconnect) (void *user, int status);
} gf_sftp_client_events;

typedef struct gf_sftp_client_config
{
  uint32_t max_packet;		/* 0: GF_SFTP_DEFAULT_MAX_PACKET.  */
  unsigned max_requests;	/* Outstanding at once; 0: 64.  */
  size_t max_output;		/* 0: 4 MiB.  */
} gf_sftp_client_config;

typedef struct gf_sftp_client gf_sftp_client;

int gf_sftp_client_new (gf_sftp_client **out,
                        const gf_sftp_client_config *config,
                        const gf_sftp_client_events *events);
void gf_sftp_client_free (gf_sftp_client *c);

/* Send INIT.  Call once the subsystem is running.  */
int gf_sftp_client_start (gf_sftp_client *c);
int gf_sftp_client_input (gf_sftp_client *c, const uint8_t *data, size_t len);
int gf_sftp_client_writable (gf_sftp_client *c);
size_t gf_sftp_client_pending (const gf_sftp_client *c);
int gf_sftp_client_is_ready (const gf_sftp_client *c);

/* Requests.  Each takes a TAG, handed back in the response, and stores the
   id used in *ID (which may be NULL).  GF_ERR_AGAIN: too many outstanding
   or too much unsent; wait for a response or gf_sftp_client_writable.  */
int gf_sftp_client_open (gf_sftp_client *c, const char *path, uint32_t pflags,
                         const gf_sftp_attrs *attrs, void *tag, uint32_t *id);
int gf_sftp_client_close (gf_sftp_client *c, const uint8_t *handle, size_t hl,
                          void *tag, uint32_t *id);
/* LENGTH is the most the answer may carry; it must fit the packet size.  */
int gf_sftp_client_read (gf_sftp_client *c, const uint8_t *handle, size_t hl,
                         uint64_t offset, uint32_t length, void *tag,
                         uint32_t *id);
int gf_sftp_client_write (gf_sftp_client *c, const uint8_t *handle, size_t hl,
                          uint64_t offset, const uint8_t *data, size_t len,
                          void *tag, uint32_t *id);
int gf_sftp_client_stat (gf_sftp_client *c, const char *path, void *tag,
                         uint32_t *id);
int gf_sftp_client_lstat (gf_sftp_client *c, const char *path, void *tag,
                          uint32_t *id);
int gf_sftp_client_fstat (gf_sftp_client *c, const uint8_t *handle, size_t hl,
                          void *tag, uint32_t *id);
int gf_sftp_client_setstat (gf_sftp_client *c, const char *path,
                            const gf_sftp_attrs *attrs, void *tag,
                            uint32_t *id);
int gf_sftp_client_fsetstat (gf_sftp_client *c, const uint8_t *handle,
                             size_t hl, const gf_sftp_attrs *attrs, void *tag,
                             uint32_t *id);
int gf_sftp_client_opendir (gf_sftp_client *c, const char *path, void *tag,
                            uint32_t *id);
int gf_sftp_client_readdir (gf_sftp_client *c, const uint8_t *handle,
                            size_t hl, void *tag, uint32_t *id);
int gf_sftp_client_remove (gf_sftp_client *c, const char *path, void *tag,
                           uint32_t *id);
int gf_sftp_client_mkdir (gf_sftp_client *c, const char *path,
                          const gf_sftp_attrs *attrs, void *tag, uint32_t *id);
int gf_sftp_client_rmdir (gf_sftp_client *c, const char *path, void *tag,
                          uint32_t *id);
int gf_sftp_client_realpath (gf_sftp_client *c, const char *path, void *tag,
                             uint32_t *id);
int gf_sftp_client_rename (gf_sftp_client *c, const char *from, const char *to,
                           void *tag, uint32_t *id);
int gf_sftp_client_readlink (gf_sftp_client *c, const char *path, void *tag,
                             uint32_t *id);
/* Make LINKPATH a link to TARGET.  On the wire the target comes first, as
   OpenSSH and the implementations that follow it do, which is the reverse of
   what the draft text says; a server request has the link in path and the
   target in path2 whichever way they came.  */
int gf_sftp_client_symlink (gf_sftp_client *c, const char *linkpath,
                            const char *target, void *tag, uint32_t *id);
int gf_sftp_client_extended (gf_sftp_client *c, const char *name,
                             const uint8_t *data, size_t len, void *tag,
                             uint32_t *id);

/* What the server advertised in its VERSION: 1 and its data if it did
   (valid until the client is freed), else 0.  */
int gf_sftp_client_extension (const gf_sftp_client *c, const char *name,
                              gf_slice *data);

/* Requests of the extensions.  Each is GF_ERR_UNSUPPORTED if the server did
   not advertise the extension.  The answer is a STATUS, except that
   statvfs, fstatvfs and limits are answered with an EXTENDED_REPLY
   (gf_sftp_response_statvfs, _limits), expand_path with a NAME of one
   entry, and users_groups_by_id with an EXTENDED_REPLY
   (gf_sftp_response_users_groups).  */
int gf_sftp_client_posix_rename (gf_sftp_client *c, const char *from,
                                 const char *to, void *tag, uint32_t *id);
int gf_sftp_client_statvfs (gf_sftp_client *c, const char *path, void *tag,
                            uint32_t *id);
int gf_sftp_client_fstatvfs (gf_sftp_client *c, const uint8_t *handle,
                             size_t hl, void *tag, uint32_t *id);
/* Make NEWPATH another name for the file OLDPATH.  */
int gf_sftp_client_hardlink (gf_sftp_client *c, const char *oldpath,
                             const char *newpath, void *tag, uint32_t *id);
int gf_sftp_client_fsync (gf_sftp_client *c, const uint8_t *handle, size_t hl,
                          void *tag, uint32_t *id);
/* Like setstat, but of a symbolic link itself.  */
int gf_sftp_client_lsetstat (gf_sftp_client *c, const char *path,
                             const gf_sftp_attrs *attrs, void *tag,
                             uint32_t *id);
int gf_sftp_client_limits (gf_sftp_client *c, void *tag, uint32_t *id);
/* Expand a path that begins with "~" or "~user" on the server.  */
int gf_sftp_client_expand_path (gf_sftp_client *c, const char *path, void *tag,
                                uint32_t *id);
/* Copy LENGTH bytes (0: to the end) from OFFSET of the file READ_HANDLE to
   OFFSET2 of WRITE_HANDLE on the server, without them passing through the
   client.  */
int gf_sftp_client_copy_data (gf_sftp_client *c, const uint8_t *read_handle,
                              size_t rhl, uint64_t offset, uint64_t length,
                              const uint8_t *write_handle, size_t whl,
                              uint64_t offset2, void *tag, uint32_t *id);
/* The names of NUIDS user ids and NGIDS group ids (each at most
   GF_SFTP_MAX_IDS).  */
int gf_sftp_client_users_groups_by_id (gf_sftp_client *c, const uint32_t *uids,
                                       size_t nuids, const uint32_t *gids,
                                       size_t ngids, void *tag, uint32_t *id);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_SFTP_H */
