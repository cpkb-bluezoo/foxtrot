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

/* A session: the transport, user authentication and the connection
   protocol joined into one object with one set of events.

   It is a facade over conn.h, auth.h and chan.h, which stay public and
   usable on their own (a proxy that wants to route messages differently
   can).  What the session does for the application is the plumbing that
   every application would otherwise write the same way:

     - routes messages 50 to 79 to the authentication machine and 80 to 100
       to the channels, and ends the connection if a peer sends a channel
       message before authentication, or a message number nobody knows
       (that one is answered with SSH_MSG_UNIMPLEMENTED);
     - requests the ssh-userauth service, hands the authentication machine
       the session identifier and the host key, and passes it the server's
       extensions (RFC 8308), including server-sig-algs and the host-bound
       public key method;
     - turns every layer's request to end the connection into a DISCONNECT;
     - starts key exchanges when due, and resumes channels that were held
       back by one;
     - keeps one deadline for the application to wait for, the earliest of
       the transport's and the authentication grace time;
     - enforces no-more-sessions@openssh.com and a limit on session
       channels, and refuses what the application has not been asked to
       decide: with no channel_open callback every channel is refused, and
       with no global_request callback every global request is.

   Everything is optional except the write callback, the host key callback
   of a client, and the authentication request callback of a server.  A
   client with no host_key callback trusts nothing.

   SFTP is bound to a channel with gf_session_sftp_server or
   gf_session_sftp_client; the session then carries its data, flushes its
   output when the channel can take more, and closes the channel if the
   SFTP session fails.

   The session has the phases HANDSHAKE (key exchange), AUTH and READY
   (authenticated; channels allowed), then CLOSED.

   Time is the caller's clock in microseconds, as everywhere.  Calls that
   take a time update the session's idea of it; the channel functions do
   not take one, and use the time of the last call that did (or of
   gf_session_set_time).  Threading: one session is used from one thread at
   a time, and callbacks must not free it.  */

#ifndef FOXTROT_SESSION_H
#define FOXTROT_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/auth.h>
#include <foxtrot/chan.h>
#include <foxtrot/conn.h>
#include <foxtrot/sftp.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gf_session_phase
{
  GF_PHASE_HANDSHAKE = 1,
  GF_PHASE_AUTH,
  GF_PHASE_READY,
  GF_PHASE_CLOSED
};

typedef struct gf_session_events
{
  void *user;

  /* Bytes for the transport.  Required.  Nonzero fails the session.  */
  int (*write) (void *user, const uint8_t *data, size_t len);
  /* The key exchange is complete, before authentication.  Optional.  */
  int (*established) (void *user, const gf_conn_info *info);
  /* A key exchange after the first is complete.  Optional.  */
  int (*rekeyed) (void *user, const gf_conn_info *info);
  /* Client: trust this host key?  Return 0 to trust it.  */
  int (*host_key) (void *user, const gf_key *key);
  /* The wall clock in seconds since 1970, for the validity of
     certificates (a server's user certificates; see auth.h).  Optional:
     without it the library reads time(2).  */
  uint64_t (*unix_time) (void *user);
  /* SSH_MSG_DEBUG from the peer.  The text is the peer's; sanitize it.  */
  void (*debug) (void *user, int always_display, gf_slice text);
  /* The peer did not understand our packet number SEQ.  */
  void (*unimplemented) (void *user, uint32_t seq);

  /* ---- Server: authentication ---- */

  /* A request to decide; answer with gf_session_auth_accept, _reject,
     _pk_ok or _kbdint_prompt, now or later.  Required for a server.  */
  int (*auth_request) (void *user, const gf_auth_request *req);
  int (*auth_kbdint_response) (void *user, const gf_slice *responses,
                               size_t n);

  /* ---- Client: authentication ---- */

  void (*auth_banner) (void *user, gf_slice text);
  /* Keyboard-interactive prompts; answer with
     gf_session_auth_kbdint_respond.  If NULL the method is not tried.  */
  int (*auth_kbdint) (void *user, gf_slice name, gf_slice instruction,
                      size_t nprompts, const gf_slice *prompts,
                      const int *echo);
  /* Nothing is left to try.  The session then disconnects.  */
  int (*auth_failed) (void *user);

  /* Both: authentication succeeded and channels may be used.  A server is
     told the user name (also gf_session_user).  */
  int (*authenticated) (void *user, gf_slice username);

  /* ---- Channels (see chan.h) ---- */

  /* The peer asks to open a channel; answer with gf_session_channel_accept
     or _reject.  Without this callback every channel is refused.  */
  int (*channel_open) (void *user, const gf_chan_open *open);
  int (*channel_confirmed) (void *user, uint32_t id);
  int (*channel_failed) (void *user, uint32_t id, uint32_t reason,
                         gf_slice text);
  /* Data and extended data are valid only during the call; tell the
     channels you have dealt with them with gf_chans_consumed (on
     gf_session_channels), or set chans.auto_window.  With no callback the
     data is dropped.  */
  int (*channel_data) (void *user, uint32_t id, const uint8_t *data,
                       size_t len);
  int (*channel_extended_data) (void *user, uint32_t id, uint32_t type,
                                const uint8_t *data, size_t len);
  int (*channel_eof) (void *user, uint32_t id);
  int (*channel_writable) (void *user, uint32_t id);
  int (*channel_request) (void *user, const gf_chan_request *req);
  int (*channel_request_reply) (void *user, uint32_t id, int success);
  int (*channel_closed) (void *user, uint32_t id);
  /* A global request.  Without this callback every one is refused.  */
  int (*global_request) (void *user, const gf_global_request *req);
  int (*global_reply) (void *user, int success, uint32_t port);

  /* The session ended.  ERROR is 0 for an orderly end, otherwise a negative
     status; REASON is the disconnect reason.  Called at most once.  */
  void (*closed) (void *user, int error, uint32_t reason, gf_slice text);
} gf_session_events;

typedef struct gf_session_config
{
  gf_conn_config conn;
  /* Server: what to offer (methods, host-bound, limits, the user CAs and
     the client's address).  */
  gf_auth_server_config server_auth;
  /* Client: who to be and how (user, keys, password, methods).  */
  gf_auth_client_config client_auth;
  gf_chans_config chans;
  /* Most session channels the peer may have open at once (0: no limit
     beyond the channel limit).  */
  unsigned max_sessions;
} gf_session_config;

typedef struct gf_session gf_session;

int gf_session_client_new (gf_session **out, const gf_session_config *config,
                           const gf_session_events *events);
int gf_session_server_new (gf_session **out, const gf_session_config *config,
                           const gf_session_events *events);
void gf_session_free (gf_session *s);

/* Send our identification and start the key exchange.  */
int gf_session_start (gf_session *s, uint64_t now_us);
/* Bytes from the transport.  */
int gf_session_receive (gf_session *s, uint64_t now_us, const uint8_t *data,
                        size_t len);
/* When to call gf_session_on_timeout, or UINT64_MAX.  */
uint64_t gf_session_timeout (const gf_session *s);
int gf_session_on_timeout (gf_session *s, uint64_t now_us);
void gf_session_set_time (gf_session *s, uint64_t now_us);
int gf_session_disconnect (gf_session *s, uint64_t now_us, uint32_t reason,
                           const char *description);

enum gf_session_phase gf_session_phase (const gf_session *s);
/* The negotiated parameters; NULL before the key exchange completes.  */
const gf_conn_info *gf_session_info (const gf_session *s);
/* The authenticated user, as a NUL-terminated string, on a server after
   authentication; else NULL.  */
const char *gf_session_user (const gf_session *s);
/* A server, after authentication: the command the user's certificate
   forces ("force-command"), or NULL if there is none.  If there is one the
   application must run it, and only it, in place of whatever the client
   asks for in an exec, shell or subsystem request.  Valid until the
   session is freed.  */
const char *gf_session_force_command (const gf_session *s);

/* The layers underneath, for what the session does not wrap: channel
   operations (open, send data, requests, close: see chan.h) and transport
   operations (rekey, debug, ignore).  */
gf_chans *gf_session_channels (gf_session *s);
gf_conn *gf_session_conn (gf_session *s);

/* ---- Server: answers to auth_request ---- */

int gf_session_auth_accept (gf_session *s);
int gf_session_auth_reject (gf_session *s, int partial_success);
int gf_session_auth_pk_ok (gf_session *s);
int gf_session_auth_kbdint_prompt (gf_session *s, const char *name,
                                   const char *instruction, size_t nprompts,
                                   const char *const *prompts, const int *echo);
int gf_session_auth_banner (gf_session *s, const char *text);

/* ---- Client: answer to auth_kbdint ---- */

int gf_session_auth_kbdint_respond (gf_session *s, size_t n,
                                    const char *const *responses);

/* ---- Answers to channel_open ---- */

int gf_session_channel_accept (gf_session *s, uint32_t id, uint32_t window,
                               uint32_t max_packet);
int gf_session_channel_reject (gf_session *s, uint32_t id, uint32_t reason,
                               const char *text);

/* ---- SFTP on a channel ---- */

/* Serve SFTP on channel ID, which is a session channel on which the
   "sftp" subsystem was requested (and answered yes).  The write member of
   EVENTS is ignored; the rest are called as for gf_sftp_server.  The
   object belongs to the session and is freed when the channel closes.  */
int gf_session_sftp_server (gf_session *s, uint32_t id,
                            const gf_sftp_server_config *config,
                            const gf_sftp_server_events *events,
                            gf_sftp_server **out);
/* The same for a client; the INIT is sent at once, so call it when the
   subsystem request was answered yes.  */
int gf_session_sftp_client (gf_session *s, uint32_t id,
                            const gf_sftp_client_config *config,
                            const gf_sftp_client_events *events,
                            gf_sftp_client **out);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_SESSION_H */
