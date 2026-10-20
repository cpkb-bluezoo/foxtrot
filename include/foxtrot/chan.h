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

/* The connection protocol (RFC 4254): channels multiplexed over one
   authenticated transport, with their flow control, requests and
   TCP forwarding.

   A gf_chans object is the same on both ends: either side opens channels
   and accepts them.  Like the authentication machines it attaches to the
   transport through a send callback and an input call for the messages
   numbered 80 to 100; it does no I/O and holds no clocks.

   Flow control is strict, and it is the application's.  The peer may send
   only as much as the window we gave it; more is a protocol error and ends
   the connection.  The window is given back as the application says it has
   dealt with the data (gf_chans_consumed), not as it arrives, so a slow
   consumer slows the sender instead of filling memory.  Nothing is buffered
   for sending either: gf_chans_send_data takes what the peer's window and
   packet size allow and returns how much that was; when it returns less
   than asked the writable event says when to try again.

   What it checks, and ends the connection for: data, requests or window
   changes on a channel that is not open; data after EOF or past the window
   or the packet size; a window beyond 2^32 - 1; a reply nobody is waiting
   for; more pending requests or channels than the configured limits; and
   every malformed message.

   What it refuses by itself, replying failure: X11 forwarding and agent
   forwarding (both extend the trust of the connection to other
   credentials of a machine), channel types other than session,
   direct-tcpip and forwarded-tcpip, and requests and global requests it
   does not know, which is also how the "keepalive@openssh.com" request is
   answered.

   Channel numbers are the local ones: gf_chans allocates them and the
   application names channels by them.  They are reused only after a channel
   is closed on both sides.  */

#ifndef FOXTROT_CHAN_H
#define FOXTROT_CHAN_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/wire.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gf_chan_msg
{
  GF_MSG_GLOBAL_REQUEST = 80,
  GF_MSG_REQUEST_SUCCESS = 81,
  GF_MSG_REQUEST_FAILURE = 82,
  GF_MSG_CHANNEL_OPEN = 90,
  GF_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
  GF_MSG_CHANNEL_OPEN_FAILURE = 92,
  GF_MSG_CHANNEL_WINDOW_ADJUST = 93,
  GF_MSG_CHANNEL_DATA = 94,
  GF_MSG_CHANNEL_EXTENDED_DATA = 95,
  GF_MSG_CHANNEL_EOF = 96,
  GF_MSG_CHANNEL_CLOSE = 97,
  GF_MSG_CHANNEL_REQUEST = 98,
  GF_MSG_CHANNEL_SUCCESS = 99,
  GF_MSG_CHANNEL_FAILURE = 100
};

enum gf_chan_type
{
  GF_CHAN_SESSION = 1,
  GF_CHAN_DIRECT_TCPIP,
  GF_CHAN_FORWARDED_TCPIP
};

/* Reasons for refusing to open a channel (RFC 4254 section 5.1).  */
enum gf_open_failure
{
  GF_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
  GF_OPEN_CONNECT_FAILED = 2,
  GF_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
  GF_OPEN_RESOURCE_SHORTAGE = 4
};

/* The one extended data type: standard error.  */
#define GF_EXTENDED_DATA_STDERR 1

#define GF_CHAN_DEFAULT_WINDOW (1024 * 1024)
/* The data in one CHANNEL_DATA message: the most a transport payload
   holds, less the message's 9 bytes of header.  */
#define GF_CHAN_MAX_PACKET 32759
#define GF_CHAN_DEFAULT_PACKET 32000

/* A channel the peer asks to open.  The strings are valid only during the
   callback.  Answer with gf_chans_open_accept or gf_chans_open_reject, now
   or later; until then the channel does not exist for the peer.  */
typedef struct gf_chan_open
{
  uint32_t id;			/* Our number for it.  */
  enum gf_chan_type type;
  /* direct-tcpip: where the peer wants us to connect (HOST, PORT) and
     where the connection comes from.  forwarded-tcpip: the address that
     was connected to on the peer, and the connection's origin.  */
  gf_slice host;
  uint16_t port;
  gf_slice orig_host;
  uint16_t orig_port;
  uint32_t window, max_packet;	/* The peer's.  */
} gf_chan_open;

enum gf_req_type
{
  GF_REQ_EXEC = 1,		/* command */
  GF_REQ_SHELL,
  GF_REQ_SUBSYSTEM,		/* command is the subsystem name */
  GF_REQ_PTY,			/* name (term), cols, rows, width, height, modes */
  GF_REQ_ENV,			/* name, value */
  GF_REQ_WINDOW_CHANGE,		/* cols, rows, width, height */
  GF_REQ_SIGNAL,		/* name, without "SIG" */
  GF_REQ_EXIT_STATUS,		/* status */
  GF_REQ_EXIT_SIGNAL,		/* name, core_dumped, message */
  GF_REQ_BREAK			/* ms */
};

typedef struct gf_chan_request
{
  uint32_t id;
  enum gf_req_type type;
  int want_reply;		/* Answer with gf_chans_reply.  */
  gf_slice command;
  gf_slice name, value;
  uint32_t cols, rows, width, height;
  gf_slice modes;
  uint32_t status;
  int core_dumped;
  gf_slice message;
  uint32_t ms;
} gf_chan_request;

enum gf_global_type
{
  GF_GLOBAL_TCPIP_FORWARD = 1,		/* addr, port */
  GF_GLOBAL_CANCEL_TCPIP_FORWARD,	/* addr, port */
  GF_GLOBAL_NO_MORE_SESSIONS		/* no-more-sessions@openssh.com */
};

typedef struct gf_global_request
{
  enum gf_global_type type;
  int want_reply;		/* Answer with gf_chans_global_reply.  */
  gf_slice addr;
  uint32_t port;
} gf_global_request;

typedef struct gf_chans_events
{
  void *user;
  /* Send a message (to gf_conn_send).  Required.  Return 0, or nonzero to
     fail the connection.  For a message of data it may return GF_ERR_AGAIN
     (from gf_conn_send): the message was not sent, and gf_chans_send_data
     reports it to its caller.  */
  int (*send) (void *user, const uint8_t *payload, size_t len);
  /* The peer asks to open a channel.  Required if the peer may.  */
  int (*open_request) (void *user, const gf_chan_open *open);
  /* A channel we asked to open is open (the peer's window and packet size
     are available through the accessors), or was refused.  */
  int (*open_confirmed) (void *user, uint32_t id);
  int (*open_failed) (void *user, uint32_t id, uint32_t reason, gf_slice text);
  /* Data from the peer.  Valid only during the call.  Call
     gf_chans_consumed when done with it (inside the call is fine).  With
     auto_window set the library does so when the callback returns 0.  */
  int (*data) (void *user, uint32_t id, const uint8_t *data, size_t len);
  int (*extended_data) (void *user, uint32_t id, uint32_t type,
                        const uint8_t *data, size_t len);
  /* The peer will send no more.  */
  int (*eof) (void *user, uint32_t id);
  /* The peer's window grew after a send was short: try again.  */
  int (*writable) (void *user, uint32_t id);
  /* A request on a channel.  Required if the peer may send any.  */
  int (*request) (void *user, const gf_chan_request *req);
  /* The answer to a request we sent with want_reply, in order.  */
  int (*request_reply) (void *user, uint32_t id, int success);
  /* A global request; the answer to one of ours.  */
  int (*global_request) (void *user, const gf_global_request *req);
  int (*global_reply) (void *user, int success, uint32_t port);
  /* The channel is closed on both sides and its number is free again.  */
  int (*closed) (void *user, uint32_t id);
  /* The connection must end, for REASON (an enum gf_disconnect value).
     Required.  */
  int (*disconnect) (void *user, uint32_t reason);
} gf_chans_events;

typedef struct gf_chans_config
{
  unsigned max_channels;	/* 0: 64.  */
  unsigned max_requests;	/* Unanswered requests per channel, and
				   global: 0: 16.  */
  int auto_window;		/* Consume data when the callback returns.  */
} gf_chans_config;

typedef struct gf_chans gf_chans;

int gf_chans_new (gf_chans **out, const gf_chans_config *config,
                  const gf_chans_events *events);
void gf_chans_free (gf_chans *m);

/* A message numbered 80 to 100.  Returns GF_OK, or an error after which
   the events' disconnect was called.  */
int gf_chans_input (gf_chans *m, const uint8_t *payload, size_t len);

/* ---- Opening ---- */

/* Ask the peer to open a channel.  WINDOW and MAX_PACKET are what we allow
   the peer to send (0 for the defaults).  The number comes back in *ID;
   open_confirmed or open_failed follows.  */
int gf_chans_open_session (gf_chans *m, uint32_t *id, uint32_t window,
                           uint32_t max_packet);
int gf_chans_open_direct_tcpip (gf_chans *m, uint32_t *id, const char *host,
                                uint16_t port, const char *orig_host,
                                uint16_t orig_port, uint32_t window,
                                uint32_t max_packet);
int gf_chans_open_forwarded_tcpip (gf_chans *m, uint32_t *id,
                                   const char *host, uint16_t port,
                                   const char *orig_host, uint16_t orig_port,
                                   uint32_t window, uint32_t max_packet);

/* Answer an open_request.  */
int gf_chans_open_accept (gf_chans *m, uint32_t id, uint32_t window,
                          uint32_t max_packet);
int gf_chans_open_reject (gf_chans *m, uint32_t id, uint32_t reason,
                          const char *text);

/* ---- Data ---- */

/* Send up to LEN bytes; returns how many were taken (possibly 0), or a
   negative status.  Offer everything you have rather than first checking
   gf_chans_writable: a result below LEN is what arms the writable event.
   GF_ERR_AGAIN means the transport could not take it now (a key exchange
   is full); try again after gf_chans_resume.  */
long gf_chans_send_data (gf_chans *m, uint32_t id, const uint8_t *data,
                         size_t len);
long gf_chans_send_extended (gf_chans *m, uint32_t id, uint32_t type,
                             const uint8_t *data, size_t len);
/* Tell the library N bytes of received data were dealt with, so that the
   peer may send that much more.  */
int gf_chans_consumed (gf_chans *m, uint32_t id, size_t n);
/* No more data from us.  */
int gf_chans_send_eof (gf_chans *m, uint32_t id);
/* Close.  The channel is gone when the peer has closed too.  */
int gf_chans_close (gf_chans *m, uint32_t id);

/* Call this from the transport's rekeyed event: every channel whose send
   was refused with GF_ERR_AGAIN, or cut short, while the transport held
   messages back gets its writable event, if the peer's window allows.  */
int gf_chans_resume (gf_chans *m);

/* How much the peer's window allows us to send now, and the largest
   message it accepts.  */
size_t gf_chans_writable (const gf_chans *m, uint32_t id);
uint32_t gf_chans_remote_max_packet (const gf_chans *m, uint32_t id);

/* ---- Requests ---- */

int gf_chans_request_exec (gf_chans *m, uint32_t id, const char *command,
                           int want_reply);
int gf_chans_request_shell (gf_chans *m, uint32_t id, int want_reply);
int gf_chans_request_subsystem (gf_chans *m, uint32_t id, const char *name,
                                int want_reply);
int gf_chans_request_pty (gf_chans *m, uint32_t id, const char *term,
                          uint32_t cols, uint32_t rows, uint32_t width,
                          uint32_t height, const uint8_t *modes,
                          size_t modes_len, int want_reply);
int gf_chans_request_env (gf_chans *m, uint32_t id, const char *name,
                          const char *value, int want_reply);
int gf_chans_request_window_change (gf_chans *m, uint32_t id, uint32_t cols,
                                    uint32_t rows, uint32_t width,
                                    uint32_t height);
int gf_chans_request_signal (gf_chans *m, uint32_t id, const char *name);
int gf_chans_request_exit_status (gf_chans *m, uint32_t id, uint32_t status);
int gf_chans_request_exit_signal (gf_chans *m, uint32_t id, const char *name,
                                  int core_dumped, const char *message);
/* Answer the oldest request on the channel that asked for a reply.  */
int gf_chans_reply (gf_chans *m, uint32_t id, int success);

/* ---- Global requests ---- */

int gf_chans_request_tcpip_forward (gf_chans *m, const char *addr,
                                    uint32_t port);
int gf_chans_request_cancel_tcpip_forward (gf_chans *m, const char *addr,
                                           uint32_t port);
int gf_chans_request_no_more_sessions (gf_chans *m);
/* Answer the oldest global request that asked for a reply.  PORT is the
   port bound, for a tcpip-forward of port 0.  */
int gf_chans_global_reply (gf_chans *m, int success, uint32_t port);

/* Number of channels open, opening or closing.  */
size_t gf_chans_count (const gf_chans *m);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_CHAN_H */
