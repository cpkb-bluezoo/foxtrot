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

/* The SSH transport layer (RFC 4253) as a state machine: identification
   exchange, algorithm negotiation, key exchange, key derivation, the
   binary packet protocol, rekeying, and the transport messages
   (DISCONNECT, IGNORE, UNIMPLEMENTED, DEBUG, SERVICE_REQUEST,
   SERVICE_ACCEPT, EXT_INFO).

   Like everything else here it does no I/O and never blocks.  The caller
   hands it the bytes it reads from its socket with gf_conn_receive, and
   the connection calls back with the bytes to write.  Time is a
   caller-supplied monotonic clock in MICROSECONDS, passed to every call
   that can need it, so the library behaves identically under a simulated
   clock.  gf_conn_timeout says when to call gf_conn_on_timeout next.  All
   callbacks are invoked synchronously from inside the call that caused
   them, and must not free the connection (call gf_conn_disconnect and
   free it afterwards).

   What it does for you:
     - sends our identification and KEXINIT as soon as gf_conn_start is
       called, and answers the peer's;
     - refuses anything the policy forbids, and requires strict key
       exchange (the Terrapin countermeasure; see kexinit.h);
     - verifies the server's host key signature and asks the application
       (the host_key callback) whether it trusts the key: a client has no
       default and must set the callback;
     - rekeys before the packet layer's limits and every hour or gigabyte
       (config below), whether we or the peer start it; application
       messages sent during a key exchange are held and sent after it;
     - answers a peer's DISCONNECT, and sends the right DISCONNECT when it
       finds a protocol violation.

   Layers above (authentication, channels) see only messages numbered
   50 and up, through the message callback, and send with gf_conn_send.
   After a fatal error or a disconnect every call but gf_conn_free returns
   GF_ERR_CLOSED.

   Threading: one connection is used from one thread at a time.  */

#ifndef FOXTROT_CONN_H
#define FOXTROT_CONN_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/key.h>
#include <foxtrot/kexinit.h>
#include <foxtrot/packet.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Transport message numbers (RFC 4250 section 4.1.2).  */
enum gf_msg
{
  GF_MSG_DISCONNECT = 1,
  GF_MSG_IGNORE = 2,
  GF_MSG_UNIMPLEMENTED = 3,
  GF_MSG_DEBUG = 4,
  GF_MSG_SERVICE_REQUEST = 5,
  GF_MSG_SERVICE_ACCEPT = 6,
  GF_MSG_EXT_INFO = 7,
  GF_MSG_NEWKEYS = 21,
  GF_MSG_KEX_ECDH_INIT = 30,	/* Also SSH_MSG_KEX_HYBRID_INIT.  */
  GF_MSG_KEX_ECDH_REPLY = 31	/* Also SSH_MSG_KEX_HYBRID_REPLY.  */
};

/* Disconnect reason codes (RFC 4253 section 11.1).  */
enum gf_disconnect
{
  GF_DISCONNECT_HOST_NOT_ALLOWED = 1,
  GF_DISCONNECT_PROTOCOL_ERROR = 2,
  GF_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
  GF_DISCONNECT_RESERVED = 4,
  GF_DISCONNECT_MAC_ERROR = 5,
  GF_DISCONNECT_COMPRESSION_ERROR = 6,
  GF_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
  GF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
  GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
  GF_DISCONNECT_CONNECTION_LOST = 10,
  GF_DISCONNECT_BY_APPLICATION = 11,
  GF_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
  GF_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
  GF_DISCONNECT_NO_MORE_AUTH_METHODS = 14,
  GF_DISCONNECT_ILLEGAL_USER_NAME = 15
};

/* What was negotiated, available once the connection is established and
   updated by each rekey.  The pointers are valid until the next rekey or
   until the connection is freed.  */
typedef struct gf_conn_info
{
  enum gf_kex kex;
  enum gf_sigalg hostkey_alg;
  enum gf_cipher cipher_c2s, cipher_s2c;
  /* H of the first key exchange: what user authentication signs.  */
  const uint8_t *session_id;
  size_t session_id_len;
  /* The peer's identification line without CR LF, and its software
     version and comments.  */
  gf_slice peer_ident;
  gf_slice peer_software;
  /* The server's host key: the one the client verified, or the one a
     server signed with.  */
  const gf_key *host_key;
  int ext_info;			/* The peer announced RFC 8308 support.  */
} gf_conn_info;

typedef struct gf_conn_events
{
  void *user;
  /* Bytes to write to the transport.  Required.  Return nonzero on
     failure, which fails the connection.  */
  int (*write) (void *user, const uint8_t *data, size_t len);
  /* Client: the server presented KEY, and it proved possession by
     signing the exchange hash.  Return 0 to trust it.  This is where
     known_hosts or a trust-on-first-use policy goes.  Required for a
     client: a connection with no callback refuses every host key.  */
  int (*host_key) (void *user, const gf_key *key);
  /* The first key exchange is complete; the keys are in use.  */
  int (*established) (void *user, const gf_conn_info *info);
  /* A rekey is complete.  Messages held back during it have been sent.  */
  int (*rekeyed) (void *user, const gf_conn_info *info);
  /* Server: the client asked for service NAME (always "ssh-userauth";
     any other is refused by the library).  Return nonzero to refuse.
     Optional; the library sends SERVICE_ACCEPT itself.  */
  int (*service_request) (void *user, gf_slice name);
  /* Client: the server accepted the service requested with
     gf_conn_request_service.  */
  int (*service_accepted) (void *user, gf_slice name);
  /* A message for the layers above (number 50 to 255).  PAYLOAD is valid
     only during the call.  Required.  Return nonzero to fail the
     connection.  */
  int (*message) (void *user, const uint8_t *payload, size_t len);
  /* An RFC 8308 extension from the peer, delivered one at a time from its
     SSH_MSG_EXT_INFO.  A client gets e.g. "server-sig-algs", the user key
     algorithms the server accepts.  */
  int (*extension) (void *user, gf_slice name, gf_slice value);
  /* SSH_MSG_DEBUG from the peer.  TEXT is peer-controlled and unchecked;
     sanitize it before showing it to anyone.  */
  void (*debug) (void *user, int always_display, gf_slice text);
  /* SSH_MSG_UNIMPLEMENTED: the peer did not understand our packet number
     SEQ.  */
  void (*unimplemented) (void *user, uint32_t seq);
  /* The connection ended.  ERROR is 0 for an orderly end (we or the peer
     disconnected BY_APPLICATION), otherwise a negative status.  REASON
     is the disconnect reason sent or received (0 if none); TEXT is the
     peer's description if it sent one, peer-controlled like debug.
     Called at most once.  */
  void (*closed) (void *user, int error, uint32_t reason, gf_slice text);
} gf_conn_events;

typedef struct gf_conn_config
{
  /* Algorithm preferences; NULL members mean the policy defaults.  A
     client that holds a known host key restricts sigalgs to that key's
     algorithms.  */
  struct gf_kex_prefs prefs;
  /* Our identification: "SSH-2.0-" SOFTWARE [SP COMMENTS].  NULL
     SOFTWARE means "foxtrot_VERSION".  */
  const char *software;
  const char *comments;
  /* Server only: the host keys.  The algorithms offered are those the
     keys can make (limited by prefs.sigalgs).  The keys must outlive
     the connection.  */
  gf_key *const *host_keys;
  size_t nhost_keys;
  /* Rekey after this much traffic in either direction (0: 1 GiB), this
     many packets (0: 2^28), or this long since the last key exchange
     (0: one hour).  The first is RFC 4253 section 9's advice.  */
  uint64_t rekey_bytes;
  uint64_t rekey_packets;
  uint64_t rekey_interval_us;
  /* A key exchange, the first or a rekey, must finish within this long of
     starting (0: 60 s).  */
  uint64_t kex_timeout_us;
} gf_conn_config;

typedef struct gf_conn gf_conn;

/* Create a client or server connection.  CONFIG and EVENTS are copied;
   keys and strings in CONFIG are not.  */
int gf_conn_client_new (gf_conn **out, const gf_conn_config *config,
                        const gf_conn_events *events);
int gf_conn_server_new (gf_conn **out, const gf_conn_config *config,
                        const gf_conn_events *events);
/* Free the connection and wipe its secrets.  Does not send anything.  */
void gf_conn_free (gf_conn *c);

/* Send our identification and KEXINIT.  Both ends call this once, as soon
   as the transport is connected.  */
int gf_conn_start (gf_conn *c, uint64_t now_us);

/* Feed bytes read from the transport.  All of them are consumed; a
   partial packet is held internally.  Returns GF_OK, or a negative status
   after which the connection is closed (a DISCONNECT has been sent if
   the protocol allowed it).  */
int gf_conn_receive (gf_conn *c, uint64_t now_us, const uint8_t *data,
                     size_t len);

/* The next time gf_conn_on_timeout is due, or UINT64_MAX for never.  */
uint64_t gf_conn_timeout (const gf_conn *c);
int gf_conn_on_timeout (gf_conn *c, uint64_t now_us);

/* Client: ask for the service NAME (after established).  */
int gf_conn_request_service (gf_conn *c, uint64_t now_us, const char *name);

/* Send a message of number 50 or more (PAYLOAD includes the number; at
   most GF_MAX_PAYLOAD bytes).  Allowed once established.  During a key
   exchange the message is held, up to a limit, after which GF_ERR_AGAIN
   is returned and the message is not queued: retry after the rekeyed
   event.  */
int gf_conn_send (gf_conn *c, uint64_t now_us, const uint8_t *payload,
                  size_t len);

/* Send SSH_MSG_IGNORE with DATA (traffic padding, keepalive).  */
int gf_conn_send_ignore (gf_conn *c, uint64_t now_us, const uint8_t *data,
                         size_t len);

/* Send SSH_MSG_DEBUG.  TEXT is UTF-8.  */
int gf_conn_send_debug (gf_conn *c, uint64_t now_us, int always_display,
                        const char *text);

/* Start a key exchange now (also happens by itself when due).  */
int gf_conn_rekey (gf_conn *c, uint64_t now_us);

/* Send DISCONNECT with REASON and DESCRIPTION (may be NULL) and close.  The
   caller then closes the transport.  */
int gf_conn_disconnect (gf_conn *c, uint64_t now_us, uint32_t reason,
                        const char *description);

int gf_conn_is_established (const gf_conn *c);
int gf_conn_is_closed (const gf_conn *c);
/* NULL before the first key exchange completes.  */
const gf_conn_info *gf_conn_get_info (const gf_conn *c);
/* Packets sent and received so far, for statistics.  */
uint32_t gf_conn_seq (const gf_conn *c, enum gf_dir dir);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_CONN_H */
