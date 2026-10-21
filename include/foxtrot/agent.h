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

/* The messages of the ssh-agent protocol (draft-ietf-sshm-ssh-agent,
   formerly draft-miller-ssh-agent), for a client.

   A client can keep its private keys in an agent: auth.h hands the
   application the key, the algorithm and the bytes to sign (the sign event,
   and gf_auth_client_sign_respond or gf_session_auth_sign_respond to
   answer).  This is the agent's side of that: the framing, the requests a
   client needs and the replies it reads.  It does no I/O.  The application
   owns the socket (usually a Unix socket named by SSH_AUTH_SOCK), writes the
   bytes these functions make and gives what it reads to the reader.

   A client asks for two things:

     - the identities the agent holds: gf_agent_request_identities, and
       gf_agent_identities on the answer;
     - a signature by one of them: gf_agent_sign_request, and
       gf_agent_sign_response on the answer, whose signature blob goes
       straight to the sign event's answer.

   and, for an agent that holds keys restricted to certain destinations
   (ssh-add -h), tells it which server it is talking to first:
   gf_agent_session_bind.  There is deliberately nothing here to add,
   remove, lock or unlock keys, and nothing for agent forwarding (chan.h
   refuses it) or for an agent server.

   Framing.  A frame is a uint32 length and that many bytes, the first of
   which is the message type.  The reader is a push parser (HACKING): it
   reassembles frames from chunks of any size, checks a length as soon as
   its four bytes are in and before anything it announces is buffered, and
   fails on a length of zero or over GF_AGENT_MAX_FRAME, which is also
   OpenSSH's limit.  A frame that arrives whole in one chunk is delivered as a
   slice of that chunk and copied nowhere.

   Every parser here is all or nothing: a message is checked from end to end
   before any callback runs, and one with bytes left over after its last
   field, a length that runs past the end or a count larger than the bytes
   could hold is GF_ERR_ENCODING.  Everything an agent sends is the peer's,
   and a hostile one can send anything.

   Keys.  A client does not take an agent's word for what a key is:
   identities go through gf_key_from_blob, so the key policy (key.h) stays
   in one place, and what it refuses is skipped and counted.  A signature
   comes back as the same blob gf_key_sign makes (string algorithm name,
   string signature; for a security key held by the agent, the flags and
   counter after that), which the sign event's answer checks against the
   public key before anything is sent to the server.

   The RSA signature flags (the draft's SSH_AGENT_RSA_SHA2_256 and
   SSH_AGENT_RSA_SHA2_512: GF_AGENT_RSA_SHA2_256 and _512 here) are derived
   from the algorithm, and the SHA-1 flag (1) is never sent: an agent asked
   for neither would sign with SHA-1.  */

#ifndef FOXTROT_AGENT_H
#define FOXTROT_AGENT_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/key.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The longest frame (the type and its contents, not the length field)
   that is read or written.  */
#define GF_AGENT_MAX_FRAME (256u * 1024)

/* Signature flags of SIGN_REQUEST.  There is none for SHA-1, which is
   never asked for.  */
#define GF_AGENT_RSA_SHA2_256 2u
#define GF_AGENT_RSA_SHA2_512 4u

/* Bytes that a SIGN_REQUEST frame has besides the key blob and the data
   (length, type, two string lengths, flags), and that a session-bind frame
   has besides the host key, the session identifier and the signature (length,
   type, four string lengths, the extension's name and the forwarding flag).
   CAP of the functions below needs to be at least the sum.  */
#define GF_AGENT_SIGN_OVERHEAD 17
#define GF_AGENT_BIND_OVERHEAD 46

enum gf_agent_type
{
  GF_AGENT_UNKNOWN = 0,		/* Anything else.  */
  GF_AGENT_FAILURE = 5,
  GF_AGENT_SUCCESS = 6,
  GF_AGENT_REQUEST_IDENTITIES = 11,
  GF_AGENT_IDENTITIES_ANSWER = 12,
  GF_AGENT_SIGN_REQUEST = 13,
  GF_AGENT_SIGN_RESPONSE = 14,
  GF_AGENT_EXTENSION = 27,
  GF_AGENT_EXTENSION_FAILURE = 28
};

/* ---- Framing ---- */

typedef struct gf_agent_reader gf_agent_reader;

int gf_agent_reader_new (gf_agent_reader **out);
void gf_agent_reader_free (gf_agent_reader *r);

/* One frame: PAYLOAD is the message, its type byte first, and is valid only
   during the call.  Return 0 to continue, nonzero to stop.  Do not call
   gf_agent_reader_feed on the same reader from the callback.  */
typedef int (*gf_agent_frame_cb) (void *user, const uint8_t *payload,
                                  size_t len);

/* Give the reader the next LEN bytes the socket delivered (any number, in
   any chunks), and call FRAME_CB for each frame completed by them, in
   order.  All of DATA is consumed.  Returns:

     GF_OK           every frame in DATA was delivered; the reader may be
                     in the middle of the next (see gf_agent_reader_idle)
     GF_ERR_ENCODING a length of zero
     GF_ERR_RANGE    a length over GF_AGENT_MAX_FRAME
     GF_ERR_NOMEM    no room to hold a partial frame
     GF_ERR_HANDLER  FRAME_CB returned nonzero
     GF_ERR_STATE    the reader has failed before

   After any error the reader is failed for good: the stream cannot be
   resynchronised, and the connection to the agent should be closed.  */
int gf_agent_reader_feed (gf_agent_reader *r, const uint8_t *data, size_t len,
                          gf_agent_frame_cb frame_cb, void *user);

/* 1 if the reader is between frames, 0 if it holds part of one.  The
   socket ending while it does not is a truncated reply.  */
int gf_agent_reader_idle (const gf_agent_reader *r);

/* ---- Requests ----

   Each writes a whole frame, length field included, to OUT (CAP bytes), and
   sets *LEN to its size.  GF_ERR_BUFSIZE if CAP is too small, and then
   nothing useful is in OUT.  */

int gf_agent_request_identities (uint8_t *out, size_t cap, size_t *len);

/* Ask the agent to sign DATA (DATALEN bytes) with KEY under ALG.  The key
   is named by its blob (gf_key_blob: the certificate for a certificate), so
   KEY needs no private part; ALG must belong to it (gf_key_sigalgs, or the
   certificate algorithm for a certificate, or a security key's).  The flags
   are derived from ALG: rsa-sha2-256 and rsa-sha2-512 and their certificate
   forms give GF_AGENT_RSA_SHA2_256 and _512, the others 0.

   GF_ERR_UNSUPPORTED for an ALG that is none of those or that policy.h
   refuses (there is no SHA-1 algorithm here; 0 is not one), that is X.509 (an
   agent does not hold those) or that does not belong to KEY.  GF_ERR_RANGE
   if the frame would be over GF_AGENT_MAX_FRAME.  */
int gf_agent_sign_request (const gf_key *key, enum gf_sigalg alg,
                           const uint8_t *data, size_t datalen, uint8_t *out,
                           size_t cap, size_t *len);

/* ---- session-bind@openssh.com ----

   An agent that holds a key with destination constraints (ssh-add -h)
   signs for it only for a session it has been told about, and checks that
   the host key it is told about is the one that signed the session
   identifier.  Send this once the host key is trusted and before asking for
   a signature, with the host key (gf_conn_info.host_key), the session
   identifier and the signature the server made over it in the first key
   exchange (gf_conn_info.host_sig).  It is made with the forwarding flag
   clear: this library does not forward agents.

   An agent that does not know the extension answers FAILURE or
   EXTENSION_FAILURE, which ssh ignores; one that does answers SUCCESS, or
   FAILURE if the signature is not the host key's over the session
   identifier.  GF_ERR_INVAL for an empty session identifier or signature.  */
int gf_agent_session_bind (const gf_key *hostkey, gf_slice session_id,
                           gf_slice signature, uint8_t *out, size_t cap,
                           size_t *len);

/* ---- Replies ----

   These read a frame's payload, as the reader delivers it.  */

/* The type of a message, or GF_AGENT_UNKNOWN for one that is none of the
   above, one that is empty, and one of the types that carry nothing
   (FAILURE, SUCCESS, REQUEST_IDENTITIES, EXTENSION_FAILURE) with anything
   after the type byte.  The contents of the others are for their own
   parsers to check.  */
enum gf_agent_type gf_agent_type (const uint8_t *payload, size_t len);

/* One identity of an IDENTITIES_ANSWER: KEY is valid only during the call
   (to keep it, make one with gf_key_from_blob of its gf_key_blob).  COMMENT
   is the agent's text, usually the file the key came from, and is
   peer-controlled: it may be anything, with terminal control sequences
   among it, and is not NUL-free or UTF-8; sanitise it before showing it to
   anyone.  Return 0 to continue, nonzero to stop.  */
typedef int (*gf_agent_identity_cb) (void *user, const gf_key *key,
                                     gf_slice comment);

/* Read an IDENTITIES_ANSWER and call IDENTITY_CB for each identity whose
   key gf_key_from_blob accepts, in the agent's order.  Those it refuses
   (DSA, ECDSA over P-521, RSA under GF_MIN_RSA_BITS, a certificate with a
   bad CA signature, a blob that is malformed) are skipped and counted in
   *SKIPPED (which may be NULL).  GF_ERR_ENCODING for a message that is
   malformed (then nothing is called), GF_ERR_PROTOCOL if it is another
   type, GF_ERR_NOMEM, GF_ERR_HANDLER if the callback stopped.  */
int gf_agent_identities (const uint8_t *payload, size_t len,
                         gf_agent_identity_cb identity_cb, void *user,
                         size_t *skipped);

/* Read a SIGN_RESPONSE.  *SIG is the signature blob, a slice of PAYLOAD,
   for gf_auth_client_sign_respond or gf_session_auth_sign_respond, which
   check it against the public key.  GF_ERR_ENCODING if the message is
   malformed, GF_ERR_PROTOCOL if it is another type (a FAILURE is the agent
   refusing: use gf_agent_type to tell).  */
int gf_agent_sign_response (const uint8_t *payload, size_t len, gf_slice *sig);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_AGENT_H */
