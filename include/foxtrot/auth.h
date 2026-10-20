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

/* User authentication (RFC 4252, RFC 4256), as client and server state
   machines.

   They sit on top of the transport (conn.h) but do not depend on it.  The
   application routes the messages numbered 50 to 79 that gf_conn delivers
   to gf_auth_server_input or gf_auth_client_input, and each machine sends
   its own through a send callback, normally gf_conn_send.  Time is a
   caller-supplied clock in microseconds, as everywhere.

   Methods:

     none                  only to learn the methods a server offers
     publickey             RFC 4252 section 7: the client first asks
                           whether a key would be accepted, then signs;
                           the signature covers the session identifier
     publickey-hostbound-v00@openssh.com
                           the same, with the server's host key in the
                           signed data, so that a signature made for one
                           server cannot be replayed to another by a
                           forwarding agent
     password              RFC 4252 section 8, without password change
     keyboard-interactive  RFC 4256

   Certificates (key.h): a client may present an OpenSSH user certificate
   in place of a plain key.  A server accepts one only if its config names
   the CAs it trusts (trusted_user_cas); without any, certificate
   signature algorithms are refused.  Before the application sees the
   request, the machine checks that a trusted CA signed it, that it is a
   user certificate good at the current time, that the user name is one of
   its principals, that its "source-address" (if any) allows the client's
   address, and that every critical option is one it understands, and the
   application is told what it must itself honour: the "force-command"
   option is in the request and is kept for gf_auth_server_force_command.
   Whether to accept the certificate (a revocation list, say, by serial or
   key id: gf_key_certificate_info) remains the application's decision.

   X.509 chains (RFC 6187, x509.h) are accepted the same way if the server's
   configuration has a trust store (x509_trust): the machine checks the chain
   against it for a user (id-kp-secureShellClient), at the current time, before the
   application sees the request, which is then marked x509 and left to the
   application to map to a user from the subject (gf_x509_subject,
   gf_x509_san).  Without a trust store no chain is accepted.

   Security keys (FIDO, key.h) are accepted as public keys: the machine
   verifies the token's signature, requires the user presence flag, and
   hands the application the flags and counter.  There is no client side:
   the library does not talk to tokens.

   Not implemented: hostbased (it trusts a client machine's identity on
   the word of its administrator and the DNS), and password change (a
   request to change the password is refused).  A signature algorithm
   is only ever one of policy.h: a client cannot sign, and a server
   will not accept, an ssh-rsa signature.

   The server's side is asynchronous.  A request is handed to the
   application, which decides now or later and answers with one of
   gf_auth_server_accept, _reject, _pk_ok or _kbdint_prompt.  Everything
   that can be checked without the application is checked first: the
   encoding, the algorithm against the key, the key against the policy, and
   the signature.  The application therefore only sees signed requests
   whose signature is valid, and only has to say whether it trusts the key
   for the user.

   Limits: a server ends the connection after max_failures failed
   attempts (default 6; a "none" request and a public key query are not
   attempts), and after a grace time (default 120 s) without success.  A
   client gives up after max_attempts requests.  */

#ifndef FOXTROT_AUTH_H
#define FOXTROT_AUTH_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/key.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gf_auth_msg
{
  GF_MSG_USERAUTH_REQUEST = 50,
  GF_MSG_USERAUTH_FAILURE = 51,
  GF_MSG_USERAUTH_SUCCESS = 52,
  GF_MSG_USERAUTH_BANNER = 53,
  GF_MSG_USERAUTH_PK_OK = 60,		/* Also INFO_REQUEST, PASSWD_CHANGEREQ.  */
  GF_MSG_USERAUTH_INFO_RESPONSE = 61
};

/* The service user authentication opens.  */
#define GF_SERVICE_CONNECTION "ssh-connection"

/* Methods, as bits: for what a server offers and a client may try.  */
enum gf_auth_method
{
  GF_AUTH_NONE = 1,
  GF_AUTH_PUBLICKEY = 2,
  GF_AUTH_PASSWORD = 4,
  GF_AUTH_KBDINT = 8
};

#define GF_AUTH_HOSTBOUND_METHOD "publickey-hostbound-v00@openssh.com"
#define GF_AUTH_HOSTBOUND_EXTENSION "publickey-hostbound@openssh.com"

/* The most prompts or responses of one keyboard-interactive round.  */
#define GF_AUTH_MAX_PROMPTS 32
/* The longest user name.  */
#define GF_AUTH_MAX_USER 255

/* ================================================================== */
/* Server                                                             */
/* ================================================================== */

typedef struct gf_auth_request
{
  enum gf_auth_method method;
  gf_slice user;
  gf_slice service;
  /* GF_AUTH_PUBLICKEY: the key, and the algorithm of the signature.  If
     HAS_SIGNATURE the signature is present and has been verified; the
     request is then the final one and the answer is accept or reject.
     Otherwise it asks whether the key would be accepted: answer
     gf_auth_server_pk_ok or gf_auth_server_reject.  */
  const gf_key *key;
  enum gf_sigalg sigalg;
  int has_signature;
  int hostbound;
  /* The key is a certificate that passed the checks above.  Its other
     properties are in gf_key_certificate_info (serial, key id).  */
  int certificate;
  /* The certificate's "force-command" (NUL-terminated), or an empty slice:
     the application must run this and nothing else for the session.  */
  gf_slice force_command;
  /* The key is an X.509 chain that the server's trust store vouches for as a
     user's.  Its subject is in gf_x509_subject and gf_x509_san.  */
  int x509;
  /* The certificate has "verify-required".  The machine enforces it for a
     security key (its signature must show that the token verified its
     user); for other keys, as in OpenSSH, it means nothing.  */
  int verify_required;
  /* A security key (key.h): the flags and counter the token signed, valid
     when HAS_SIGNATURE.  The user presence flag is set, or the machine would
     not have asked.  The application decides whether it wants more
     (GF_SK_USER_VERIFIED) and what to make of the counter, which only a
     server that remembers the last one can use.  */
  uint8_t sk_flags;
  uint32_t sk_counter;
  /* GF_AUTH_PASSWORD.  Valid only during the call: copy it if it is needed
     later, and wipe the copy.  */
  gf_slice password;
  /* GF_AUTH_KBDINT: the submethods the client asked for.  */
  gf_slice submethods;
} gf_auth_request;

typedef struct gf_auth_server_events
{
  void *user;
  /* Send a message (to gf_conn_send).  Required.  Nonzero fails.  */
  int (*send) (void *user, const uint8_t *payload, size_t len);
  /* A request to decide.  Required.  The request and what it points to are
     valid only during the call.  Answer inside it or later.  */
  int (*request) (void *user, const gf_auth_request *req);
  /* Keyboard-interactive: the client answered the prompts.  Valid only
     during the call.  Answer as for a request.  Required if the method is
     offered.  */
  int (*kbdint_response) (void *user, const gf_slice *responses, size_t n);
  /* Authentication succeeded for USER.  The service is ssh-connection.  */
  int (*authenticated) (void *user, gf_slice username);
  /* The wall clock in seconds since 1970, for the validity of
     certificates.  Optional: without it the machine reads time(2), which
     does no I/O.  */
  uint64_t (*unix_time) (void *user);
  /* The machine wants the connection ended, for REASON (an
     enum gf_disconnect value).  Required.  */
  int (*disconnect) (void *user, uint32_t reason);
} gf_auth_server_events;

typedef struct gf_auth_server_config
{
  unsigned methods;		/* Offered methods; 0: publickey.  */
  int hostbound;		/* Accept the host-bound public key method.  */
  unsigned max_failures;	/* 0: 6.  */
  uint64_t grace_us;		/* 0: 120 seconds.  */
  /* The CA keys whose user certificates are accepted, and the client's
     address in text (the "source-address" option is checked against it; a
     certificate with that option fails if it is NULL).  Neither is copied:
     they must outlive the machine.  */
  const gf_key *const *trusted_user_cas;
  size_t ntrusted_user_cas;
  const char *peer_address;
  /* The trust for X.509 chains as users' keys; not copied, and it must
     outlive the machine.  */
  const gf_x509_trust *x509_trust;
  /* Do not require the user name to be one of a certificate's principals:
     the application decides who the certificate is for (authkeys.h does,
     with "principals=", and with none, the user name).  The machine still
     checks the CA, the dates and the source address.  Set it only if
     the application does check: a certificate for someone else is
     otherwise accepted as the user's.  */
  int principals_by_application;
} gf_auth_server_config;

typedef struct gf_auth_server gf_auth_server;

int gf_auth_server_new (gf_auth_server **out,
                        const gf_auth_server_config *config,
                        const gf_auth_server_events *events);
void gf_auth_server_free (gf_auth_server *a);

/* Tell it the session identifier and our host key blob once the
   transport is established (gf_conn_info).  Starts the grace time.  */
int gf_auth_server_start (gf_auth_server *a, uint64_t now_us,
                          const uint8_t *session_id, size_t session_id_len,
                          const uint8_t *host_key_blob, size_t host_key_len);

/* A message numbered 50 to 79 from the client.  Returns GF_OK, or an error
   after which the machine has asked for the connection to be ended.  */
int gf_auth_server_input (gf_auth_server *a, uint64_t now_us,
                          const uint8_t *payload, size_t len);

/* Answers.  Each is valid once, after a request.  */
int gf_auth_server_accept (gf_auth_server *a, uint64_t now_us);
int gf_auth_server_reject (gf_auth_server *a, uint64_t now_us,
                           int partial_success);
int gf_auth_server_pk_ok (gf_auth_server *a, uint64_t now_us);
/* Ask the client NPROMPTS questions.  PROMPTS are NUL-terminated UTF-8;
   ECHO says which answers may be shown as typed.  */
int gf_auth_server_kbdint_prompt (gf_auth_server *a, uint64_t now_us,
                                  const char *name, const char *instruction,
                                  size_t nprompts, const char *const *prompts,
                                  const int *echo);

/* Send a banner (RFC 4252 section 5.4), UTF-8 and without control
   characters.  Allowed before success.  */
int gf_auth_server_banner (gf_auth_server *a, uint64_t now_us,
                           const char *text);

/* After the authenticated event for a user who presented a certificate:
   its force-command (NUL-terminated; *CMD is empty if it has none).  The
   command is valid until the machine is freed.  */
int gf_auth_server_force_command (const gf_auth_server *a, gf_slice *cmd);

/* After the authenticated event: does the user's certificate permit
   PERMISSION, one of the extensions of key.h ("permit-pty" and the like)?
   1 if the user did not authenticate with a certificate, since there is then
   nothing that restricts them, and for any other key type.  */
int gf_auth_server_permits (const gf_auth_server *a, const char *permission);

uint64_t gf_auth_server_timeout (const gf_auth_server *a);
int gf_auth_server_on_timeout (gf_auth_server *a, uint64_t now_us);
int gf_auth_server_is_done (const gf_auth_server *a);

/* ================================================================== */
/* Client                                                             */
/* ================================================================== */

typedef struct gf_auth_client_events
{
  void *user;
  int (*send) (void *user, const uint8_t *payload, size_t len);
  /* A banner from the server.  The text is the server's and may contain
     terminal control sequences: sanitize it.  Optional.  */
  void (*banner) (void *user, gf_slice text);
  /* Keyboard-interactive prompts.  Answer with gf_auth_client_kbdint_respond
     inside the call or later.  If this is NULL the method is not tried.
     PROMPTS and the text are valid only during the call.  */
  int (*kbdint) (void *user, gf_slice name, gf_slice instruction,
                 size_t nprompts, const gf_slice *prompts, const int *echo);
  /* Sign DATA with KEY, which has no private part here, under ALG: the key
     lives in an agent, a security token, a smart card or a remote service.
     Required for such a key.  Return 0 to take the job, and answer with
     gf_auth_client_sign_respond or gf_auth_client_sign_fail, inside the call
     or later; DATA is valid only until you answer.  Return nonzero to say
     you cannot, and the key is skipped.  The signature is the whole blob
     (string algorithm name, then the signature, and for a security key the
     flags and counter after it), as gf_key_sign makes it; for a certificate
     the name inside is its key's.  The machine checks the answer against KEY
     before it sends it, so a wrong or untouched-token answer only costs the
     key.  Signing may take as long as a person does; the server's grace
     time is running meanwhile.  */
  int (*sign) (void *user, const gf_key *key, enum gf_sigalg alg,
               gf_slice data);
  /* Authentication succeeded.  */
  int (*authenticated) (void *user);
  /* Nothing is left to try, or max_attempts is used up.  Required.  The
     application normally disconnects.  */
  int (*failed) (void *user);
} gf_auth_client_events;

typedef struct gf_auth_client_config
{
  const char *user;		/* Required, UTF-8.  */
  /* The keys to offer, in order.  Each must have a private part, or the
     events must have a sign function to do without one.  */
  const gf_key *const *keys;
  size_t nkeys;
  /* The password, or NULL.  It must stay valid while authenticating; wipe
     it afterwards.  */
  const char *password;
  /* Methods to try; 0: public key, then keyboard-interactive if the event
     is set, then password.  */
  unsigned methods;
  unsigned max_attempts;	/* 0: 6.  */
} gf_auth_client_config;

typedef struct gf_auth_client gf_auth_client;

int gf_auth_client_new (gf_auth_client **out,
                        const gf_auth_client_config *config,
                        const gf_auth_client_events *events);
void gf_auth_client_free (gf_auth_client *a);

/* The server's extensions (RFC 8308), from the transport's extension
   event: "server-sig-algs" limits the RSA hash the client uses, and
   "publickey-hostbound@openssh.com" switches to the host-bound method.
   Others are ignored.  Call before start.  */
int gf_auth_client_extension (gf_auth_client *a, gf_slice name, gf_slice value);

/* Begin: the session identifier and the host key blob of the connection
   (gf_conn_info), and send the first request.  Call once the service
   request was accepted.  */
int gf_auth_client_start (gf_auth_client *a, uint64_t now_us,
                          const uint8_t *session_id, size_t session_id_len,
                          const uint8_t *host_key_blob, size_t host_key_len);

int gf_auth_client_input (gf_auth_client *a, uint64_t now_us,
                          const uint8_t *payload, size_t len);

/* Answer keyboard-interactive prompts: one response per prompt.  */
int gf_auth_client_kbdint_respond (gf_auth_client *a, uint64_t now_us,
                                   size_t n, const char *const *responses);

/* Answer the sign event: the signature blob, or that there is none.
   GF_ERR_STATE if nothing was asked.  A signature that does not verify as
   KEY's for the data (or whose token was not touched) skips the key as a
   failure would.  */
int gf_auth_client_sign_respond (gf_auth_client *a, uint64_t now_us,
                                 const uint8_t *sig, size_t len);
int gf_auth_client_sign_fail (gf_auth_client *a, uint64_t now_us);

int gf_auth_client_is_done (const gf_auth_client *a);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_AUTH_H */
