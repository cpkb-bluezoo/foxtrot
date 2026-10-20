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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/conn.h>
#include <foxtrot/auth.h>
#include <foxtrot/kex.h>

#define GF_KEX_MAX_HASH_AUTH GF_KEX_MAX_HASH

#define DEFAULT_MAX_FAILURES 6
#define DEFAULT_GRACE_US (UINT64_C (120) * 1000000)
#define MAX_SIGNED 36000

static const struct
{
  unsigned bit;
  const char *name;
} method_names[] = {
  { GF_AUTH_PUBLICKEY, "publickey" },
  { GF_AUTH_PASSWORD, "password" },
  { GF_AUTH_KBDINT, "keyboard-interactive" }
};

/* The "authentications that can continue" list for MASK.  */
static size_t
methods_list (unsigned mask, char *out, size_t cap)
{
  size_t i, n = 0;

  out[0] = '\0';
  for (i = 0; i < sizeof method_names / sizeof method_names[0]; i++)
    if (mask & method_names[i].bit)
      {
        size_t l = strlen (method_names[i].name);

        if (n + l + 2 > cap)
          break;
        if (n)
          out[n++] = ',';
        memcpy (out + n, method_names[i].name, l);
        n += l;
        out[n] = '\0';
      }
  return n;
}

static unsigned
methods_mask (gf_slice list)
{
  unsigned m = 0;
  size_t i;

  for (i = 0; i < sizeof method_names / sizeof method_names[0]; i++)
    if (gf_namelist_contains (list, method_names[i].name))
      m |= method_names[i].bit;
  return m;
}

/* The data a public key signature covers (RFC 4252 section 7), with the
   server's host key appended for the host-bound method.  */
static int
signed_data (uint8_t **out, size_t *outlen, const uint8_t *sid, size_t sidlen,
             gf_slice user, const char *method, const char *alg,
             const uint8_t *blob, size_t bloblen, const uint8_t *host,
             size_t hostlen)
{
  size_t cap = 64 + sidlen + user.len + strlen (GF_SERVICE_CONNECTION)
    + strlen (method) + strlen (alg) + bloblen + hostlen;
  uint8_t *buf;
  gf_writer w;

  if (cap > MAX_SIGNED)
    return GF_ERR_RANGE;
  buf = malloc (cap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, cap);
  gf_wr_string (&w, sid, sidlen);
  gf_wr_u8 (&w, GF_MSG_USERAUTH_REQUEST);
  gf_wr_string (&w, user.data, user.len);
  gf_wr_cstring (&w, GF_SERVICE_CONNECTION);
  gf_wr_cstring (&w, method);
  gf_wr_bool (&w, 1);
  gf_wr_cstring (&w, alg);
  gf_wr_string (&w, blob, bloblen);
  if (host != NULL)
    gf_wr_string (&w, host, hostlen);
  if (gf_wr_status (&w) != GF_OK)
    {
      free (buf);
      return GF_ERR_BUFSIZE;
    }
  *out = buf;
  *outlen = w.len;
  return GF_OK;
}

static uint8_t *
dup_bytes (const uint8_t *p, size_t n)
{
  uint8_t *c = malloc (n ? n : 1);

  if (c != NULL && n)
    memcpy (c, p, n);
  return c;
}

/* ================================================================== */
/* Server                                                             */
/* ================================================================== */

enum pending
{
  P_NONE,
  P_REQUEST,			/* The application owes an answer.  */
  P_KBD				/* The client owes responses.  */
};

struct gf_auth_server
{
  gf_auth_server_config cfg;
  gf_auth_server_events ev;
  unsigned methods;
  int started, done;
  uint64_t deadline;
  uint8_t sid[GF_KEX_MAX_HASH_AUTH];
  size_t sidlen;
  uint8_t *host;
  size_t hostlen;
  uint8_t *user;		/* The user of the first request.  */
  size_t userlen;
  unsigned failures;
  enum pending pending;
  enum gf_auth_method pending_method;
  int pending_probe;		/* A public key query: not an attempt.  */
  gf_key *cert_key;		/* The certificate of this request, if any.  */
  uint8_t *force;		/* The certificate's force-command, if any.  */
  size_t forcelen;
  uint8_t *pk_blob;		/* For PK_OK.  */
  size_t pk_bloblen;
  enum gf_sigalg pk_alg;
  size_t kbd_prompts;
};

int
gf_auth_server_new (gf_auth_server **out, const gf_auth_server_config *config,
                    const gf_auth_server_events *events)
{
  gf_auth_server *a;
  size_t i;

  if (out == NULL || config == NULL || events == NULL || events->send == NULL
      || events->request == NULL || events->disconnect == NULL)
    return GF_ERR_INVAL;
  a = calloc (1, sizeof *a);
  if (a == NULL)
    return GF_ERR_NOMEM;
  a->cfg = *config;
  a->ev = *events;
  a->methods = config->methods ? config->methods : GF_AUTH_PUBLICKEY;
  a->methods &= GF_AUTH_PUBLICKEY | GF_AUTH_PASSWORD | GF_AUTH_KBDINT;
  if ((a->methods & GF_AUTH_KBDINT) && events->kbdint_response == NULL)
    {
      free (a);
      return GF_ERR_INVAL;
    }
  for (i = 0; i < config->ntrusted_user_cas; i++)
    if (config->trusted_user_cas == NULL || config->trusted_user_cas[i] == NULL
        || gf_key_is_certificate (config->trusted_user_cas[i]))
      {
        free (a);
        return GF_ERR_INVAL;
      }
  *out = a;
  return GF_OK;
}

void
gf_auth_server_free (gf_auth_server *a)
{
  if (a == NULL)
    return;
  free (a->host);
  free (a->user);
  free (a->pk_blob);
  free (a->force);
  gf_key_free (a->cert_key);
  gf_wipe (a, sizeof *a);
  free (a);
}

int
gf_auth_server_start (gf_auth_server *a, uint64_t now_us,
                      const uint8_t *sid, size_t sidlen, const uint8_t *host,
                      size_t hostlen)
{
  if (a == NULL || sid == NULL || host == NULL || sidlen == 0
      || sidlen > sizeof a->sid)
    return GF_ERR_INVAL;
  if (a->started)
    return GF_ERR_STATE;
  a->host = dup_bytes (host, hostlen);
  if (a->host == NULL)
    return GF_ERR_NOMEM;
  a->hostlen = hostlen;
  memcpy (a->sid, sid, sidlen);
  a->sidlen = sidlen;
  a->started = 1;
  a->deadline = now_us + (a->cfg.grace_us ? a->cfg.grace_us
                          : DEFAULT_GRACE_US);
  return GF_OK;
}

static int
srv_send (gf_auth_server *a, const uint8_t *p, size_t n)
{
  return a->ev.send (a->ev.user, p, n) ? GF_ERR_HANDLER : GF_OK;
}

/* Ask for the connection to end and report the error.  */
static int
srv_die (gf_auth_server *a, uint32_t reason, int status)
{
  a->done = 1;
  a->pending = P_NONE;
  a->ev.disconnect (a->ev.user, reason);
  return status;
}

static int
srv_failure (gf_auth_server *a, int partial)
{
  uint8_t buf[128];
  char list[96];
  gf_writer w;

  methods_list (a->methods, list, sizeof list);
  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u8 (&w, GF_MSG_USERAUTH_FAILURE);
  gf_wr_namelist (&w, list);
  gf_wr_bool (&w, partial);
  return srv_send (a, buf, w.len);
}

/* A failed attempt: counted, and the end of the connection when there
   have been too many.  */
static int
srv_attempt_failed (gf_auth_server *a, int counted)
{
  unsigned max = a->cfg.max_failures ? a->cfg.max_failures
                                     : DEFAULT_MAX_FAILURES;

  a->pending = P_NONE;
  if (counted && ++a->failures >= max)
    return srv_die (a, GF_DISCONNECT_NO_MORE_AUTH_METHODS, GF_ERR_AUTH);
  return srv_failure (a, 0);
}

static int
srv_request_app (gf_auth_server *a, gf_auth_request *req)
{
  int r;

  a->pending = P_REQUEST;
  a->pending_method = req->method;
  a->pending_probe = req->method == GF_AUTH_PUBLICKEY && !req->has_signature;
  r = a->ev.request (a->ev.user, req);
  /* An application that answered with a failure has already ended things,
     if that was the end.  */
  return r && !a->done
    ? srv_die (a, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER) : GF_OK;
}

/* The wall clock, for the validity of certificates: the application's, or
   time(2).  */
static uint64_t
now_unix (const gf_auth_server *a)
{
  time_t t;

  if (a->ev.unix_time)
    return a->ev.unix_time (a->ev.user);
  t = time (NULL);
  return t < 0 ? 0 : (uint64_t) t;
}

/* Is KEY, a certificate, one this server takes for USER?  Everything but
   the application's own policy.  Sets the request's certificate fields.  */
static int
srv_certificate (gf_auth_server *a, const gf_key *key, gf_auth_request *req)
{
  gf_cert_info ci;
  size_t i;
  int trusted = 0, found;
  uint64_t now = now_unix (a);
  gf_slice v;

  if (gf_key_certificate_info (key, &ci) != GF_OK)
    return 0;
  for (i = 0; i < a->cfg.ntrusted_user_cas; i++)
    if (gf_key_equal (ci.ca, a->cfg.trusted_user_cas[i]))
      trusted = 1;
  if (!trusted || gf_cert_check (key, GF_CERT_USER, now, NULL) != GF_OK
      || !gf_cert_has_principal (key, (const char *) req->user.data,
                                 req->user.len, 0)
      || !gf_cert_source_address_ok (key, a->cfg.peer_address))
    return 0;
  req->certificate = 1;
  found = gf_cert_critical_option (key, "force-command", &v);
  if (found == 1)
    {
      free (a->force);
      a->force = malloc (v.len + 1);
      if (a->force == NULL)
        return 0;
      memcpy (a->force, v.data, v.len);
      a->force[v.len] = '\0';
      a->forcelen = v.len;
      req->force_command.data = a->force;
      req->force_command.len = v.len;
    }
  req->verify_required =
    gf_cert_critical_option (key, "verify-required", &v) == 1;
  return 1;
}

static int
srv_publickey (gf_auth_server *a, gf_reader *rd, gf_auth_request *req,
               int hostbound)
{
  gf_slice algname, blob, host = { NULL, 0 }, sig = { NULL, 0 };
  int has_sig;
  enum gf_sigalg alg;
  gf_key *key = NULL;
  int r, counted;

  if (gf_rd_bool (rd, &has_sig) != GF_OK
      || gf_rd_text (rd, &algname) != GF_OK
      || gf_rd_string (rd, &blob) != GF_OK
      || (hostbound && gf_rd_string (rd, &host) != GF_OK)
      || (has_sig && gf_rd_string (rd, &sig) != GF_OK)
      || gf_rd_finish (rd) != GF_OK)
    return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
  counted = has_sig;
  alg = gf_sigalg_from_name ((const char *) algname.data, algname.len);
  if (alg == 0 || gf_key_from_blob (&key, blob.data, blob.len) != GF_OK
      || !gf_sigalg_matches_key_type (alg, gf_key_type_name (key),
                                      strlen (gf_key_type_name (key)))
      || (hostbound && (host.len != a->hostlen
                        || !gf_ct_equal (host.data, a->host, a->hostlen))))
    {
      gf_key_free (key);
      return srv_attempt_failed (a, counted);
    }
  if (gf_key_is_certificate (key) && !srv_certificate (a, key, req))
    {
      gf_key_free (key);
      return srv_attempt_failed (a, counted);
    }
  if (gf_x509_chain_length (key) > 0)
    {
      /* A chain is only as good as the trust that vouches for it; with none
         configured it is a stranger's claim.  */
      if (a->cfg.x509_trust == NULL
          || gf_x509_verify (a->cfg.x509_trust, key, GF_X509_CLIENT, NULL,
                             now_unix (a), NULL) != GF_OK)
        {
          gf_key_free (key);
          return srv_attempt_failed (a, counted);
        }
      req->x509 = 1;
    }
  if (has_sig)
    {
      uint8_t *data;
      size_t dl;

      r = signed_data (&data, &dl, a->sid, a->sidlen, req->user,
                       hostbound ? GF_AUTH_HOSTBOUND_METHOD : "publickey",
                       gf_sigalg_name (alg), blob.data, blob.len,
                       hostbound ? a->host : NULL, a->hostlen);
      if (r == GF_OK)
        {
          if (gf_sigalg_is_user_only (alg))
            {
              /* A security key: the token vouches for a person only if it
                 was touched (checked), and for more if it checked a PIN or
                 a fingerprint, which a certificate may demand.  */
              r = gf_key_verify_sk (key, alg, data, dl, sig.data, sig.len,
                                    &req->sk_flags, &req->sk_counter);
              if (r == GF_OK && req->verify_required
                  && !(req->sk_flags & GF_SK_USER_VERIFIED))
                r = GF_ERR_HOSTKEY;
            }
          else
            r = gf_key_verify (key, alg, data, dl, sig.data, sig.len);
          free (data);
        }
      if (r != GF_OK)
        {
          gf_key_free (key);
          return srv_attempt_failed (a, 1);
        }
    }
  free (a->pk_blob);
  a->pk_blob = dup_bytes (blob.data, blob.len);
  a->pk_bloblen = blob.len;
  a->pk_alg = alg;
  if (a->pk_blob == NULL)
    {
      gf_key_free (key);
      return GF_ERR_NOMEM;
    }
  req->method = GF_AUTH_PUBLICKEY;
  req->key = key;
  req->sigalg = alg;
  req->has_signature = has_sig;
  req->hostbound = hostbound;
  /* A certificate is kept for as long as the request may be answered, so
     that what it permits can be asked of the machine afterwards.  */
  if (req->certificate)
    a->cert_key = key;
  r = srv_request_app (a, req);
  if (!req->certificate)
    gf_key_free (key);
  return r;
}

static int
srv_handle_request (gf_auth_server *a, const uint8_t *p, size_t n)
{
  gf_reader rd;
  gf_auth_request req;
  gf_slice user, service, method;

  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_utf8 (&rd, &user) != GF_OK || gf_rd_utf8 (&rd, &service) != GF_OK
      || gf_rd_text (&rd, &method) != GF_OK)
    return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
  if (a->pending == P_REQUEST)
    return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
  a->pending = P_NONE;
  if (!gf_slice_equals (service, GF_SERVICE_CONNECTION))
    return srv_die (a, GF_DISCONNECT_SERVICE_NOT_AVAILABLE, GF_ERR_UNSUPPORTED);
  if (user.len > GF_AUTH_MAX_USER)
    return srv_die (a, GF_DISCONNECT_ILLEGAL_USER_NAME, GF_ERR_PROTOCOL);
  if (a->user == NULL)
    {
      a->user = dup_bytes (user.data, user.len);
      if (a->user == NULL)
        return GF_ERR_NOMEM;
      a->userlen = user.len;
    }
  else if (a->userlen != user.len || memcmp (a->user, user.data, user.len))
    return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);

  memset (&req, 0, sizeof req);
  req.user = user;
  req.service = service;
  free (a->force);		/* A command belongs to the last request.  */
  a->force = NULL;
  a->forcelen = 0;
  gf_key_free (a->cert_key);	/* And so does a certificate.  */
  a->cert_key = NULL;
  if (user.len == 0)
    return srv_attempt_failed (a, 1);

  if (gf_slice_equals (method, "none"))
    return srv_attempt_failed (a, 0);
  if (gf_slice_equals (method, "publickey") && (a->methods & GF_AUTH_PUBLICKEY))
    return srv_publickey (a, &rd, &req, 0);
  if (gf_slice_equals (method, GF_AUTH_HOSTBOUND_METHOD)
      && (a->methods & GF_AUTH_PUBLICKEY) && a->cfg.hostbound)
    return srv_publickey (a, &rd, &req, 1);
  if (gf_slice_equals (method, "password") && (a->methods & GF_AUTH_PASSWORD))
    {
      int change;
      gf_slice pw, newpw;

      if (gf_rd_bool (&rd, &change) != GF_OK || gf_rd_string (&rd, &pw) != GF_OK
          || (change && gf_rd_string (&rd, &newpw) != GF_OK)
          || gf_rd_finish (&rd) != GF_OK)
        return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
      if (change)		/* Password change is not supported.  */
        return srv_attempt_failed (a, 1);
      req.method = GF_AUTH_PASSWORD;
      req.password = pw;
      return srv_request_app (a, &req);
    }
  if (gf_slice_equals (method, "keyboard-interactive")
      && (a->methods & GF_AUTH_KBDINT))
    {
      gf_slice lang, sub;

      if (gf_rd_string (&rd, &lang) != GF_OK || gf_rd_string (&rd, &sub) != GF_OK
          || gf_rd_finish (&rd) != GF_OK)
        return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
      req.method = GF_AUTH_KBDINT;
      req.submethods = sub;
      return srv_request_app (a, &req);
    }
  /* A method we do not offer or do not know.  */
  return srv_attempt_failed (a, 1);
}

static int
srv_handle_info_response (gf_auth_server *a, const uint8_t *p, size_t n)
{
  gf_reader rd;
  uint32_t count, i;
  gf_slice resp[GF_AUTH_MAX_PROMPTS];
  int r;

  if (a->pending != P_KBD)
    return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_u32 (&rd, &count) != GF_OK || count != a->kbd_prompts)
    return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
  for (i = 0; i < count; i++)
    if (gf_rd_string (&rd, &resp[i]) != GF_OK)
      return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
  if (gf_rd_finish (&rd) != GF_OK)
    return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_ENCODING);
  a->pending = P_REQUEST;
  a->pending_method = GF_AUTH_KBDINT;
  a->pending_probe = 0;
  r = a->ev.kbdint_response (a->ev.user, resp, count);
  return r && !a->done
    ? srv_die (a, GF_DISCONNECT_BY_APPLICATION, GF_ERR_HANDLER) : GF_OK;
}

int
gf_auth_server_input (gf_auth_server *a, uint64_t now_us,
                      const uint8_t *payload, size_t len)
{
  (void) now_us;
  if (a == NULL || payload == NULL || len == 0)
    return GF_ERR_INVAL;
  if (!a->started)
    return GF_ERR_STATE;
  if (a->done)
    return GF_OK;		/* After the end, requests are ignored.  */
  switch (payload[0])
    {
    case GF_MSG_USERAUTH_REQUEST:
      return srv_handle_request (a, payload, len);
    case GF_MSG_USERAUTH_INFO_RESPONSE:
      return srv_handle_info_response (a, payload, len);
    default:
      return srv_die (a, GF_DISCONNECT_PROTOCOL_ERROR, GF_ERR_PROTOCOL);
    }
}

int
gf_auth_server_accept (gf_auth_server *a, uint64_t now_us)
{
  uint8_t m = GF_MSG_USERAUTH_SUCCESS;
  gf_slice user;
  int r;

  (void) now_us;
  if (a == NULL || a->done || a->pending != P_REQUEST || a->pending_probe)
    return GF_ERR_STATE;
  a->pending = P_NONE;
  r = srv_send (a, &m, 1);
  if (r != GF_OK)
    return r;
  a->done = 1;
  user.data = a->user;
  user.len = a->userlen;
  if (a->ev.authenticated && a->ev.authenticated (a->ev.user, user))
    return GF_ERR_HANDLER;
  return GF_OK;
}

int
gf_auth_server_permits (const gf_auth_server *a, const char *permission)
{
  if (a == NULL || permission == NULL)
    return 0;
  return a->cert_key == NULL || gf_cert_has_extension (a->cert_key, permission);
}

int
gf_auth_server_force_command (const gf_auth_server *a, gf_slice *cmd)
{
  if (a == NULL || cmd == NULL)
    return GF_ERR_INVAL;
  cmd->data = a->force;
  cmd->len = a->forcelen;
  return GF_OK;
}

int
gf_auth_server_reject (gf_auth_server *a, uint64_t now_us, int partial)
{
  (void) now_us;
  if (a == NULL || a->done || a->pending != P_REQUEST)
    return GF_ERR_STATE;
  if (partial)
    {
      a->pending = P_NONE;
      return srv_failure (a, 1);
    }
  return srv_attempt_failed (a, !a->pending_probe);
}

int
gf_auth_server_pk_ok (gf_auth_server *a, uint64_t now_us)
{
  uint8_t *buf;
  const char *alg;
  gf_writer w;
  size_t cap;
  int r;

  (void) now_us;
  if (a == NULL || a->done || a->pending != P_REQUEST || !a->pending_probe)
    return GF_ERR_STATE;
  alg = gf_sigalg_name (a->pk_alg);
  cap = 16 + strlen (alg) + a->pk_bloblen;
  buf = malloc (cap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, GF_MSG_USERAUTH_PK_OK);
  gf_wr_cstring (&w, alg);
  gf_wr_string (&w, a->pk_blob, a->pk_bloblen);
  a->pending = P_NONE;
  r = srv_send (a, buf, w.len);
  free (buf);
  return r;
}

int
gf_auth_server_kbdint_prompt (gf_auth_server *a, uint64_t now_us,
                              const char *name, const char *instruction,
                              size_t nprompts, const char *const *prompts,
                              const int *echo)
{
  uint8_t *buf;
  size_t cap = 64 + strlen (name) + strlen (instruction), i;
  gf_writer w;
  int r;

  (void) now_us;
  if (a == NULL || a->done || a->pending != P_REQUEST
      || a->pending_method != GF_AUTH_KBDINT || nprompts > GF_AUTH_MAX_PROMPTS
      || (nprompts && (prompts == NULL || echo == NULL)))
    return GF_ERR_STATE;
  for (i = 0; i < nprompts; i++)
    cap += 8 + strlen (prompts[i]);
  buf = malloc (cap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, GF_MSG_USERAUTH_PK_OK);	/* INFO_REQUEST.  */
  gf_wr_cstring (&w, name);
  gf_wr_cstring (&w, instruction);
  gf_wr_cstring (&w, "");
  gf_wr_u32 (&w, (uint32_t) nprompts);
  for (i = 0; i < nprompts; i++)
    {
      gf_wr_cstring (&w, prompts[i]);
      gf_wr_bool (&w, echo[i]);
    }
  a->pending = P_KBD;
  a->kbd_prompts = nprompts;
  r = srv_send (a, buf, w.len);
  free (buf);
  return r;
}

int
gf_auth_server_banner (gf_auth_server *a, uint64_t now_us, const char *text)
{
  uint8_t *buf;
  size_t n, cap, i;
  gf_writer w;
  int r;

  (void) now_us;
  if (a == NULL || text == NULL)
    return GF_ERR_INVAL;
  if (a->done)
    return GF_ERR_STATE;
  n = strlen (text);
  if (!gf_utf8_valid ((const uint8_t *) text, n))
    return GF_ERR_INVAL;
  for (i = 0; i < n; i++)
    if ((uint8_t) text[i] < 0x20 && text[i] != '\n' && text[i] != '\r'
        && text[i] != '\t')
      return GF_ERR_INVAL;
  cap = n + 16;
  buf = malloc (cap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, GF_MSG_USERAUTH_BANNER);
  gf_wr_string (&w, text, n);
  gf_wr_cstring (&w, "");
  r = srv_send (a, buf, w.len);
  free (buf);
  return r;
}

uint64_t
gf_auth_server_timeout (const gf_auth_server *a)
{
  return a->started && !a->done ? a->deadline : UINT64_MAX;
}

int
gf_auth_server_on_timeout (gf_auth_server *a, uint64_t now_us)
{
  if (a->started && !a->done && now_us >= a->deadline)
    return srv_die (a, GF_DISCONNECT_CONNECTION_LOST, GF_ERR_TIMEOUT);
  return GF_OK;
}

int
gf_auth_server_is_done (const gf_auth_server *a)
{
  return a->done;
}

/* ================================================================== */
/* Client                                                             */
/* ================================================================== */

enum attempt
{
  A_NONE,
  A_PK_QUERY,
  A_PK_SIGNING,			/* Waiting for the application to sign.  */
  A_PK_SIGNED,
  A_KBD,
  A_PASSWORD
};

struct gf_auth_client
{
  gf_auth_client_config cfg;
  gf_auth_client_events ev;
  char *user;
  unsigned allowed;		/* What we may try.  */
  unsigned server_methods;	/* What the server last said continues.  */
  int started, done;
  uint8_t sid[GF_KEX_MAX_HASH_AUTH];
  size_t sidlen;
  uint8_t *host;
  size_t hostlen;
  int hostbound;
  char *sigalgs;		/* server-sig-algs, or NULL if unknown.  */
  size_t sigalgs_len;
  unsigned attempts;
  int stage;			/* 0 keys, 1 keyboard-interactive, 2 password.  */
  size_t key_idx;
  size_t cur_key;
  enum gf_sigalg cur_alg;
  enum attempt cur;
  size_t kbd_prompts;
  uint8_t *sign_data;		/* What the application is signing.  */
  size_t sign_len;
};

int
gf_auth_client_new (gf_auth_client **out, const gf_auth_client_config *config,
                    const gf_auth_client_events *events)
{
  gf_auth_client *a;
  size_t i;

  if (out == NULL || config == NULL || events == NULL || config->user == NULL
      || events->send == NULL || events->failed == NULL)
    return GF_ERR_INVAL;
  if (strlen (config->user) > GF_AUTH_MAX_USER
      || !gf_utf8_valid ((const uint8_t *) config->user, strlen (config->user)))
    return GF_ERR_INVAL;
  for (i = 0; i < config->nkeys; i++)
    if (config->keys == NULL || config->keys[i] == NULL
        || (!gf_key_has_private (config->keys[i]) && events->sign == NULL))
      return GF_ERR_INVAL;
  a = calloc (1, sizeof *a);
  if (a == NULL)
    return GF_ERR_NOMEM;
  a->cfg = *config;
  a->ev = *events;
  a->user = malloc (strlen (config->user) + 1);
  if (a->user == NULL)
    {
      free (a);
      return GF_ERR_NOMEM;
    }
  strcpy (a->user, config->user);
  a->allowed = config->methods ? config->methods
    : GF_AUTH_PUBLICKEY | GF_AUTH_KBDINT | GF_AUTH_PASSWORD;
  a->allowed &= GF_AUTH_PUBLICKEY | GF_AUTH_PASSWORD | GF_AUTH_KBDINT;
  if (events->kbdint == NULL)
    a->allowed &= ~(unsigned) GF_AUTH_KBDINT;
  if (config->password == NULL)
    a->allowed &= ~(unsigned) GF_AUTH_PASSWORD;
  if (config->nkeys == 0)
    a->allowed &= ~(unsigned) GF_AUTH_PUBLICKEY;
  a->server_methods = GF_AUTH_PUBLICKEY | GF_AUTH_PASSWORD | GF_AUTH_KBDINT;
  *out = a;
  return GF_OK;
}

void
gf_auth_client_free (gf_auth_client *a)
{
  if (a == NULL)
    return;
  free (a->user);
  free (a->host);
  free (a->sigalgs);
  free (a->sign_data);
  gf_wipe (a, sizeof *a);
  free (a);
}

int
gf_auth_client_extension (gf_auth_client *a, gf_slice name, gf_slice value)
{
  if (a == NULL)
    return GF_ERR_INVAL;
  if (a->started)
    return GF_ERR_STATE;
  if (gf_slice_equals (name, "server-sig-algs"))
    {
      free (a->sigalgs);
      a->sigalgs = malloc (value.len + 1);
      if (a->sigalgs == NULL)
        return GF_ERR_NOMEM;
      memcpy (a->sigalgs, value.data, value.len);
      a->sigalgs[value.len] = '\0';
      a->sigalgs_len = value.len;
    }
  else if (gf_slice_equals (name, GF_AUTH_HOSTBOUND_EXTENSION)
           && gf_slice_equals (value, "0"))
    a->hostbound = 1;
  return GF_OK;
}

static int
cl_send (gf_auth_client *a, const uint8_t *p, size_t n)
{
  return a->ev.send (a->ev.user, p, n) ? GF_ERR_HANDLER : GF_OK;
}

static void
cl_request_head (gf_auth_client *a, gf_writer *w, const char *method)
{
  gf_wr_u8 (w, GF_MSG_USERAUTH_REQUEST);
  gf_wr_cstring (w, a->user);
  gf_wr_cstring (w, GF_SERVICE_CONNECTION);
  gf_wr_cstring (w, method);
}

static int
cl_failed (gf_auth_client *a)
{
  a->done = 1;
  return a->ev.failed (a->ev.user) ? GF_ERR_HANDLER : GF_ERR_AUTH;
}

/* The algorithm to sign with: the first the key can make that the server
   accepts, if it said.  0 if there is none.  The server's list names plain
   algorithms only, and a certificate is signed for with the algorithm of
   its key, so a certificate algorithm is looked up by its plain one.  */
static enum gf_sigalg
pick_alg (const gf_auth_client *a, const gf_key *key)
{
  size_t n, i;
  const enum gf_sigalg *algs = gf_key_sigalgs (key, &n);

  for (i = 0; i < n; i++)
    {
      /* The list is OpenSSH's and has nothing of X.509 in it: a chain is the
         key's own business and the server says no if it does not take it.  */
      if (a->sigalgs == NULL || gf_sigalg_is_x509 (algs[i]))
        return algs[i];
      if (gf_namelist_contains ((gf_slice) { (const uint8_t *) a->sigalgs,
                                             a->sigalgs_len },
                                gf_sigalg_name (gf_sigalg_base (algs[i]))))
        return algs[i];
    }
  return 0;
}

/* Send the public key request for the current key: the query, or with
   SIGN the signed one.  */
/* Send the public key request for the current key, with the signature SIG
   if SIGN.  */
static int
cl_pk_send (gf_auth_client *a, int sign, const uint8_t *sig, size_t siglen)
{
  const gf_key *key = a->cfg.keys[a->cur_key];
  const char *method = a->hostbound ? GF_AUTH_HOSTBOUND_METHOD : "publickey";
  const char *alg = gf_sigalg_name (a->cur_alg);
  size_t bloblen, cap, ul = strlen (a->user);
  const uint8_t *blob = gf_key_blob (key, &bloblen);
  uint8_t *buf;
  gf_writer w;
  int r;

  cap = 128 + ul + strlen (method) + strlen (alg) + bloblen + a->hostlen
    + siglen;
  buf = malloc (cap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, cap);
  cl_request_head (a, &w, method);
  gf_wr_bool (&w, sign);
  gf_wr_cstring (&w, alg);
  gf_wr_string (&w, blob, bloblen);
  if (a->hostbound)
    gf_wr_string (&w, a->host, a->hostlen);
  if (sign)
    gf_wr_string (&w, sig, siglen);
  a->cur = sign ? A_PK_SIGNED : A_PK_QUERY;
  r = gf_wr_status (&w) == GF_OK ? cl_send (a, buf, w.len) : GF_ERR_BUFSIZE;
  free (buf);
  return r;
}

static int cl_next (gf_auth_client *a);

/* The query (SIGN 0), or the signed request, for which the key signs here or
   the application is asked to.  */
static int
cl_publickey (gf_auth_client *a, int sign)
{
  const gf_key *key = a->cfg.keys[a->cur_key];
  const char *method = a->hostbound ? GF_AUTH_HOSTBOUND_METHOD : "publickey";
  size_t bloblen, ul = strlen (a->user), dl;
  const uint8_t *blob = gf_key_blob (key, &bloblen);
  uint8_t *data = NULL, sig[GF_SIG_MAX];
  size_t siglen = 0;
  int r;

  if (!sign)
    return cl_pk_send (a, 0, NULL, 0);
  {
    gf_slice user = { (const uint8_t *) a->user, ul };

    r = signed_data (&data, &dl, a->sid, a->sidlen, user, method,
                     gf_sigalg_name (a->cur_alg), blob, bloblen,
                     a->hostbound ? a->host : NULL, a->hostlen);
  }
  if (r != GF_OK)
    return r;
  if (gf_key_has_private (key))
    {
      r = gf_key_sign (key, a->cur_alg, data, dl, sig, sizeof sig, &siglen);
      free (data);
      return r != GF_OK ? r : cl_pk_send (a, 1, sig, siglen);
    }
  /* The key is elsewhere: hand the application the bytes.  */
  free (a->sign_data);
  a->sign_data = data;
  a->sign_len = dl;
  a->cur = A_PK_SIGNING;
  if (a->ev.sign (a->ev.user, key, a->cur_alg, (gf_slice) { data, dl }) != 0
      && a->cur == A_PK_SIGNING)
    {
      /* It cannot: another key.  */
      free (a->sign_data);
      a->sign_data = NULL;
      return cl_next (a);
    }
  return GF_OK;
}

int
gf_auth_client_sign_respond (gf_auth_client *a, uint64_t now_us,
                             const uint8_t *sig, size_t len)
{
  const gf_key *key;
  uint8_t *data;
  size_t dl;
  int r;

  (void) now_us;
  if (a == NULL || sig == NULL || len > GF_SIG_MAX)
    return GF_ERR_INVAL;
  if (a->cur != A_PK_SIGNING || a->sign_data == NULL)
    return GF_ERR_STATE;
  key = a->cfg.keys[a->cur_key];
  data = a->sign_data;
  dl = a->sign_len;
  a->sign_data = NULL;
  /* Believe nothing that has not been checked against the key.  */
  r = gf_key_verify (key, a->cur_alg, data, dl, sig, len);
  free (data);
  if (r != GF_OK)
    return cl_next (a);
  return cl_pk_send (a, 1, sig, len);
}

int
gf_auth_client_sign_fail (gf_auth_client *a, uint64_t now_us)
{
  (void) now_us;
  if (a == NULL)
    return GF_ERR_INVAL;
  if (a->cur != A_PK_SIGNING)
    return GF_ERR_STATE;
  free (a->sign_data);
  a->sign_data = NULL;
  return cl_next (a);
}

/* Send the next request that the server's methods and ours allow, or
   report that there is none.  */
static int
cl_next (gf_auth_client *a)
{
  unsigned max = a->cfg.max_attempts ? a->cfg.max_attempts : 6;
  unsigned usable = a->allowed & a->server_methods;

  a->cur = A_NONE;
  if (a->attempts >= max)
    return cl_failed (a);
  if (a->stage == 0)
    {
      while ((usable & GF_AUTH_PUBLICKEY) && a->key_idx < a->cfg.nkeys)
        {
          enum gf_sigalg alg = pick_alg (a, a->cfg.keys[a->key_idx]);

          a->cur_key = a->key_idx++;
          if (alg == 0)
            continue;
          a->cur_alg = alg;
          return cl_publickey (a, 0);
        }
      a->stage = 1;
    }
  if (a->stage == 1)
    {
      a->stage = 2;
      if (usable & GF_AUTH_KBDINT)
        {
          uint8_t buf[256];
          gf_writer w;

          gf_writer_init (&w, buf, sizeof buf);
          cl_request_head (a, &w, "keyboard-interactive");
          gf_wr_cstring (&w, "");
          gf_wr_cstring (&w, "");
          if (gf_wr_status (&w) != GF_OK)
            return GF_ERR_BUFSIZE;
          a->attempts++;
          a->cur = A_KBD;
          return cl_send (a, buf, w.len);
        }
    }
  if (a->stage == 2)
    {
      a->stage = 3;
      if (usable & GF_AUTH_PASSWORD)
        {
          size_t pl = strlen (a->cfg.password);
          uint8_t *buf = malloc (pl + strlen (a->user) + 64);
          gf_writer w;
          int r;

          if (buf == NULL)
            return GF_ERR_NOMEM;
          gf_writer_init (&w, buf, pl + strlen (a->user) + 64);
          cl_request_head (a, &w, "password");
          gf_wr_bool (&w, 0);
          gf_wr_cstring (&w, a->cfg.password);
          a->attempts++;
          a->cur = A_PASSWORD;
          r = gf_wr_status (&w) == GF_OK ? cl_send (a, buf, w.len)
                                         : GF_ERR_BUFSIZE;
          gf_wipe (buf, w.len);
          free (buf);
          return r;
        }
    }
  return cl_failed (a);
}

int
gf_auth_client_start (gf_auth_client *a, uint64_t now_us, const uint8_t *sid,
                      size_t sidlen, const uint8_t *host, size_t hostlen)
{
  uint8_t buf[GF_AUTH_MAX_USER + 64];
  gf_writer w;

  (void) now_us;
  if (a == NULL || sid == NULL || host == NULL || sidlen == 0
      || sidlen > sizeof a->sid)
    return GF_ERR_INVAL;
  if (a->started)
    return GF_ERR_STATE;
  a->host = dup_bytes (host, hostlen);
  if (a->host == NULL)
    return GF_ERR_NOMEM;
  a->hostlen = hostlen;
  memcpy (a->sid, sid, sidlen);
  a->sidlen = sidlen;
  a->started = 1;
  /* First ask what the server offers.  */
  gf_writer_init (&w, buf, sizeof buf);
  cl_request_head (a, &w, "none");
  a->cur = A_NONE;
  return cl_send (a, buf, w.len);
}

static int
cl_info_request (gf_auth_client *a, const uint8_t *p, size_t n)
{
  gf_reader rd;
  gf_slice name, instr, lang, prompts[GF_AUTH_MAX_PROMPTS];
  int echo[GF_AUTH_MAX_PROMPTS];
  uint32_t count, i;

  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_utf8 (&rd, &name) != GF_OK || gf_rd_utf8 (&rd, &instr) != GF_OK
      || gf_rd_string (&rd, &lang) != GF_OK || gf_rd_u32 (&rd, &count) != GF_OK
      || count > GF_AUTH_MAX_PROMPTS)
    return GF_ERR_ENCODING;
  for (i = 0; i < count; i++)
    if (gf_rd_utf8 (&rd, &prompts[i]) != GF_OK
        || gf_rd_bool (&rd, &echo[i]) != GF_OK)
      return GF_ERR_ENCODING;
  if (gf_rd_finish (&rd) != GF_OK)
    return GF_ERR_ENCODING;
  a->kbd_prompts = count;
  if (count == 0)
    {
      static const uint8_t empty[] = { GF_MSG_USERAUTH_INFO_RESPONSE, 0, 0, 0, 0 };

      return cl_send (a, empty, sizeof empty);
    }
  return a->ev.kbdint (a->ev.user, name, instr, count, prompts, echo)
    ? GF_ERR_HANDLER : GF_OK;
}

int
gf_auth_client_input (gf_auth_client *a, uint64_t now_us,
                      const uint8_t *payload, size_t len)
{
  gf_reader rd;
  int r;

  (void) now_us;
  if (a == NULL || payload == NULL || len == 0)
    return GF_ERR_INVAL;
  if (!a->started)
    return GF_ERR_STATE;
  if (a->done)
    return GF_OK;
  gf_reader_init (&rd, payload + 1, len - 1);
  switch (payload[0])
    {
    case GF_MSG_USERAUTH_SUCCESS:
      if (len != 1)
        return GF_ERR_ENCODING;
      a->done = 1;
      return a->ev.authenticated && a->ev.authenticated (a->ev.user)
        ? GF_ERR_HANDLER : GF_OK;

    case GF_MSG_USERAUTH_BANNER:
      {
        gf_slice msg, lang;

        if (gf_rd_utf8 (&rd, &msg) != GF_OK || gf_rd_string (&rd, &lang) != GF_OK
            || gf_rd_finish (&rd) != GF_OK)
          return GF_ERR_ENCODING;
        if (a->ev.banner)
          a->ev.banner (a->ev.user, msg);
        return GF_OK;
      }

    case GF_MSG_USERAUTH_FAILURE:
      {
        gf_slice list;
        int partial;

        if (gf_rd_namelist (&rd, &list) != GF_OK
            || gf_rd_bool (&rd, &partial) != GF_OK
            || gf_rd_finish (&rd) != GF_OK)
          return GF_ERR_ENCODING;
        (void) partial;
        a->server_methods = methods_mask (list);
        return cl_next (a);
      }

    case GF_MSG_USERAUTH_PK_OK:
      if (a->cur == A_PK_QUERY)
        {
          gf_slice alg, blob;
          size_t bl;
          const uint8_t *kb = gf_key_blob (a->cfg.keys[a->cur_key], &bl);

          if (gf_rd_text (&rd, &alg) != GF_OK || gf_rd_string (&rd, &blob) != GF_OK
              || gf_rd_finish (&rd) != GF_OK)
            return GF_ERR_ENCODING;
          if (!gf_slice_equals (alg, gf_sigalg_name (a->cur_alg))
              || blob.len != bl || memcmp (blob.data, kb, bl) != 0)
            return GF_ERR_PROTOCOL;
          a->attempts++;
          r = cl_publickey (a, 1);
          return r;
        }
      if (a->cur == A_KBD)
        return cl_info_request (a, payload, len);
      if (a->cur == A_PASSWORD)	/* Password change: not supported.  */
        return cl_next (a);
      return GF_ERR_PROTOCOL;

    default:
      return GF_ERR_PROTOCOL;
    }
}

int
gf_auth_client_kbdint_respond (gf_auth_client *a, uint64_t now_us, size_t n,
                               const char *const *responses)
{
  uint8_t *buf;
  size_t cap = 16, i;
  gf_writer w;
  int r;

  (void) now_us;
  if (a == NULL || a->cur != A_KBD || n != a->kbd_prompts
      || (n && responses == NULL))
    return GF_ERR_STATE;
  for (i = 0; i < n; i++)
    cap += 4 + strlen (responses[i]);
  buf = malloc (cap);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, cap);
  gf_wr_u8 (&w, GF_MSG_USERAUTH_INFO_RESPONSE);
  gf_wr_u32 (&w, (uint32_t) n);
  for (i = 0; i < n; i++)
    gf_wr_cstring (&w, responses[i]);
  r = cl_send (a, buf, w.len);
  gf_wipe (buf, w.len);
  free (buf);
  return r;
}

int
gf_auth_client_is_done (const gf_auth_client *a)
{
  return a->done;
}
