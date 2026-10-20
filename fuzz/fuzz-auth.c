#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>
#include <foxtrot/auth.h>

#include "fuzz-common.h"
#include "../tests/vectors-x509.h"

static gf_key *ca, *user, *userpub, *hostkey;
static uint8_t sid[32];
#ifdef HAVE_GNUTLS
static gf_x509_trust *trust;
#endif

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  if (gf_key_generate (&ca, GF_KEY_ED25519, 0) != GF_OK
      || gf_key_generate (&user, GF_KEY_ED25519, 0) != GF_OK
      || gf_key_generate (&hostkey, GF_KEY_ED25519, 0) != GF_OK)
    abort ();
  {
    size_t n;
    const uint8_t *b = gf_key_blob (user, &n);

    if (gf_key_from_blob (&userpub, b, n) != GF_OK)
      abort ();
  }
  memset (sid, 0x42, sizeof sid);
#ifdef HAVE_GNUTLS
  {
    static uint8_t root[8192];

    if (gf_x509_trust_new (&trust) != GF_OK
        || gf_x509_trust_add_ca (trust, root, fuzz_unhex (vec_x_root, root, sizeof root)) != GF_OK)
      abort ();
  }
#endif
  return 0;
}

/* ---- the server ---- */

struct srv
{
  gf_auth_server *a;
  unsigned schedule;
  unsigned requests;
  int pending;
  int stop;
};

static int
srv_send (void *u, const uint8_t *p, size_t n)
{
  (void) u;
  (void) p;
  (void) n;
  return 0;
}

static int
srv_answer (struct srv *s)
{
  unsigned how = (s->schedule >> (s->requests++ % 8 * 2)) & 3;

  if (how == 0)
    return gf_auth_server_accept (s->a, 0) != GF_OK;
  if (how == 1)
    return gf_auth_server_reject (s->a, 0, s->requests & 1) != GF_OK;
  return gf_auth_server_reject (s->a, 0, 0) != GF_OK;
}

static int
srv_request (void *u, const gf_auth_request *req)
{
  struct srv *s = u;

  if (req->method == GF_AUTH_PUBLICKEY && !req->has_signature)
    {
      if (s->schedule & 0x8000)
        return gf_auth_server_reject (s->a, 0, 0) != GF_OK;
      return gf_auth_server_pk_ok (s->a, 0) != GF_OK;
    }
  if (req->method == GF_AUTH_KBDINT)
    {
      static const char *const prompts[] = { "a", "b" };
      static const int echo[] = { 0, 1 };

      return gf_auth_server_kbdint_prompt (s->a, 0, "n", "i", 1 + (s->schedule & 1),
                                           prompts, echo) != GF_OK;
    }
  if (s->schedule & 0x4000)
    {
      s->pending = 1;		/* The application takes its time.  */
      return 0;
    }
  return srv_answer (s);
}

static int
srv_kbd (void *u, const gf_slice *r, size_t n)
{
  struct srv *s = u;

  (void) r;
  (void) n;
  return srv_answer (s);
}

static int
srv_authenticated (void *u, gf_slice name)
{
  (void) u;
  (void) name;
  return 0;
}

static int
srv_disconnect (void *u, uint32_t reason)
{
  struct srv *s = u;

  (void) reason;
  s->stop = 1;
  return 0;
}

static uint64_t
srv_time (void *u)
{
  (void) u;
  return 1700000000;
}

static void
fuzz_server (const uint8_t *data, size_t size)
{
  struct srv s;
  gf_auth_server_config cfg;
  gf_auth_server_events ev;
  const gf_key *cas[1];
  const uint8_t *frame;
  size_t flen, hl;
  const uint8_t *hb;

  if (size < 2)
    return;
  memset (&s, 0, sizeof s);
  s.schedule = (unsigned) data[0] << 8 | data[1];
  data += 2;
  size -= 2;
  memset (&cfg, 0, sizeof cfg);
  cas[0] = ca;
  cfg.methods = GF_AUTH_PUBLICKEY | GF_AUTH_PASSWORD | GF_AUTH_KBDINT;
  cfg.hostbound = 1;
  cfg.trusted_user_cas = cas;
  cfg.ntrusted_user_cas = 1;
  cfg.peer_address = "192.0.2.1";
#ifdef HAVE_GNUTLS
  cfg.x509_trust = trust;
#endif
  memset (&ev, 0, sizeof ev);
  ev.user = &s;
  ev.send = srv_send;
  ev.request = srv_request;
  ev.kbdint_response = srv_kbd;
  ev.authenticated = srv_authenticated;
  ev.disconnect = srv_disconnect;
  ev.unix_time = srv_time;
  if (gf_auth_server_new (&s.a, &cfg, &ev) != GF_OK)
    abort ();
  hb = gf_key_blob (hostkey, &hl);
  if (gf_auth_server_start (s.a, 0, sid, sizeof sid, hb, hl) != GF_OK)
    abort ();
  while (!s.stop && fuzz_frame (&data, &size, &frame, &flen))
    {
      if (flen == 0 || frame[0] < 50 || frame[0] > 79)
        continue;
      (void) gf_auth_server_input (s.a, 1, frame, flen);
      if (s.pending && !gf_auth_server_is_done (s.a))
        {
          s.pending = 0;
          (void) srv_answer (&s);
        }
    }
  (void) gf_auth_server_on_timeout (s.a, UINT64_MAX / 2);
  gf_auth_server_free (s.a);
}

/* ---- the client ---- */

struct cli
{
  gf_auth_client *a;
  int stop;
};

static int
cli_send (void *u, const uint8_t *p, size_t n)
{
  (void) u;
  (void) p;
  (void) n;
  return 0;
}

static int
cli_kbd (void *u, gf_slice name, gf_slice instr, size_t n, const gf_slice *prompts,
         const int *echo)
{
  struct cli *c = u;
  const char *answers[GF_AUTH_MAX_PROMPTS];
  size_t i;

  (void) name;
  (void) instr;
  (void) prompts;
  (void) echo;
  for (i = 0; i < n && i < GF_AUTH_MAX_PROMPTS; i++)
    answers[i] = "x";
  return gf_auth_client_kbdint_respond (c->a, 0, n, answers) != GF_OK;
}

static int
cli_sign (void *u, const gf_key *key, enum gf_sigalg alg, gf_slice data)
{
  struct cli *c = u;
  uint8_t sig[GF_SIG_MAX];
  size_t n;

  (void) key;
  if (gf_key_sign (user, alg, data.data, data.len, sig, sizeof sig, &n) != GF_OK)
    {
      (void) gf_auth_client_sign_fail (c->a, 0);
      return 0;
    }
  (void) gf_auth_client_sign_respond (c->a, 0, sig, n);
  return 0;
}

static int
cli_done (void *u)
{
  (void) u;
  return 0;
}

static int
cli_failed (void *u)
{
  struct cli *c = u;

  c->stop = 1;
  return 0;
}

static void
fuzz_client (const uint8_t *data, size_t size)
{
  struct cli c;
  gf_auth_client_config cfg;
  gf_auth_client_events ev;
  const gf_key *keys[2];
  const uint8_t *frame;
  size_t flen, hl;
  const uint8_t *hb;

  if (size < 1)
    return;
  memset (&c, 0, sizeof c);
  keys[0] = user;
  keys[1] = userpub;		/* Signed for by cli_sign.  */
  memset (&cfg, 0, sizeof cfg);
  cfg.user = "alice";
  cfg.keys = keys;
  cfg.nkeys = 2;
  cfg.password = "secret";
  memset (&ev, 0, sizeof ev);
  ev.user = &c;
  ev.send = cli_send;
  ev.kbdint = cli_kbd;
  ev.sign = cli_sign;
  ev.authenticated = cli_done;
  ev.failed = cli_failed;
  if (gf_auth_client_new (&c.a, &cfg, &ev) != GF_OK)
    abort ();
  if (data[0] & 1)
    {
      static const char *const lists[] = {
        "ssh-ed25519,rsa-sha2-512", "", "ssh-ed25519-cert-v01@openssh.com",
        "x509v3-ecdsa-sha2-nistp256,ssh-ed25519"
      };
      const char *l = lists[(data[0] >> 1) & 3];

      (void) gf_auth_client_extension (c.a, (gf_slice) { (const uint8_t *) "server-sig-algs", 15 },
                                       (gf_slice) { (const uint8_t *) l, strlen (l) });
      (void) gf_auth_client_extension (c.a,
        (gf_slice) { (const uint8_t *) "publickey-hostbound@openssh.com", 31 },
        (gf_slice) { (const uint8_t *) "0", 1 });
    }
  data++;
  size--;
  hb = gf_key_blob (hostkey, &hl);
  if (gf_auth_client_start (c.a, 0, sid, sizeof sid, hb, hl) != GF_OK)
    abort ();
  while (!c.stop && fuzz_frame (&data, &size, &frame, &flen))
    {
      if (flen == 0 || frame[0] < 50 || frame[0] > 79)
        continue;
      (void) gf_auth_client_input (c.a, 1, frame, flen);
    }
  gf_auth_client_free (c.a);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;
  if (data[0] & 1)
    fuzz_server (data + 1, size - 1);
  else
    fuzz_client (data + 1, size - 1);
  return 0;
}
