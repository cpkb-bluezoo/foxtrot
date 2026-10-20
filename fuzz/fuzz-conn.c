#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>
#include <foxtrot/conn.h>

#include "fuzz-common.h"

static gf_key *hostkey;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  if (gf_key_generate (&hostkey, GF_KEY_ED25519, 0) != GF_OK)
    abort ();
  return 0;
}

static int
w_write (void *u, const uint8_t *d, size_t n)
{
  (void) u;
  (void) d;
  (void) n;
  return 0;
}

static int
w_message (void *u, const uint8_t *p, size_t n)
{
  (void) u;
  (void) p;
  (void) n;
  return 0;
}

static int
w_host_key (void *u, const gf_key *k)
{
  (void) u;
  (void) k;
  return 0;
}

/* A transport at the start of its life, as server or client, given bytes in
   pieces: the identification, KEXINIT, the key exchange and whatever else
   a stranger sends.  The first byte says which and how it is cut.  A seed
   made of a real client's first bytes gets past negotiation.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  gf_conn *c = NULL;
  gf_conn_config cfg;
  gf_conn_events ev;
  gf_key *keys[1];
  size_t chunk, pos = 0;
  int server;
  uint64_t now = 1000;

  if (size < 3)
    return 0;
  server = data[0] & 1;
  chunk = 1 + data[1] % 120;
  data += 2;
  size -= 2;
  memset (&cfg, 0, sizeof cfg);
  memset (&ev, 0, sizeof ev);
  ev.write = w_write;
  ev.message = w_message;
  ev.host_key = w_host_key;
  if (server)
    {
      keys[0] = hostkey;
      cfg.host_keys = keys;
      cfg.nhost_keys = 1;
      if (gf_conn_server_new (&c, &cfg, &ev) != GF_OK)
        abort ();
    }
  else if (gf_conn_client_new (&c, &cfg, &ev) != GF_OK)
    abort ();
  if (gf_conn_start (c, now) != GF_OK)
    abort ();
  while (pos < size && !gf_conn_is_closed (c))
    {
      size_t n = size - pos < chunk ? size - pos : chunk;

      now += 1000;
      if (gf_conn_receive (c, now, data + pos, n) != GF_OK)
        break;
      pos += n;
    }
  (void) gf_conn_on_timeout (c, now + 3600u * 1000000u);
  gf_conn_free (c);
  return 0;
}
