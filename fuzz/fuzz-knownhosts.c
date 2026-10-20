#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>
#include <foxtrot/knownhosts.h>

#include "fuzz-common.h"

static gf_key *keys[3];

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  if (gf_key_generate (&keys[0], GF_KEY_ED25519, 0) != GF_OK
      || gf_key_generate (&keys[1], GF_KEY_ECDSA_P256, 0) != GF_OK
      || gf_key_generate (&keys[2], GF_KEY_RSA, 2048) != GF_OK)
    abort ();
  return 0;
}

/* [host length][host][port high][port low][known_hosts text].  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  gf_knownhosts *kh = NULL;
  char host[300], line[1024];
  enum gf_sigalg algs[16];
  size_t hl, bad, i, n;
  unsigned port;

  if (size < 3)
    return 0;
  hl = data[0];
  if (hl + 3 > size)
    return 0;
  memcpy (host, data + 1, hl);
  host[hl] = '\0';
  port = (unsigned) data[1 + hl] << 8 | data[2 + hl];
  data += 3 + hl;
  size -= 3 + hl;
  if (gf_knownhosts_new (&kh) != GF_OK)
    return 0;
  if (gf_knownhosts_load (kh, (const char *) data, size, &bad) == GF_OK)
    {
      for (i = 0; i < 3; i++)
        {
          (void) gf_knownhosts_check (kh, host, port, keys[i], 1700000000);
          (void) gf_knownhosts_check (kh, "example.org", 22, keys[i], 1700000000);
        }
      n = gf_knownhosts_sigalgs (kh, host, port, algs, 16);
      if (n > 16)
        {
          fprintf (stderr, "sigalgs wrote %zu of at most 16\n", n);
          abort ();
        }
      /* A line we write, loaded, makes the host known by that key.  */
      if (gf_knownhosts_format (line, sizeof line, &n, host, port, keys[0], size & 1)
          == GF_OK)
        {
          gf_knownhosts *two = NULL;

          if (gf_knownhosts_new (&two) == GF_OK)
            {
              if (gf_knownhosts_load (two, line, n, &bad) != GF_OK || bad != 0
                  || gf_knownhosts_check (two, host, port, keys[0], 1700000000)
                     != GF_HOST_MATCH)
                {
                  fprintf (stderr, "a line written for %s:%u (%s) is not read back: %.*s",
                           host, port, size & 1 ? "hashed" : "plain", (int) n, line);
                  abort ();
                }
              gf_knownhosts_free (two);
            }
        }
      (void) gf_knownhosts_add (kh, host, port, keys[1]);
    }
  gf_knownhosts_free (kh);
  return 0;
}
