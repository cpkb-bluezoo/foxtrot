#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/kexinit.h>

#include "fuzz-common.h"

static uint8_t ours_client[2048], ours_server[2048];
static size_t nclient, nserver;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  if (gf_kexinit_make (ours_client, sizeof ours_client, &nclient, 0, 1, NULL) != GF_OK
      || gf_kexinit_make (ours_server, sizeof ours_server, &nserver, 1, 1, NULL) != GF_OK)
    abort ();
  return 0;
}

/* A KEXINIT from either side, against ours, at the first exchange and
   after it.  What is negotiated has to be something the policy has.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct gf_kexinit theirs, mine;
  struct gf_algs a;
  int initial;

  if (gf_kexinit_parse (data, size, &theirs) != GF_OK)
    return 0;
  for (initial = 0; initial < 2; initial++)
    {
      if (gf_kexinit_parse (ours_server, nserver, &mine) != GF_OK)
        abort ();
      if (gf_kexinit_negotiate (&theirs, &mine, initial, &a) == GF_OK
          && (gf_kex_name (a.kex) == NULL || gf_sigalg_name (a.hostkey) == NULL
              || gf_cipher_name (a.c2s) == NULL || gf_cipher_name (a.s2c) == NULL
              || gf_sigalg_is_user_only (a.hostkey)))
        abort ();
      if (gf_kexinit_parse (ours_client, nclient, &mine) != GF_OK)
        abort ();
      if (gf_kexinit_negotiate (&mine, &theirs, initial, &a) == GF_OK
          && (gf_kex_name (a.kex) == NULL || gf_sigalg_name (a.hostkey) == NULL
              || gf_sigalg_is_user_only (a.hostkey)))
        abort ();
    }
  return 0;
}
