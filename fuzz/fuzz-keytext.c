#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>

#include "fuzz-common.h"

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  return 0;
}

/* Public keys as text: ".pub" lines.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  gf_key *k = NULL, *again = NULL;
  gf_slice comment;
  char out[8192];
  size_t n;

  if (gf_key_from_text (&k, (const char *) data, size, &comment) != GF_OK)
    return 0;
  if (comment.len > size)
    abort ();
  if (gf_key_to_text (k, out, sizeof out, &n) == GF_OK)
    {
      if (strlen (out) != n || gf_key_from_text (&again, out, n, NULL) != GF_OK
          || !gf_key_equal (k, again))
        abort ();
      gf_key_free (again);
    }
  gf_key_free (k);
  return 0;
}
