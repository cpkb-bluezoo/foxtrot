#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

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

/* A key derivation for the encrypted files of the harness: PBKDF2.  */
static int
kdf (void *user, const uint8_t *pass, size_t passlen, const uint8_t *salt,
     size_t saltlen, uint32_t rounds, uint8_t *out, size_t outlen)
{
  (void) user;
  return gcry_kdf_derive (pass, passlen, GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt,
                          saltlen, rounds < 2 ? rounds : 2, outlen, out) != 0;
}

/* OpenSSH private key files, protected or not.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  gf_key *k = NULL, *again = NULL;
  static char out[16384];
  size_t n;

  if (gf_key_from_openssh_private_encrypted (&k, (const char *) data, size,
                                             "passphrase", kdf, NULL) != GF_OK)
    return 0;
  if (!gf_key_has_private (k))
    abort ();
  /* What was read can be written, read again, and is the same key.  */
  if (gf_key_to_openssh_private (k, out, sizeof out, &n) == GF_OK)
    {
      if (gf_key_from_openssh_private (&again, out, n) != GF_OK || !gf_key_equal (k, again))
        abort ();
      gf_key_free (again);
      again = NULL;
    }
  if (gf_key_to_openssh_private_encrypted (k, out, sizeof out, &n, "pass", 1, kdf,
                                           NULL) == GF_OK)
    {
      if (gf_key_from_openssh_private_encrypted (&again, out, n, "pass", kdf, NULL)
          != GF_OK || !gf_key_equal (k, again))
        abort ();
      gf_key_free (again);
    }
  gf_key_free (k);
  return 0;
}
