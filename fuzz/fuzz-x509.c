#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/key.h>
#include <foxtrot/x509.h>

#include "fuzz-common.h"
#include "../tests/vectors-x509.h"

#ifdef HAVE_GNUTLS
static gf_x509_trust *trust, *strict;
#endif

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
#ifdef HAVE_GNUTLS
  {
    static uint8_t root[8192], inter[8192], crl[8192];

    if (gf_x509_trust_new (&trust) != GF_OK || gf_x509_trust_new (&strict) != GF_OK
        || gf_x509_trust_add_ca (trust, root, fuzz_unhex (vec_x_root, root, sizeof root)) != GF_OK
        || gf_x509_trust_add_ca (strict, root, fuzz_unhex (vec_x_root, root, sizeof root)) != GF_OK
        || gf_x509_trust_add_ca (strict, inter, fuzz_unhex (vec_x_inter, inter, sizeof inter)) != GF_OK
        || gf_x509_trust_add_crl (strict, crl, fuzz_unhex (vec_x_crl, crl, sizeof crl)) != GF_OK)
      abort ();
    gf_x509_trust_require_ocsp (strict, 1);
  }
#endif
  return 0;
}

/* An RFC 6187 blob (chain and OCSP responses) is parsed, checked against a
   trust store for both purposes, at several times, and its names read.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
#ifdef HAVE_GNUTLS
  gf_key *k = NULL;
  static const uint64_t times[] = { 1700000000, 0, 1500000000, 4000000000u };
  size_t i;

  if (gf_key_from_blob (&k, data, size) != GF_OK)
    return 0;
  if (gf_x509_chain_length (k) > 0)
    for (i = 0; i < 4; i++)
      {
        const char *why;

        (void) gf_x509_verify (trust, k, GF_X509_SERVER, "host.example.org", times[i], &why);
        (void) gf_x509_verify (trust, k, GF_X509_CLIENT, NULL, times[i], &why);
        (void) gf_x509_verify (strict, k, GF_X509_SERVER, NULL, times[i], &why);
      }
  gf_key_free (k);
#else
  (void) data;
  (void) size;
#endif
  return 0;
}
