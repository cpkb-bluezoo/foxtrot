#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>
#include <foxtrot/x509.h>

#include "fuzz-common.h"

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  gf_crypto_init ();
  return 0;
}

/* A public key blob (plain, OpenSSH certificate, security key or X.509
   chain), and a signature on some data by it.  The input is
   [u16 length][blob][u16 length][signature][data].  What parses is used
   in every way there is, and has to be consistent.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  const uint8_t *blob = NULL, *sig = NULL;
  size_t bl = 0, sl = 0, n, na, i;
  gf_key *k = NULL, *again = NULL;
  const enum gf_sigalg *algs;
  char text[8192], fp[64];

  if (!fuzz_frame (&data, &size, &blob, &bl))
    return 0;
  (void) fuzz_frame (&data, &size, &sig, &sl);
  if (gf_key_from_blob (&k, blob, bl) != GF_OK)
    return 0;
  {
    const uint8_t *b = gf_key_blob (k, &n);

    if (n != bl || memcmp (b, blob, bl) != 0)
      {
        /* A key is rebuilt from its parts: what comes out has to parse to
           the same key.  */
        if (gf_key_from_blob (&again, b, n) != GF_OK || !gf_key_equal (k, again))
          abort ();
        gf_key_free (again);
        again = NULL;
      }
  }
  (void) gf_key_type (k);
  (void) gf_key_bits (k);
  if (gf_key_type_name (k) == NULL || gf_key_has_private (k))
    abort ();
  if (gf_key_fingerprint (k, fp, sizeof fp) != GF_OK)
    abort ();
  if (gf_key_to_text (k, text, sizeof text, &n) == GF_OK)
    {
      if (gf_key_from_text (&again, text, n, NULL) != GF_OK || !gf_key_equal (k, again))
        abort ();
      gf_key_free (again);
    }
  algs = gf_key_sigalgs (k, &na);
  for (i = 0; i < na; i++)
    (void) gf_key_verify (k, algs[i], data, size, sig ? sig : data, sl);
  /* It is no use signing with another algorithm's name.  */
  (void) gf_key_verify (k, GF_SIG_ED25519, data, size, sig ? sig : data, sl);
  (void) gf_key_verify_sk (k, GF_SIG_SK_ED25519, data, size, sig ? sig : data, sl,
                           NULL, NULL);

  if (gf_key_is_certificate (k))
    {
      gf_cert_info ci;
      gf_slice name, d;
      size_t pos = 0;
      const char *why;

      if (gf_key_certificate_info (k, &ci) != GF_OK || ci.ca == NULL)
        abort ();
      (void) gf_cert_check (k, GF_CERT_USER, 1700000000, &why);
      (void) gf_cert_check (k, GF_CERT_HOST, 0, NULL);
      (void) gf_cert_check (k, GF_CERT_USER, UINT64_MAX, NULL);
      while (gf_cert_principal_next (k, &pos, &name))
        (void) gf_cert_has_principal (k, (const char *) name.data, name.len, 1);
      pos = 0;
      while (gf_cert_critical_next (k, &pos, &name, &d))
        (void) gf_cert_critical_option (k, "force-command", &d);
      pos = 0;
      while (gf_cert_extension_next (k, &pos, &name, &d))
        (void) gf_cert_has_extension (k, "permit-pty");
      (void) gf_cert_source_address_ok (k, "192.0.2.1");
      (void) gf_cert_source_address_ok (k, "2001:db8::1");
      (void) gf_cert_source_address_ok (k, NULL);
    }
  if (gf_x509_chain_length (k) > 0)
    {
      int type;
      char out[600];
      size_t pos = 0;

      (void) gf_x509_subject (k, out, sizeof out);
      while (gf_x509_san (k, &pos, &type, out, sizeof out))
        ;
    }
  gf_key_free (k);
  return 0;
}
