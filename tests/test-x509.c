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

#include <stdio.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/wire.h>
#include <foxtrot/key.h>
#include <foxtrot/x509.h>

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;			/* No X.509 without GnuTLS.  */
}

#else

#include "tst-util.h"
#include "vectors-x509.h"

#define NOW 1700000000u
#define BLOBMAX 16384

static uint8_t msg[64];
static size_t msglen;

static size_t
unhex (const char *hex, uint8_t *out, size_t cap)
{
  return tst_unhex (hex, out, cap);
}

static gf_key *
from_hex (const char *hex)
{
  static uint8_t b[BLOBMAX];
  gf_key *k = NULL;
  size_t n = unhex (hex, b, sizeof b);

  CHECK_EQ (gf_key_from_blob (&k, b, n), GF_OK);
  return k;
}

static int
parse_rc (const char *hex)
{
  static uint8_t b[BLOBMAX];
  gf_key *k = NULL;
  size_t n = unhex (hex, b, sizeof b);
  int rc = gf_key_from_blob (&k, b, n);

  gf_key_free (k);
  return rc;
}

static gf_key *
private_key (const char *pem)
{
  gf_key *k = NULL;

  CHECK_EQ (gf_key_from_openssh_private (&k, pem, strlen (pem)), GF_OK);
  return k;
}

static gf_x509_trust *
trust_with (const char *const *cas, size_t n)
{
  gf_x509_trust *t = NULL;
  static uint8_t d[BLOBMAX];
  size_t i;

  CHECK_EQ (gf_x509_trust_new (&t), GF_OK);
  for (i = 0; i < n; i++)
    CHECK_EQ (gf_x509_trust_add_ca (t, d, unhex (cas[i], d, sizeof d)), GF_OK);
  return t;
}

/* Is the chain of BLOB good for PURPOSE and NAME at NOW under T, with WHY
   as the reason if not?  */
static int
check (const gf_x509_trust *t, const char *blobhex, int purpose,
       const char *name, uint64_t now, const char **why)
{
  gf_key *k = from_hex (blobhex);
  int rc;

  if (k == NULL)
    return -99;
  rc = gf_x509_verify (t, k, purpose, name, now, why);
  gf_key_free (k);
  return rc;
}

#define GOOD(t, blob, purpose, name, now) \
  do { \
    const char *why_ = NULL; \
    int rc_ = check (t, blob, purpose, name, now, &why_); \
    if (rc_ != GF_OK) \
      fprintf (stderr, "%s:%d: %s: expected good, got %d (%s)\n", __FILE__, \
               __LINE__, #blob, rc_, why_ ? why_ : "-"); \
    CHECK_EQ (rc_, GF_OK); \
  } while (0)

#define BAD(t, blob, purpose, name, now, reason) \
  do { \
    const char *why_ = NULL; \
    int rc_ = check (t, blob, purpose, name, now, &why_); \
    if (rc_ != GF_ERR_HOSTKEY || why_ == NULL || strcmp (why_, reason) != 0) \
      fprintf (stderr, "%s:%d: %s: expected \"%s\", got %d (%s)\n", __FILE__, \
               __LINE__, #blob, reason, rc_, why_ ? why_ : "-"); \
    CHECK_EQ (rc_, GF_ERR_HOSTKEY); \
    CHECK (why_ != NULL && strcmp (why_, reason) == 0); \
  } while (0)

static void
test_parse (void)
{
  static const struct
  {
    const char *blob, *priv, *name;
    enum gf_keytype type;
    enum gf_sigalg alg;
  } v[] = {
    { vec_x_p256_blob, vec_x_p256_private, "x509v3-ecdsa-sha2-nistp256",
      GF_KEY_ECDSA_P256, GF_SIG_X509_ECDSA_NISTP256 },
    { vec_x_p384_blob, vec_x_p384_private, "x509v3-ecdsa-sha2-nistp384",
      GF_KEY_ECDSA_P384, GF_SIG_X509_ECDSA_NISTP384 },
    { vec_x_rsa_blob, vec_x_rsa_private, "x509v3-rsa2048-sha256",
      GF_KEY_RSA, GF_SIG_X509_RSA2048_SHA256 },
    { vec_x_client_blob, vec_x_client_private, "x509v3-ecdsa-sha2-nistp256",
      GF_KEY_ECDSA_P256, GF_SIG_X509_ECDSA_NISTP256 }
  };
  size_t i;

  for (i = 0; i < 4; i++)
    {
      static uint8_t b[BLOBMAX];
      gf_key *k = from_hex (v[i].blob), *priv = private_key (v[i].priv);
      const uint8_t *kb, *pb, *pb2, *cd;
      size_t kl, pl, pl2, cl, na;
      const enum gf_sigalg *a;
      char fp1[64], fp2[64];

      if (k == NULL || priv == NULL)
        continue;
      CHECK_EQ (gf_key_type (k), v[i].type);
      CHECK (strcmp (gf_key_type_name (k), v[i].name) == 0);
      CHECK (!gf_key_is_certificate (k) && !gf_key_is_security_key (k));
      CHECK (!gf_key_has_private (k));
      a = gf_key_sigalgs (k, &na);
      CHECK (na == 1 && a[0] == v[i].alg);
      /* The blob is the RFC 6187 one.  */
      kb = gf_key_blob (k, &kl);
      CHECK (kl == unhex (v[i].blob, b, sizeof b) && memcmp (kb, b, kl) == 0);
      /* The key it carries is the one in the private key file.  */
      pb = gf_key_plain_blob (k, &pl);
      pb2 = gf_key_blob (priv, &pl2);
      CHECK (pl == pl2 && memcmp (pb, pb2, pl) == 0);
      CHECK_EQ (gf_key_fingerprint (k, fp1, sizeof fp1), GF_OK);
      CHECK_EQ (gf_key_fingerprint (priv, fp2, sizeof fp2), GF_OK);
      CHECK (strcmp (fp1, fp2) == 0);
      CHECK (!gf_key_equal (k, priv));
      /* The chain: the end certificate and the intermediate.  */
      CHECK_EQ (gf_x509_chain_length (k), 2);
      CHECK_EQ (gf_x509_chain_cert (k, 0, &cd, &cl), GF_OK);
      CHECK_EQ (gf_x509_chain_cert (k, 1, &cd, &cl), GF_OK);
      CHECK (gf_x509_chain_cert (k, 2, &cd, &cl) != GF_OK);
      CHECK_EQ (gf_x509_chain_length (priv), 0);
      /* Text form: the name and the base64 of the blob.  */
      {
        static char text[BLOBMAX * 2];
        gf_key *t = NULL;
        size_t tn;

        CHECK_EQ (gf_key_to_text (k, text, sizeof text, &tn), GF_OK);
        CHECK (strncmp (text, v[i].name, strlen (v[i].name)) == 0);
        CHECK_EQ (gf_key_from_text (&t, text, tn, NULL), GF_OK);
        CHECK (t != NULL && gf_key_equal (k, t));
        gf_key_free (t);
      }
      gf_key_free (k);
      gf_key_free (priv);
    }
  /* The end certificate by its own, the root as well, OCSP responses
     (kept out of sight): all parse.  */
  CHECK_EQ (parse_rc (vec_x_p256_alone_blob), GF_OK);
  CHECK_EQ (parse_rc (vec_x_p256_with_root_blob), GF_OK);
  CHECK_EQ (parse_rc (vec_x_p256_unsorted_blob), GF_OK);	/* Order is verify's. */
  CHECK_EQ (parse_rc (vec_x_p256_ocsp_blob), GF_OK);
  /* Refused: a name that does not fit the key, a key the policy refuses, an
     algorithm there is none of.  */
  CHECK_EQ (parse_rc (vec_x_p256_as_p384_blob), GF_ERR_UNSUPPORTED);
  CHECK_EQ (parse_rc (vec_x_p256_as_rsa_blob), GF_ERR_UNSUPPORTED);
  CHECK_EQ (parse_rc (vec_x_rsa_as_p256_blob), GF_ERR_UNSUPPORTED);
  CHECK_EQ (parse_rc (vec_x_p256_as_sshrsa_blob), GF_ERR_UNSUPPORTED);
  CHECK_EQ (parse_rc (vec_x_p256_as_p521_blob), GF_ERR_UNSUPPORTED);
  CHECK_EQ (parse_rc (vec_x_rsa1024_blob), GF_ERR_UNSUPPORTED);
  CHECK_EQ (parse_rc (vec_x_ed_blob), GF_ERR_UNSUPPORTED);
  CHECK_EQ (parse_rc (vec_x_p521_blob), GF_ERR_UNSUPPORTED);
}

/* Shapes of the blob that are wrong. */
static void
test_blob_shapes (void)
{
  static uint8_t b[BLOBMAX], c[BLOBMAX];
  size_t n = unhex (vec_x_p256_blob, b, sizeof b), i;
  gf_key *k = NULL;
  size_t name_len = 4 + 26, count_off = name_len;

  /* Every shorter prefix, and one byte more.  */
  for (i = 0; i < n; i++)
    {
      CHECK (gf_key_from_blob (&k, b, i) != GF_OK);
      gf_key_free (k);
      k = NULL;
    }
  memcpy (c, b, n);
  c[n] = 0;
  CHECK (gf_key_from_blob (&k, c, n + 1) != GF_OK);
  /* The certificate count: none, more than there are, far too many. */
  memcpy (c, b, n);
  c[count_off + 3] = 0;
  CHECK_EQ (gf_key_from_blob (&k, c, n), GF_ERR_ENCODING);
  c[count_off + 3] = 3;
  CHECK_EQ (gf_key_from_blob (&k, c, n), GF_ERR_ENCODING);
  c[count_off + 3] = 9;
  CHECK_EQ (gf_key_from_blob (&k, c, n), GF_ERR_ENCODING);
  c[count_off] = 0x7f;
  CHECK_EQ (gf_key_from_blob (&k, c, n), GF_ERR_ENCODING);
  /* A certificate that is not one. */
  memcpy (c, b, n);
  c[count_off + 4 + 4] ^= 0xff;		/* In the first certificate's DER. */
  CHECK (gf_key_from_blob (&k, c, n) != GF_OK);
  /* The OCSP count: more than the cap even with the responses there, and
     as many as the cap, with the responses; one that is too long.  */
  memcpy (c, b, n);
  memset (c + n - 4, 0, 4);
  c[n - 1] = 9;
  memset (c + n, 0, 9 * 4);
  CHECK_EQ (gf_key_from_blob (&k, c, n + 9 * 4), GF_ERR_ENCODING);
  c[n - 1] = 8;
  CHECK_EQ (gf_key_from_blob (&k, c, n + 8 * 4), GF_OK);
  gf_key_free (k);
  k = NULL;
  memcpy (c, b, n);
  c[n - 1] = 1;
  CHECK_EQ (gf_key_from_blob (&k, c, n), GF_ERR_ENCODING);
  c[n - 1] = 1;
  CHECK_EQ (gf_key_from_blob (&k, c, n), GF_ERR_ENCODING);	/* Missing. */
  CHECK (k == NULL);
}

static void
test_sign_verify (void)
{
  static const struct
  {
    const char *blob, *priv, *sig;
    enum gf_sigalg alg, plain;
    const char *plainname;
  } v[] = {
    { vec_x_p256_blob, vec_x_p256_private, vec_x_p256_sig, GF_SIG_X509_ECDSA_NISTP256,
      GF_SIG_ECDSA_NISTP256, "ecdsa-sha2-nistp256" },
    { vec_x_p384_blob, vec_x_p384_private, vec_x_p384_sig, GF_SIG_X509_ECDSA_NISTP384,
      GF_SIG_ECDSA_NISTP384, "ecdsa-sha2-nistp384" },
    { vec_x_rsa_blob, vec_x_rsa_private, vec_x_rsa_sig, GF_SIG_X509_RSA2048_SHA256,
      GF_SIG_RSA_SHA2_256, "rsa-sha2-256" }
  };
  size_t i;

  msglen = unhex (vec_x_msg, msg, sizeof msg);
  for (i = 0; i < 3; i++)
    {
      static uint8_t sig[GF_SIG_MAX], mine[GF_SIG_MAX], plainsig[GF_SIG_MAX];
      gf_key *k = from_hex (v[i].blob), *priv = private_key (v[i].priv);
      gf_key *signer = NULL, *plain_pub = NULL;
      size_t n = unhex (v[i].sig, sig, sizeof sig), mn, pn;
      const uint8_t *cd[2];
      size_t cl[2], j;

      if (k == NULL || priv == NULL)
        continue;
      /* Another implementation's signature, in the RFC's format.  */
      CHECK_EQ (gf_key_verify (k, v[i].alg, msg, msglen, sig, n), GF_OK);
      CHECK_EQ (gf_key_verify (k, v[i].alg, msg, msglen - 1, sig, n), GF_ERR_HOSTKEY);
      for (j = 0; j < n; j++)
        {
          sig[j] ^= 1;
          CHECK (gf_key_verify (k, v[i].alg, msg, msglen, sig, n) != GF_OK);
          sig[j] ^= 1;
        }
      /* A signature is for the algorithm that names it: no plain algorithm
         on the chain, no x509 algorithm on the plain key.  */
      CHECK_EQ (gf_key_verify (k, v[i].plain, msg, msglen, sig, n), GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_verify (priv, v[i].alg, msg, msglen, sig, n), GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_verify (k, i == 0 ? GF_SIG_X509_ECDSA_NISTP384 : GF_SIG_X509_ECDSA_NISTP256,
                               msg, msglen, sig, n), GF_ERR_UNSUPPORTED);
      /* Ours: the private key with the chain attached. */
      for (j = 0; j < 2; j++)
        CHECK_EQ (gf_x509_chain_cert (k, j, &cd[j], &cl[j]), GF_OK);
      CHECK_EQ (gf_key_with_x509 (priv, cd, cl, 2, &signer), GF_OK);
      if (signer == NULL)
        continue;
      CHECK (gf_key_has_private (signer) && gf_key_equal (signer, k));
      CHECK_EQ (gf_key_sign (signer, v[i].alg, msg, msglen, mine, sizeof mine, &mn), GF_OK);
      CHECK_EQ (gf_key_verify (k, v[i].alg, msg, msglen, mine, mn), GF_OK);
      CHECK_EQ (gf_key_sign (signer, v[i].plain, msg, msglen, mine, sizeof mine, &mn),
                GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_sign (priv, v[i].alg, msg, msglen, mine, sizeof mine, &mn),
                GF_ERR_UNSUPPORTED);
      /* Under the name of the plain algorithm it is the plain algorithm's
         signature, which the key inside verifies.  */
      CHECK_EQ (gf_key_sign (signer, v[i].alg, msg, msglen, mine, sizeof mine, &mn), GF_OK);
      {
        gf_reader r;
        gf_slice nm, body;
        gf_writer w;

        gf_reader_init (&r, mine, mn);
        CHECK_EQ (gf_rd_string (&r, &nm), GF_OK);
        CHECK_EQ (gf_rd_string (&r, &body), GF_OK);
        gf_writer_init (&w, plainsig, sizeof plainsig);
        gf_wr_cstring (&w, v[i].plainname);
        gf_wr_string (&w, body.data, body.len);
        pn = w.len;
      }
      {
        const uint8_t *pb = gf_key_blob (priv, &mn);

        CHECK_EQ (gf_key_from_blob (&plain_pub, pb, mn), GF_OK);
      }
      CHECK_EQ (gf_key_verify (plain_pub, v[i].plain, msg, msglen, plainsig, pn), GF_OK);
      gf_key_free (plain_pub);
      gf_key_free (signer);
      gf_key_free (k);
      gf_key_free (priv);
    }
}

static void
test_with_x509_errors (void)
{
  gf_key *k = from_hex (vec_x_p256_blob), *priv = private_key (vec_x_p256_private);
  gf_key *other = private_key (vec_x_p384_private), *out = NULL, *ed = NULL;
  const uint8_t *cd[9];
  size_t cl[9], i;

  for (i = 0; i < 2; i++)
    CHECK_EQ (gf_x509_chain_cert (k, i, &cd[i], &cl[i]), GF_OK);
  for (i = 2; i < 9; i++)
    {
      cd[i] = cd[1];
      cl[i] = cl[1];
    }
  /* A key that is not the certificate's, no key, no private part, no chain,
     too long a chain, an empty certificate, a type there is no x509 for. */
  CHECK_EQ (gf_key_with_x509 (other, cd, cl, 2, &out), GF_ERR_UNSUPPORTED);	/* P-384 key, P-256 chain. */
  gf_key_free (other);
  other = NULL;
  CHECK_EQ (gf_key_generate (&other, GF_KEY_ECDSA_P256, 0), GF_OK);
  CHECK_EQ (gf_key_with_x509 (other, cd, cl, 2, &out), GF_ERR_INVAL);	/* Another P-256 key. */
  CHECK_EQ (gf_key_with_x509 (priv, cd, cl, 0, &out), GF_ERR_INVAL);
  CHECK_EQ (gf_key_with_x509 (priv, cd, cl, 9, &out), GF_ERR_INVAL);
  CHECK_EQ (gf_key_with_x509 (priv, cd, cl, 8, &out), GF_OK);
  gf_key_free (out);
  out = NULL;
  cl[1] = 0;
  CHECK_EQ (gf_key_with_x509 (priv, cd, cl, 2, &out), GF_ERR_INVAL);
  CHECK_EQ (gf_key_with_x509 (k, cd, cl, 1, &out), GF_ERR_INVAL);	/* No private part. */
  CHECK_EQ (gf_key_generate (&ed, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_with_x509 (ed, cd, cl, 1, &out), GF_ERR_UNSUPPORTED);
  CHECK (out == NULL);
  gf_key_free (ed);
  gf_key_free (other);
  gf_key_free (priv);
  gf_key_free (k);
}

static void
test_verify (void)
{
  const char *roots[] = { vec_x_root };
  const char *others[] = { vec_x_ca2 };
  const char *oldroot[] = { vec_x_old_root };
  gf_x509_trust *t = trust_with (roots, 1), *ct, *empty = trust_with (NULL, 0);
  gf_x509_trust *wrong = trust_with (others, 1), *old = trust_with (oldroot, 1);
  static uint8_t d[BLOBMAX];
  size_t dn;

  /* The chains that are good, for a server.  */
  GOOD (t, vec_x_p256_blob, GF_X509_SERVER, "host.example.org", NOW);
  GOOD (t, vec_x_p384_blob, GF_X509_SERVER, "host.example.org", NOW);
  GOOD (t, vec_x_rsa_blob, GF_X509_SERVER, "host.example.org", NOW);
  GOOD (t, vec_x_p256_blob, GF_X509_SERVER, NULL, NOW);		/* No name asked. */
  GOOD (t, vec_x_p256_with_root_blob, GF_X509_SERVER, "host.example.org", NOW);
  GOOD (t, vec_x_noeku_blob, GF_X509_SERVER, "host.example.org", NOW);
  GOOD (t, vec_x_p256_ocsp_blob, GF_X509_SERVER, "host.example.org", NOW);
  /* Names: a dNSName, case-blind, a one-label wildcard, an address. */
  GOOD (t, vec_x_p256_blob, GF_X509_SERVER, "HOST.Example.ORG", NOW);
  GOOD (t, vec_x_p256_blob, GF_X509_SERVER, "a.wild.example.org", NOW);
  GOOD (t, vec_x_p256_blob, GF_X509_SERVER, "192.0.2.7", NOW);
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, "a.b.wild.example.org", NOW, "name does not match");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, "wild.example.org", NOW, "name does not match");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, ".wild.example.org", NOW, "name does not match");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, "evil.example.org", NOW, "name does not match");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, "host.example.org.", NOW, "name does not match");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, "xhost.example.org", NOW, "name does not match");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, "192.0.2.8", NOW, "name does not match");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, "::1", NOW, "name does not match");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, "", NOW, "name does not match");
  /* An address is matched against iPAddress names, IPv6 whole, and never
     against a dNSName that merely looks like one.  */
  GOOD (t, vec_x_ip6_blob, GF_X509_SERVER, "2001:db8::1", NOW);
  GOOD (t, vec_x_ip6_blob, GF_X509_SERVER, "2001:0db8:0:0:0:0:0:1", NOW);
  GOOD (t, vec_x_ip6_blob, GF_X509_SERVER, "192.0.2.7", NOW);
  BAD (t, vec_x_ip6_blob, GF_X509_SERVER, "2001:db8::2", NOW, "name does not match");
  BAD (t, vec_x_ip6_blob, GF_X509_SERVER, "2001:db8:1::1", NOW, "name does not match");
  BAD (t, vec_x_ip6_blob, GF_X509_SERVER, "192.0.2.8", NOW, "name does not match");
  BAD (t, vec_x_dnsip_blob, GF_X509_SERVER, "10.1.2.3", NOW, "name does not match");
  /* A wildcard needs a domain behind it: not "*.org", not "*.example", not
     "*" alone.  */
  BAD (t, vec_x_widestar_blob, GF_X509_SERVER, "evil.org", NOW, "name does not match");
  BAD (t, vec_x_widestar_blob, GF_X509_SERVER, "a.example", NOW, "name does not match");
  BAD (t, vec_x_widestar_blob, GF_X509_SERVER, "anything", NOW, "name does not match");
  /* Nor a star inside a label; the names must be used as written. */
  BAD (t, vec_x_widestar_blob, GF_X509_SERVER, "hello.example.org", NOW, "name does not match");
  BAD (t, vec_x_widestar_blob, GF_X509_SERVER, "h*.example.org", NOW, "name does not match");
  /* The common name is not a name.  */
  BAD (t, vec_x_nosan_blob, GF_X509_SERVER, "cn.example.org", NOW, "name does not match");
  GOOD (t, vec_x_nosan_blob, GF_X509_SERVER, NULL, NOW);
  /* A chain that does not lead to the store: missing intermediate, in the
     wrong order, another CA's, none at all, a store with the wrong CA.  */
  BAD (t, vec_x_p256_alone_blob, GF_X509_SERVER, NULL, NOW, "unknown signer");
  BAD (t, vec_x_p256_unsorted_blob, GF_X509_SERVER, NULL, NOW, "unknown signer");
  BAD (t, vec_x_wrongca_blob, GF_X509_SERVER, NULL, NOW, "unknown signer");
  BAD (empty, vec_x_p256_blob, GF_X509_SERVER, NULL, NOW, "unknown signer");
  BAD (wrong, vec_x_p256_blob, GF_X509_SERVER, NULL, NOW, "unknown signer");
  /* Dates: the end certificate before and after, the intermediate gone, the
     CA gone; and the clock that is ours.  */
  BAD (t, vec_x_expired_blob, GF_X509_SERVER, NULL, NOW, "expired");
  BAD (t, vec_x_future_blob, GF_X509_SERVER, NULL, NOW, "not yet valid");
  BAD (t, vec_x_oldinter_blob, GF_X509_SERVER, NULL, NOW, "expired");
  BAD (old, vec_x_oldroot_blob, GF_X509_SERVER, NULL, NOW, "expired");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, NULL, 1500000000, "not yet valid");
  BAD (t, vec_x_p256_blob, GF_X509_SERVER, NULL, 4200000000u, "expired");
  GOOD (t, vec_x_p256_blob, GF_X509_SERVER, NULL, 1600000000);
  /* A CA the web alone is allowed to use, a CA with a key too weak. */
  BAD (t, vec_x_ekuca_blob, GF_X509_SERVER, NULL, NOW, "not for this purpose");
  BAD (t, vec_x_weakca_blob, GF_X509_SERVER, NULL, NOW, "weak algorithm");
  /* Purposes: a client's certificate is not a server's and the other way;
     TLS server authentication and "any" are not SSH.  */
  BAD (t, vec_x_client_blob, GF_X509_SERVER, NULL, NOW, "not for this purpose");
  GOOD (t, vec_x_client_blob, GF_X509_CLIENT, NULL, NOW);
  BAD (t, vec_x_p256_blob, GF_X509_CLIENT, NULL, NOW, "not for this purpose");
  BAD (t, vec_x_tlsonly_blob, GF_X509_SERVER, NULL, NOW, "not for this purpose");
  BAD (t, vec_x_anyeku_blob, GF_X509_SERVER, NULL, NOW, "not for this purpose");
  /* The end certificate must be allowed to sign; and no SHA-1. */
  BAD (t, vec_x_nodsig_blob, GF_X509_SERVER, NULL, NOW, "key usage lacks digitalSignature");
  /* Made when the generator ran, so tested late in the century. */
  BAD (t, vec_x_sha1_blob, GF_X509_SERVER, NULL, 4000000000u, "weak algorithm");
  /* Revocation: only by a CRL of the store.  */
  GOOD (t, vec_x_revoked_blob, GF_X509_SERVER, NULL, NOW);
  CHECK_EQ (gf_x509_trust_add_crl (t, d, unhex (vec_x_crl_bad, d, sizeof d)), GF_ERR_HOSTKEY);
  GOOD (t, vec_x_revoked_blob, GF_X509_SERVER, NULL, NOW);
  ct = trust_with (roots, 1);
  dn = unhex (vec_x_crl, d, sizeof d);
  CHECK_EQ (gf_x509_trust_add_crl (ct, d, dn), GF_ERR_HOSTKEY);	/* Its signer is the intermediate. */
  gf_x509_trust_free (ct);
  {
    const char *both[] = { vec_x_root, vec_x_inter };

    ct = trust_with (both, 2);
    CHECK_EQ (gf_x509_trust_add_crl (ct, d, dn), GF_OK);
    BAD (ct, vec_x_revoked_blob, GF_X509_SERVER, NULL, NOW, "revoked");
    GOOD (ct, vec_x_p256_blob, GF_X509_SERVER, NULL, NOW);
    /* With the intermediate itself trusted the end certificate alone does. */
    GOOD (ct, vec_x_p256_alone_blob, GF_X509_SERVER, "host.example.org", NOW);
    gf_x509_trust_free (ct);
  }
  /* Arguments. */
  {
    gf_key *k = from_hex (vec_x_p256_blob), *plain = private_key (vec_x_p256_private);
    const char *why = "x";

    CHECK_EQ (gf_x509_verify (NULL, k, GF_X509_SERVER, NULL, NOW, &why), GF_ERR_INVAL);
    CHECK_EQ (gf_x509_verify (t, NULL, GF_X509_SERVER, NULL, NOW, &why), GF_ERR_INVAL);
    CHECK_EQ (gf_x509_verify (t, plain, GF_X509_SERVER, NULL, NOW, &why), GF_ERR_INVAL);
    CHECK_EQ (gf_x509_verify (t, k, 0, NULL, NOW, &why), GF_ERR_INVAL);
    CHECK_EQ (gf_x509_verify (t, k, 3, NULL, NOW, &why), GF_ERR_INVAL);
    CHECK_EQ (gf_x509_verify (t, k, GF_X509_SERVER, NULL, NOW, NULL), GF_OK);
    gf_key_free (k);
    gf_key_free (plain);
    CHECK_EQ (gf_x509_trust_add_ca (t, (const uint8_t *) "junk", 4), GF_ERR_ENCODING);
    CHECK_EQ (gf_x509_trust_add_ca (t, NULL, 4), GF_ERR_INVAL);
    CHECK_EQ (gf_x509_trust_add_crl (t, (const uint8_t *) "junk", 4), GF_ERR_ENCODING);
  }
  gf_x509_trust_free (t);
  gf_x509_trust_free (empty);
  gf_x509_trust_free (wrong);
  gf_x509_trust_free (old);
}

static void
test_names (void)
{
  gf_key *c = from_hex (vec_x_client_blob), *s = from_hex (vec_x_p256_blob);
  char buf[256];
  size_t pos;
  int type;

  CHECK_EQ (gf_x509_subject (c, buf, sizeof buf), GF_OK);
  CHECK (strcmp (buf, "CN=alice") == 0);
  CHECK_EQ (gf_x509_subject (c, buf, 3), GF_ERR_BUFSIZE);
  CHECK_EQ (gf_x509_subject (c, buf, 9), GF_OK);
  CHECK_EQ (gf_x509_subject (c, buf, 8), GF_ERR_BUFSIZE);
  pos = 0;
  CHECK (gf_x509_san (c, &pos, &type, buf, sizeof buf) && type == GF_X509_SAN_EMAIL
         && strcmp (buf, "alice@example.org") == 0);
  CHECK (!gf_x509_san (c, &pos, &type, buf, sizeof buf));
  pos = 0;
  CHECK (gf_x509_san (s, &pos, &type, buf, sizeof buf) && type == GF_X509_SAN_DNS
         && strcmp (buf, "host.example.org") == 0);
  CHECK (gf_x509_san (s, &pos, &type, buf, sizeof buf) && type == GF_X509_SAN_DNS
         && strcmp (buf, "*.wild.example.org") == 0);
  CHECK (gf_x509_san (s, &pos, &type, buf, sizeof buf) && type == GF_X509_SAN_IP
         && strcmp (buf, "192.0.2.7") == 0);
  CHECK (!gf_x509_san (s, &pos, &type, buf, sizeof buf));
  {
    gf_key *plain = private_key (vec_x_p256_private);

    CHECK (gf_x509_subject (plain, buf, sizeof buf) != GF_OK);
    pos = 0;
    CHECK (!gf_x509_san (plain, &pos, &type, buf, sizeof buf));
    gf_key_free (plain);
  }
  gf_key_free (c);
  gf_key_free (s);
}

int
main (void)
{
  gf_crypto_init ();
  test_parse ();
  test_blob_shapes ();
  test_sign_verify ();
  test_with_x509_errors ();
  test_verify ();
  test_names ();
  TST_DONE ();
}

#endif /* HAVE_GNUTLS */
