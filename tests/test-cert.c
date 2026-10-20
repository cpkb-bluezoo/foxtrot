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

#include "tst-util.h"
#include "vectors-cert.h"

#define BLOBMAX 4096

static uint8_t msg[64];
static size_t msglen;

static size_t
hexbuf (const char *hex, uint8_t *out, size_t cap)
{
  return tst_unhex (hex, out, cap);
}

static gf_key *
load_cert (const char *hex)
{
  static uint8_t blob[BLOBMAX];
  size_t n = hexbuf (hex, blob, sizeof blob);
  gf_key *k = NULL;
  int rc = gf_key_from_blob (&k, blob, n);

  CHECK_EQ (rc, GF_OK);
  return rc == GF_OK ? k : NULL;
}

static int
parse_rc (const char *hex)
{
  static uint8_t blob[BLOBMAX];
  size_t n = hexbuf (hex, blob, sizeof blob);
  gf_key *k = NULL;
  int rc = gf_key_from_blob (&k, blob, n);

  gf_key_free (k);
  return rc;
}

static int
names_have (const gf_key *c, const char *p, int wild)
{
  return gf_cert_has_principal (c, p, strlen (p), wild);
}

/* ---------------------------------------------------------------- */

static void
check_one (const char *tag, const char *user_hex, const char *host_hex,
           const char *priv, const char *fp_unused, enum gf_keytype type,
           const char *certname)
{
  gf_key *u = load_cert (user_hex), *h = load_cert (host_hex);
  gf_cert_info ci;
  gf_slice n, d;
  size_t pos;
  const char *why;

  (void) fp_unused;
  (void) priv;
  if (u == NULL || h == NULL)
    {
      gf_key_free (u);
      gf_key_free (h);
      return;
    }
  CHECK (gf_key_is_certificate (u));
  CHECK_EQ (gf_key_type (u), type);
  CHECK (strcmp (gf_key_type_name (u), certname) == 0);
  CHECK (!gf_key_has_private (u));
  CHECK_EQ (gf_key_certificate_info (u, &ci), GF_OK);
  CHECK_EQ (ci.type, GF_CERT_USER);
  CHECK_EQ (ci.valid_after, 1577836800);		/* 2020-01-01 UTC.  */
  CHECK_EQ (ci.valid_before, 4102358400);	/* 2099-12-31 00:00 UTC.  */
  CHECK_EQ (ci.serial, 1000 + strlen (tag));
  CHECK (ci.ca != NULL && !gf_key_is_certificate (ci.ca));
  {
    char id[16];

    snprintf (id, sizeof id, "user-%s", tag);
    CHECK (gf_slice_equals (ci.key_id, id));
  }

  /* Principals: exactly alice and bob, in order.  */
  pos = 0;
  CHECK (gf_cert_principal_next (u, &pos, &n) && gf_slice_equals (n, "alice"));
  CHECK (gf_cert_principal_next (u, &pos, &n) && gf_slice_equals (n, "bob"));
  CHECK (!gf_cert_principal_next (u, &pos, &n));
  CHECK (names_have (u, "alice", 0) && names_have (u, "bob", 0));
  CHECK (!names_have (u, "carol", 0) && !names_have (u, "ali", 0));
  CHECK (!names_have (u, "alicex", 0) && !names_have (u, "", 0));
  CHECK (!names_have (u, "a*", 0));		/* No wildcards in user names.  */

  /* The critical options a user certificate carries, in order, and the
     extensions ssh-keygen adds by default.  */
  pos = 0;
  CHECK (gf_cert_critical_next (u, &pos, &n, &d)
         && gf_slice_equals (n, "force-command"));
  CHECK (gf_cert_critical_next (u, &pos, &n, &d)
         && gf_slice_equals (n, "source-address"));
  CHECK (!gf_cert_critical_next (u, &pos, &n, &d));
  pos = 0;
  {
    int pty = 0, count = 0;

    while (gf_cert_extension_next (u, &pos, &n, &d))
      {
        count++;
        if (gf_slice_equals (n, "permit-pty"))
          pty = 1;
      }
    CHECK (pty && count >= 4);
  }

  /* Usable as a user certificate within its dates, not outside, not as a
     host certificate.  */
  CHECK_EQ (gf_cert_check (u, GF_CERT_USER, 1700000000, &why), GF_OK);
  CHECK (why == NULL);
  CHECK_EQ (gf_cert_check (u, GF_CERT_USER, 1500000000, &why), GF_ERR_HOSTKEY);
  CHECK (strcmp (why, "not yet valid") == 0);
  CHECK_EQ (gf_cert_check (u, GF_CERT_USER, 4102358399, NULL), GF_OK);
  CHECK_EQ (gf_cert_check (u, GF_CERT_USER, 4102358400, &why), GF_ERR_HOSTKEY);
  CHECK (strcmp (why, "expired") == 0);
  CHECK_EQ (gf_cert_check (u, GF_CERT_HOST, 1700000000, &why), GF_ERR_HOSTKEY);
  CHECK (strcmp (why, "not a host certificate") == 0);
  CHECK_EQ (gf_cert_check (u, GF_CERT_USER, 1577836800, NULL), GF_OK);
  CHECK_EQ (gf_cert_check (u, GF_CERT_USER, 1577836799, NULL), GF_ERR_HOSTKEY);

  /* The host certificate: wildcard principals, no critical options.  */
  CHECK_EQ (gf_key_certificate_info (h, &ci), GF_OK);
  CHECK_EQ (ci.type, GF_CERT_HOST);
  CHECK_EQ (ci.serial, 77);
  CHECK (names_have (h, "www.example.org", 1));
  CHECK (names_have (h, "a.b.example.org", 1));
  CHECK (names_have (h, "example.com", 1));
  CHECK (!names_have (h, "example.org", 1));
  CHECK (!names_have (h, "www.example.net", 1));
  CHECK (!names_have (h, "www.example.org", 0));	/* Literally, no.  */
  CHECK_EQ (gf_cert_check (h, GF_CERT_HOST, 1700000000, &why), GF_OK);
  CHECK_EQ (gf_cert_check (h, GF_CERT_USER, 1700000000, NULL), GF_ERR_HOSTKEY);

  /* The certified key and the certificate are different keys with the same
     inside.  */
  CHECK (!gf_key_equal (u, h));
  {
    size_t pl;
    const uint8_t *pb = gf_key_plain_blob (u, &pl);
    gf_key *plain = NULL;

    CHECK_EQ (gf_key_from_blob (&plain, pb, pl), GF_OK);
    if (plain != NULL)
      {
        size_t pl2;
        const uint8_t *pb2 = gf_key_plain_blob (h, &pl2);

        CHECK (!gf_key_is_certificate (plain));
        CHECK (pl == pl2 && memcmp (pb, pb2, pl) == 0);
        CHECK (!gf_key_equal (plain, u));
      }
    gf_key_free (plain);
  }
  gf_key_free (u);
  gf_key_free (h);
}

static void
test_vectors (void)
{
  msglen = hexbuf (vec_msg, msg, sizeof msg);
  check_one ("ed", vec_ed_user_cert, vec_ed_host_cert, vec_ed_private,
             vec_ed_user_fp, GF_KEY_ED25519, "ssh-ed25519-cert-v01@openssh.com");
  check_one ("p256", vec_p256_user_cert, vec_p256_host_cert, vec_p256_private,
             vec_p256_user_fp, GF_KEY_ECDSA_P256,
             "ecdsa-sha2-nistp256-cert-v01@openssh.com");
  check_one ("p384", vec_p384_user_cert, vec_p384_host_cert, vec_p384_private,
             vec_p384_user_fp, GF_KEY_ECDSA_P384,
             "ecdsa-sha2-nistp384-cert-v01@openssh.com");
  check_one ("rsa", vec_rsa_user_cert, vec_rsa_host_cert, vec_rsa_private,
             vec_rsa_user_fp, GF_KEY_RSA, "ssh-rsa-cert-v01@openssh.com");
}

static void
test_fingerprints (void)
{
  static const struct
  {
    const char *cert;
    const char *fp;
  } v[] = {
    { vec_ed_user_cert, vec_ed_user_fp }, { vec_p256_user_cert, vec_p256_user_fp },
    { vec_p384_user_cert, vec_p384_user_fp }, { vec_rsa_user_cert, vec_rsa_user_fp }
  };
  size_t i;

  for (i = 0; i < 4; i++)
    {
      gf_key *k = load_cert (v[i].cert);
      char fp[64];

      if (k == NULL)
        continue;
      /* As ssh-keygen -l: the fingerprint of the certified key.  */
      CHECK_EQ (gf_key_fingerprint (k, fp, sizeof fp), GF_OK);
      CHECK (strcmp (fp, v[i].fp) == 0);
      gf_key_free (k);
    }
}

/* Signing with the certified key, and verifying signatures made by an
   independent implementation, under the certificate algorithms.  */
static void
check_signing (const char *cert_hex, const char *priv, const char *const *sigs,
               const enum gf_sigalg *cert_algs, const enum gf_sigalg *plain_algs,
               size_t nalgs)
{
  gf_key *cert = load_cert (cert_hex), *plain = NULL, *both = NULL;
  static uint8_t sig[GF_SIG_MAX], mine[GF_SIG_MAX];
  size_t i, n, mn;
  size_t na;
  const enum gf_sigalg *algs;

  if (cert == NULL)
    return;
  CHECK_EQ (gf_key_from_openssh_private (&plain, priv, strlen (priv)), GF_OK);
  if (plain == NULL)
    {
      gf_key_free (cert);
      return;
    }
  CHECK_EQ (gf_key_with_certificate (plain, cert, &both), GF_OK);
  if (both == NULL)
    {
      gf_key_free (cert);
      gf_key_free (plain);
      return;
    }
  CHECK (gf_key_has_private (both) && gf_key_is_certificate (both));
  CHECK (gf_key_equal (both, cert));
  algs = gf_key_sigalgs (both, &na);
  CHECK_EQ (na, nalgs);
  for (i = 0; i < nalgs && i < na; i++)
    CHECK_EQ (algs[i], cert_algs[i]);
  algs = gf_key_sigalgs (cert, &na);
  CHECK_EQ (na, nalgs);

  for (i = 0; i < nalgs; i++)
    {
      n = hexbuf (sigs[i], sig, sizeof sig);
      /* Their signature, checked against our certificate key.  */
      CHECK_EQ (gf_key_verify (cert, cert_algs[i], msg, msglen, sig, n), GF_OK);
      sig[n - 1] ^= 1;
      CHECK_EQ (gf_key_verify (cert, cert_algs[i], msg, msglen, sig, n),
                GF_ERR_HOSTKEY);
      /* The certificate does not verify as a plain key, nor a plain key as
         a certificate.  */
      sig[n - 1] ^= 1;
      CHECK_EQ (gf_key_verify (cert, plain_algs[i], msg, msglen, sig, n),
                GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_verify (plain, cert_algs[i], msg, msglen, sig, n),
                GF_ERR_UNSUPPORTED);
      /* Ours, with the certificate algorithm, verifies under it, and has
         the plain algorithm's name inside.  */
      CHECK_EQ (gf_key_sign (both, cert_algs[i], msg, msglen, mine,
                             sizeof mine, &mn), GF_OK);
      CHECK_EQ (gf_key_verify (cert, cert_algs[i], msg, msglen, mine, mn), GF_OK);
      CHECK_EQ (gf_key_verify (plain, plain_algs[i], msg, msglen, mine, mn),
                GF_OK);
      CHECK_EQ (gf_key_sign (both, plain_algs[i], msg, msglen, mine,
                             sizeof mine, &mn), GF_ERR_UNSUPPORTED);
      CHECK_EQ (gf_key_sign (plain, cert_algs[i], msg, msglen, mine,
                             sizeof mine, &mn), GF_ERR_UNSUPPORTED);
    }
  /* A certificate for another key cannot be attached.  */
  {
    gf_key *other = NULL, *none = NULL;

    CHECK_EQ (gf_key_generate (&other, gf_key_type (plain), 2048), GF_OK);
    CHECK_EQ (gf_key_with_certificate (other, cert, &none), GF_ERR_INVAL);
    CHECK (none == NULL);
    gf_key_free (other);
  }
  gf_key_free (both);
  gf_key_free (plain);
  gf_key_free (cert);
}

static void
test_signing (void)
{
  {
    const char *const s[] = { vec_ed_sig };
    const enum gf_sigalg c[] = { GF_SIG_ED25519_CERT };
    const enum gf_sigalg p[] = { GF_SIG_ED25519 };

    check_signing (vec_ed_user_cert, vec_ed_private, s, c, p, 1);
  }
  {
    const char *const s[] = { vec_p256_sig };
    const enum gf_sigalg c[] = { GF_SIG_ECDSA_NISTP256_CERT };
    const enum gf_sigalg p[] = { GF_SIG_ECDSA_NISTP256 };

    check_signing (vec_p256_user_cert, vec_p256_private, s, c, p, 1);
  }
  {
    const char *const s[] = { vec_p384_sig };
    const enum gf_sigalg c[] = { GF_SIG_ECDSA_NISTP384_CERT };
    const enum gf_sigalg p[] = { GF_SIG_ECDSA_NISTP384 };

    check_signing (vec_p384_user_cert, vec_p384_private, s, c, p, 1);
  }
  {
    const char *const s[] = { vec_rsa_sig512, vec_rsa_sig256 };
    const enum gf_sigalg c[] = { GF_SIG_RSA_SHA2_512_CERT, GF_SIG_RSA_SHA2_256_CERT };
    const enum gf_sigalg p[] = { GF_SIG_RSA_SHA2_512, GF_SIG_RSA_SHA2_256 };

    check_signing (vec_rsa_user_cert, vec_rsa_private, s, c, p, 2);
  }
}

static void
test_validity_vectors (void)
{
  gf_key *k;
  gf_cert_info ci;
  const char *why;

  k = load_cert (vec_expired_cert);
  if (k)
    {
      CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1700000000, &why), GF_ERR_HOSTKEY);
      CHECK (strcmp (why, "expired") == 0);
      CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1280000000, NULL), GF_OK);
    }
  gf_key_free (k);
  k = load_cert (vec_future_cert);
  if (k)
    {
      CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1700000000, &why), GF_ERR_HOSTKEY);
      CHECK (strcmp (why, "not yet valid") == 0);
    }
  gf_key_free (k);
  /* No limits at all: the largest time is still short of "never".  */
  k = load_cert (vec_forever_cert);
  if (k)
    {
      CHECK_EQ (gf_key_certificate_info (k, &ci), GF_OK);
      CHECK_EQ (ci.valid_after, 0);
      CHECK (ci.valid_before == UINT64_MAX);
      CHECK_EQ (ci.serial, 9);
      CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 0, NULL), GF_OK);
      CHECK_EQ (gf_cert_check (k, GF_CERT_USER, UINT64_MAX - 1, NULL), GF_OK);
      CHECK_EQ (gf_cert_check (k, GF_CERT_USER, UINT64_MAX, NULL), GF_ERR_HOSTKEY);
    }
  gf_key_free (k);
  /* A critical option nobody here knows must stop it.  */
  k = load_cert (vec_unknown_critical_cert);
  if (k)
    {
      CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1700000000, &why), GF_ERR_HOSTKEY);
      CHECK (strcmp (why, "unknown critical option") == 0);
    }
  gf_key_free (k);
  /* Signed by an ECDSA CA.  */
  k = load_cert (vec_p256ca_cert);
  if (k)
    {
      CHECK_EQ (gf_key_certificate_info (k, &ci), GF_OK);
      CHECK_EQ (gf_key_type (ci.ca), GF_KEY_ECDSA_P256);
    }
  gf_key_free (k);
  /* A CA that signed with SHA-1 is refused.  */
  CHECK_EQ (parse_rc (vec_sha1_ca_cert), GF_ERR_UNSUPPORTED);
}

/* Every byte of a certificate matters: change any one and it no longer
   parses (the signature, or the structure, or the type, says no).  */
static void
test_tamper (void)
{
  static const char *const certs[] = {
    vec_ed_user_cert, vec_p256_host_cert, vec_rsa_user_cert
  };
  size_t c;

  for (c = 0; c < 3; c++)
    {
      static uint8_t blob[BLOBMAX], copy[BLOBMAX];
      size_t n = hexbuf (certs[c], blob, sizeof blob), i;
      int bad = 0;

      for (i = 0; i < n; i++)
        {
          gf_key *k = NULL;
          int rc;

          memcpy (copy, blob, n);
          copy[i] ^= 0x01;
          rc = gf_key_from_blob (&k, copy, n);
          if (rc == GF_OK)
            {
              bad++;
              fprintf (stderr, "cert %zu: byte %zu changed, still parses\n", c, i);
            }
          gf_key_free (k);
        }
      CHECK_EQ (bad, 0);
      /* Truncated at every length, and with a byte added.  */
      for (i = 0; i < n; i++)
        {
          gf_key *k = NULL;

          CHECK (gf_key_from_blob (&k, blob, i) != GF_OK);
          gf_key_free (k);
        }
      memcpy (copy, blob, n);
      copy[n] = 0;
      {
        gf_key *k = NULL;

        CHECK (gf_key_from_blob (&k, copy, n + 1) != GF_OK);
        gf_key_free (k);
      }
    }
}

/* ---------------------------------------------------------------- */
/* Certificates built here, to break the structure                    */
/* ---------------------------------------------------------------- */

struct spec
{
  uint32_t type;
  const uint8_t *principals;	/* Packed.  */
  size_t nprincipals;
  const uint8_t *critical;
  size_t ncritical;
  const uint8_t *extensions;
  size_t nextensions;
  size_t noncelen;
  size_t pklen;
  const uint8_t *sigkey;	/* Override the CA's blob.  */
  size_t nsigkey;
  int trailing;
  int sign_with_other;
};

static size_t
build (uint8_t *buf, size_t cap, gf_key *ca, gf_key *other, const struct spec *sp)
{
  gf_writer w;
  uint8_t pk[40], nonce[40], sigbuf[GF_SIG_MAX];
  size_t signed_len, cabl, sl;
  const uint8_t *cab = gf_key_blob (ca, &cabl);
  gf_key *signer = sp->sign_with_other ? other : ca;

  memset (pk, 0x42, sizeof pk);
  memset (nonce, 0x17, sizeof nonce);
  gf_writer_init (&w, buf, cap);
  gf_wr_cstring (&w, "ssh-ed25519-cert-v01@openssh.com");
  gf_wr_string (&w, nonce, sp->noncelen);
  gf_wr_string (&w, pk, sp->pklen);
  gf_wr_u64 (&w, 5);
  gf_wr_u32 (&w, sp->type);
  gf_wr_cstring (&w, "built");
  gf_wr_string (&w, sp->principals, sp->nprincipals);
  gf_wr_u64 (&w, 0);
  gf_wr_u64 (&w, UINT64_MAX);
  gf_wr_string (&w, sp->critical, sp->ncritical);
  gf_wr_string (&w, sp->extensions, sp->nextensions);
  gf_wr_string (&w, "", 0);
  if (sp->sigkey)
    gf_wr_string (&w, sp->sigkey, sp->nsigkey);
  else
    gf_wr_string (&w, cab, cabl);
  signed_len = w.len;
  CHECK_EQ (gf_key_sign (signer, GF_SIG_ED25519, buf, signed_len, sigbuf,
                         sizeof sigbuf, &sl), GF_OK);
  gf_wr_string (&w, sigbuf, sl);
  if (sp->trailing)
    gf_wr_u8 (&w, 0);
  CHECK_EQ (gf_wr_status (&w), GF_OK);
  return w.len;
}

static void
test_structure (void)
{
  gf_key *ca = NULL, *other = NULL, *k;
  uint8_t cert[BLOBMAX], pr[64], opt[128];
  gf_writer w;
  struct spec sp;
  size_t n;

  CHECK_EQ (gf_key_generate (&ca, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&other, GF_KEY_ED25519, 0), GF_OK);
  gf_writer_init (&w, pr, sizeof pr);
  gf_wr_cstring (&w, "alice");
  memset (&sp, 0, sizeof sp);
  sp.type = GF_CERT_USER;
  sp.principals = pr;
  sp.nprincipals = w.len;
  sp.noncelen = 32;
  sp.pklen = 32;

  /* The control: this builder makes a good certificate.  */
  n = build (cert, sizeof cert, ca, other, &sp);
  k = NULL;
  CHECK_EQ (gf_key_from_blob (&k, cert, n), GF_OK);
  CHECK (k != NULL && gf_cert_has_principal (k, "alice", 5, 0));
  gf_key_free (k);

  /* Critical options are for user certificates; a host certificate that
     has one parses (it is well formed) but is not usable.  */
  {
    struct spec b = sp;
    const char *why;

    {
      uint8_t in[16];
      gf_writer iw;

      gf_writer_init (&iw, in, sizeof in);
      gf_wr_cstring (&iw, "x");
      gf_writer_init (&w, opt, sizeof opt);
      gf_wr_cstring (&w, "force-command");
      gf_wr_string (&w, in, iw.len);
    }
    b.critical = opt;
    b.ncritical = w.len;
    n = build (cert, sizeof cert, ca, other, &b);
    k = NULL;
    CHECK_EQ (gf_key_from_blob (&k, cert, n), GF_OK);
    if (k != NULL)
      {
        CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1, NULL), GF_OK);
        gf_key_free (k);
      }
    b.type = GF_CERT_HOST;
    n = build (cert, sizeof cert, ca, other, &b);
    k = NULL;
    CHECK_EQ (gf_key_from_blob (&k, cert, n), GF_OK);
    if (k != NULL)
      {
        CHECK_EQ (gf_cert_check (k, GF_CERT_HOST, 1, &why), GF_ERR_HOSTKEY);
        CHECK (strcmp (why, "critical option on a host certificate") == 0);
        gf_key_free (k);
      }
  }

  /* Each of these must be refused.  */
  {
    struct spec b;
    int rc;

    b = sp;
    b.type = 0;
    n = build (cert, sizeof cert, ca, other, &b);
    k = NULL;
    rc = gf_key_from_blob (&k, cert, n);
    CHECK (rc != GF_OK);
    b.type = 3;
    n = build (cert, sizeof cert, ca, other, &b);
    CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);

    b = sp;
    b.noncelen = 0;
    n = build (cert, sizeof cert, ca, other, &b);
    CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);

    b = sp;
    b.pklen = 31;
    n = build (cert, sizeof cert, ca, other, &b);
    CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);

    b = sp;
    b.trailing = 1;
    n = build (cert, sizeof cert, ca, other, &b);
    CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);

    /* Signed by a key that is not the one named inside.  */
    b = sp;
    b.sign_with_other = 1;
    n = build (cert, sizeof cert, ca, other, &b);
    CHECK_EQ (gf_key_from_blob (&k, cert, n), GF_ERR_HOSTKEY);

    /* Principals that are not whole strings.  */
    b = sp;
    b.nprincipals = 3;
    n = build (cert, sizeof cert, ca, other, &b);
    CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);

    /* Options out of order, repeated, or cut short.  */
    {
      static const char *const orders[][2] = {
        { "b", "a" }, { "a", "a" }, { "force-command", "force" }
      };
      size_t i;

      for (i = 0; i < 3; i++)
        {
          b = sp;
          gf_writer_init (&w, opt, sizeof opt);
          gf_wr_cstring (&w, orders[i][0]);
          gf_wr_cstring (&w, "");
          gf_wr_cstring (&w, orders[i][1]);
          gf_wr_cstring (&w, "");
          b.critical = opt;
          b.ncritical = w.len;
          n = build (cert, sizeof cert, ca, other, &b);
          CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);
          b.critical = NULL;
          b.ncritical = 0;
          b.extensions = opt;
          b.nextensions = w.len;
          n = build (cert, sizeof cert, ca, other, &b);
          CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);
        }
      /* In order is fine; so is a name that is a prefix of the next.  */
      b = sp;
      gf_writer_init (&w, opt, sizeof opt);
      gf_wr_cstring (&w, "a");
      gf_wr_cstring (&w, "");
      gf_wr_cstring (&w, "ab");
      gf_wr_cstring (&w, "");
      gf_wr_cstring (&w, "b");
      gf_wr_cstring (&w, "");
      b.extensions = opt;
      b.nextensions = w.len;
      n = build (cert, sizeof cert, ca, other, &b);
      k = NULL;
      CHECK_EQ (gf_key_from_blob (&k, cert, n), GF_OK);
      gf_key_free (k);
      /* An odd number of strings.  */
      b = sp;
      gf_writer_init (&w, opt, sizeof opt);
      gf_wr_cstring (&w, "a");
      b.critical = opt;
      b.ncritical = w.len;
      n = build (cert, sizeof cert, ca, other, &b);
      CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);
    }
    /* The CA is a certificate: no chains.  */
    {
      size_t cl;
      const uint8_t *c1;
      gf_key *inner = load_cert (vec_ed_user_cert);

      if (inner != NULL)
        {
          c1 = gf_key_blob (inner, &cl);
          b = sp;
          b.sigkey = c1;
          b.nsigkey = cl;
          n = build (cert, sizeof cert, ca, other, &b);
          CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);
          gf_key_free (inner);
        }
    }
    /* A CA key the policy refuses, and one that is not a key.  */
    {
      static const uint8_t junk[] = { 0, 0, 0, 3, 'a', 'b', 'c' };

      b = sp;
      b.sigkey = junk;
      b.nsigkey = sizeof junk;
      n = build (cert, sizeof cert, ca, other, &b);
      CHECK (gf_key_from_blob (&k, cert, n) != GF_OK);
    }
  }
  gf_key_free (ca);
  gf_key_free (other);
}

/* A user certificate with one critical option whose value is VALUE (as the
   string inside the option's data), or with raw DATA if VALUE is NULL.  */
static gf_key *
with_option (gf_key *ca, gf_key *other, const char *name, const char *value,
             const uint8_t *data, size_t datalen)
{
  uint8_t cert[BLOBMAX], pr[16], opt[256], inner[200];
  gf_writer w, iw;
  struct spec sp;
  gf_key *k = NULL;
  size_t n;

  gf_writer_init (&w, pr, sizeof pr);
  gf_wr_cstring (&w, "alice");
  memset (&sp, 0, sizeof sp);
  sp.type = GF_CERT_USER;
  sp.principals = pr;
  sp.nprincipals = w.len;
  sp.noncelen = 32;
  sp.pklen = 32;
  gf_writer_init (&w, opt, sizeof opt);
  gf_wr_cstring (&w, name);
  if (value != NULL)
    {
      gf_writer_init (&iw, inner, sizeof inner);
      gf_wr_cstring (&iw, value);
      gf_wr_string (&w, inner, iw.len);
    }
  else
    gf_wr_string (&w, data, datalen);
  sp.critical = opt;
  sp.ncritical = w.len;
  n = build (cert, sizeof cert, ca, other, &sp);
  CHECK_EQ (gf_key_from_blob (&k, cert, n), GF_OK);
  return k;
}

static void
test_options (void)
{
  gf_key *ca = NULL, *other = NULL, *k;
  gf_slice v;
  const char *why;
  static const uint8_t flag[] = { 0, 0, 0, 0 };
  static const uint8_t two[] = { 0, 0, 0, 1, 'a', 0, 0, 0, 1, 'b' };
  static const uint8_t trunc[] = { 0, 0, 0, 9, 'a' };

  /* From ssh-keygen.  */
  k = load_cert (vec_ed_user_cert);
  if (k != NULL)
    {
      CHECK_EQ (gf_cert_critical_option (k, "force-command", &v), 1);
      CHECK (gf_slice_equals (v, "/bin/true"));
      CHECK_EQ (gf_cert_critical_option (k, "source-address", &v), 1);
      CHECK (gf_slice_equals (v, "192.0.2.0/24"));
      CHECK_EQ (gf_cert_critical_option (k, "verify-required", &v), 0);
      CHECK (gf_cert_source_address_ok (k, "192.0.2.1"));
      CHECK (gf_cert_source_address_ok (k, "192.0.2.255"));
      CHECK (gf_cert_source_address_ok (k, "::ffff:192.0.2.9"));
      CHECK (!gf_cert_source_address_ok (k, "192.0.3.1"));
      CHECK (!gf_cert_source_address_ok (k, "192.0.1.255"));
      CHECK (!gf_cert_source_address_ok (k, "2001:db8::1"));
      CHECK (!gf_cert_source_address_ok (k, "::ffff:192.0.3.1"));
      CHECK (!gf_cert_source_address_ok (k, "example.org"));
      CHECK (!gf_cert_source_address_ok (k, ""));
      CHECK (!gf_cert_source_address_ok (k, NULL));
      gf_key_free (k);
    }
  k = load_cert (vec_verify_cert);
  if (k != NULL)
    {
      CHECK_EQ (gf_cert_critical_option (k, "verify-required", &v), 1);
      CHECK_EQ (v.len, 0);
      CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1700000000, NULL), GF_OK);
      gf_key_free (k);
    }
  /* No restriction, no options.  */
  k = load_cert (vec_forever_cert);
  if (k != NULL)
    {
      CHECK_EQ (gf_cert_critical_option (k, "force-command", &v), 0);
      CHECK (gf_cert_source_address_ok (k, NULL));
      CHECK (gf_cert_source_address_ok (k, "203.0.113.1"));
      gf_key_free (k);
    }

  CHECK_EQ (gf_key_generate (&ca, GF_KEY_ED25519, 0), GF_OK);
  CHECK_EQ (gf_key_generate (&other, GF_KEY_ED25519, 0), GF_OK);
  {
    static const struct
    {
      const char *list, *addr;
      int ok;
    } t[] = {
      { "10.0.0.1", "10.0.0.1", 1 },
      { "10.0.0.1", "10.0.0.2", 0 },
      { "10.0.0.1,192.168.0.0/16", "192.168.77.1", 1 },
      { "10.0.0.1,192.168.0.0/16", "10.0.0.1", 1 },
      { "10.0.0.1,192.168.0.0/16", "192.169.0.1", 0 },
      { "10.0.0.0/13", "10.7.255.255", 1 },	/* Not on a byte boundary.  */
      { "10.0.0.0/13", "10.8.0.0", 0 },
      { "10.0.0.0/13", "9.255.255.255", 0 },
      { "0.0.0.0/0", "203.0.113.9", 1 },
      { "0.0.0.0/0", "2001:db8::1", 0 },	/* Another family.  */
      { "2001:db8::/32", "2001:db8:ffff::1", 1 },
      { "2001:db8::/32", "2001:db9::1", 0 },
      { "2001:db8::/33", "2001:db8:8000::1", 0 },
      { "2001:db8::/33", "2001:db8:7fff::1", 1 },
      { "::/0", "2001:db8::1", 1 },
      { "::/0", "10.0.0.1", 0 },
      { "::1", "::1", 1 },
      { "10.0.0.1/32", "10.0.0.1", 1 },
      /* Malformed anywhere in the list: nobody matches.  */
      { "10.0.0.0/33", "10.0.0.1", 0 },
      { "::/129", "::1", 0 },
      { "10.0.0.0/", "10.0.0.1", 0 },
      { "10.0.0.0/x", "10.0.0.1", 0 },
      { "10.0.0.0/-1", "10.0.0.1", 0 },
      { "10.0.0.1,", "10.0.0.1", 0 },
      { ",10.0.0.1", "10.0.0.1", 0 },
      { "10.0.0.1,,10.0.0.2", "10.0.0.2", 0 },
      { "10.0.0.1,example.org", "10.0.0.1", 0 },
      { "10.0.0.1, 10.0.0.2", "10.0.0.2", 0 },
      { "10.0.0.1/24/8", "10.0.0.1", 0 },
      { "300.0.0.1", "10.0.0.1", 0 },
      { "", "10.0.0.1", 0 }
    };
    size_t i;

    for (i = 0; i < sizeof t / sizeof t[0]; i++)
      {
        k = with_option (ca, other, "source-address", t[i].list, NULL, 0);
        if (k == NULL)
          continue;
        /* A list that is wrong anywhere is not a usable certificate.  */
        if (t[i].ok == 0 && gf_cert_check (k, GF_CERT_USER, 1, NULL) != GF_OK)
          CHECK (gf_cert_source_address_ok (k, t[i].addr) == 0);
        if (gf_cert_source_address_ok (k, t[i].addr) != t[i].ok)
          {
            fprintf (stderr, "source-address \"%s\" for %s: want %d\n",
                     t[i].list, t[i].addr, t[i].ok);
            CHECK (0);
          }
        gf_key_free (k);
      }
  }

  /* Values that are not one string, or are empty, stop the certificate; a
     flag option is fine only for the one that is a flag.  */
  k = with_option (ca, other, "force-command", NULL, two, sizeof two);
  CHECK_EQ (gf_cert_critical_option (k, "force-command", &v), -1);
  CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1, &why), GF_ERR_HOSTKEY);
  CHECK (strcmp (why, "malformed critical option") == 0);
  gf_key_free (k);
  k = with_option (ca, other, "force-command", NULL, trunc, sizeof trunc);
  CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1, &why), GF_ERR_HOSTKEY);
  gf_key_free (k);
  k = with_option (ca, other, "force-command", "", NULL, 0);
  CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1, &why), GF_ERR_HOSTKEY);
  CHECK (strcmp (why, "empty critical option") == 0);
  gf_key_free (k);
  k = with_option (ca, other, "force-command", NULL, flag, 0);
  CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1, &why), GF_ERR_HOSTKEY);
  gf_key_free (k);
  k = with_option (ca, other, "verify-required", NULL, flag, 0);
  CHECK_EQ (gf_cert_check (k, GF_CERT_USER, 1, NULL), GF_OK);
  CHECK_EQ (gf_cert_critical_option (k, "verify-required", &v), 1);
  CHECK_EQ (v.len, 0);
  gf_key_free (k);
  gf_key_free (ca);
  gf_key_free (other);
}

static void
test_wildmatch_via_principals (void)
{
  gf_key *h = load_cert (vec_ed_host_cert);

  if (h == NULL)
    return;
  /* Wildcards only where the principal has them; the pattern '?' is exact
     in length; case matters (callers lower-case host names).  */
  CHECK (names_have (h, "x.example.org", 1));
  CHECK (!names_have (h, ".example.org", 0));
  CHECK (names_have (h, ".example.org", 1));	/* '*' may be empty.  */
  CHECK (!names_have (h, "WWW.EXAMPLE.COM", 1));
  CHECK (!names_have (h, "example.comx", 1));
  CHECK (!names_have (h, "xexample.com", 1));
  gf_key_free (h);
}

int
main (void)
{
  gf_crypto_init ();
  test_vectors ();
  test_fingerprints ();
  test_signing ();
  test_validity_vectors ();
  test_tamper ();
  test_structure ();
  test_options ();
  test_wildmatch_via_principals ();
  TST_DONE ();
}
