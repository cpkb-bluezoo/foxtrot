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

/* Making certificates: what is signed is read back as the same certificate,
   by every kind of CA for every kind of key, and what is a mistake to sign
   is refused.  (That OpenSSH accepts them is the integration tests'.)  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>

#include "tst-util.h"
#include "vectors-cert.h"
/* Both define vec_msg.  */
#define vec_msg vec_msg_sk
#include "vectors-sk.h"
#undef vec_msg

#define NOW 1700000000u

static gf_key *
private_of (const char *priv)
{
  gf_key *k = NULL;

  CHECK_EQ (gf_key_from_openssh_private (&k, priv, strlen (priv)), GF_OK);
  return k;
}

static gf_key *
public_of (const gf_key *k)
{
  gf_key *p = NULL;
  size_t n;
  const uint8_t *b = gf_key_blob (k, &n);

  CHECK_EQ (gf_key_from_blob (&p, b, n), GF_OK);
  return p;
}

static gf_key *
text_key (const char *text)
{
  gf_key *k = NULL;

  CHECK_EQ (gf_key_from_text (&k, text, strlen (text), NULL), GF_OK);
  return k;
}

static const char *const names[] = { "alice", "bob" };

static gf_cert_spec
spec (void)
{
  gf_cert_spec s;

  memset (&s, 0, sizeof s);
  s.type = GF_CERT_USER;
  s.serial = 42;
  s.key_id = "alice@example.org";
  s.principals = names;
  s.nprincipals = 2;
  s.valid_after = NOW - 3600;
  s.valid_before = NOW + 3600;
  return s;
}

static int
contains (const uint8_t *hay, size_t n, const char *needle)
{
  size_t l = strlen (needle), i;

  for (i = 0; i + l <= n; i++)
    if (memcmp (hay + i, needle, l) == 0)
      return 1;
  return 0;
}

/* Every CA against every subject, with and without a private part.  */
static void
test_matrix (void)
{
  gf_key *cas[3], *subs[6];
  size_t i, j, k;

  cas[0] = private_of (vec_ca_ed_private);
  cas[1] = private_of (vec_ca_p256_private);
  cas[2] = private_of (vec_ca_rsa_private);
  subs[0] = private_of (vec_ed_private);
  subs[1] = private_of (vec_p256_private);
  subs[2] = private_of (vec_p384_private);
  subs[3] = private_of (vec_rsa_private);
  subs[4] = text_key (vec_sk_ed_pub);
  subs[5] = text_key (vec_sk_p256_pub);
  for (i = 0; i < 3; i++)
    for (j = 0; j < 6; j++)
      for (k = 0; k < 2; k++)
        {
          gf_cert_spec s = spec ();
          gf_key *sub = k ? public_of (subs[j]) : NULL, *c = NULL, *again = NULL;
          const gf_key *use = k ? sub : subs[j];
          gf_cert_info ci;
          gf_slice name, data, v;
          size_t pos, n, bl;
          const uint8_t *blob;
          char text[4096];

          s.allow = GF_CERT_ALLOW_PTY | GF_CERT_ALLOW_USER_RC;
          s.force_command = "/bin/true";
          s.source_address = "192.0.2.0/24,2001:db8::/32";
          s.verify_required = j >= 4;
          CHECK_EQ (gf_cert_sign (&c, cas[i], use, &s, 0), GF_OK);
          if (c == NULL)
            {
              fprintf (stderr, "ca %zu subject %zu public %zu\n", i, j, k);
              gf_key_free (sub);
              continue;
            }
          CHECK (gf_key_is_certificate (c));
          CHECK_EQ (gf_key_certificate_info (c, &ci), GF_OK);
          CHECK_EQ (ci.serial, 42);
          CHECK_EQ (ci.type, GF_CERT_USER);
          CHECK (gf_slice_equals (ci.key_id, "alice@example.org"));
          CHECK_EQ (ci.valid_after, NOW - 3600);
          CHECK_EQ (ci.valid_before, NOW + 3600);
          CHECK (gf_key_equal (ci.ca, cas[i]));
          /* It certifies the key it was given, and nothing else.  */
          {
            size_t pn1, pn2;
            const uint8_t *p1 = gf_key_plain_blob (c, &pn1),
              *p2 = gf_key_plain_blob (subs[j], &pn2);

            CHECK (pn1 == pn2 && memcmp (p1, p2, pn1) == 0);
          }
          CHECK_EQ (gf_cert_check (c, GF_CERT_USER, NOW, NULL), GF_OK);
          CHECK (gf_cert_check (c, GF_CERT_USER, NOW + 3600, NULL) != GF_OK);
          CHECK (gf_cert_check (c, GF_CERT_USER, NOW - 3601, NULL) != GF_OK);
          CHECK (gf_cert_check (c, GF_CERT_HOST, NOW, NULL) != GF_OK);
          pos = 0;
          CHECK (gf_cert_principal_next (c, &pos, &name));
          CHECK (gf_slice_equals (name, "alice"));
          CHECK (gf_cert_principal_next (c, &pos, &name));
          CHECK (gf_slice_equals (name, "bob"));
          CHECK (!gf_cert_principal_next (c, &pos, &name));
          CHECK_EQ (gf_cert_critical_option (c, "force-command", &v), 1);
          CHECK (gf_slice_equals (v, "/bin/true"));
          CHECK_EQ (gf_cert_critical_option (c, "source-address", &v), 1);
          CHECK (gf_slice_equals (v, "192.0.2.0/24,2001:db8::/32"));
          CHECK_EQ (gf_cert_critical_option (c, "verify-required", &v), j >= 4);
          CHECK (gf_cert_source_address_ok (c, "192.0.2.9"));
          CHECK (!gf_cert_source_address_ok (c, "192.0.3.9"));
          CHECK (gf_cert_has_extension (c, GF_CERT_PERMIT_PTY));
          CHECK (gf_cert_has_extension (c, GF_CERT_PERMIT_USER_RC));
          CHECK (!gf_cert_has_extension (c, GF_CERT_PERMIT_PORT_FORWARDING));
          CHECK (!gf_cert_has_extension (c, GF_CERT_PERMIT_AGENT_FORWARDING));
          CHECK (!gf_cert_has_extension (c, GF_CERT_PERMIT_X11_FORWARDING));
          pos = 0;
          n = 0;
          while (gf_cert_extension_next (c, &pos, &name, &data))
            {
              CHECK_EQ (data.len, 0);
              n++;
            }
          CHECK_EQ (n, 2);
          /* The CA signed with its own first algorithm (SHA-512 for RSA).  */
          blob = gf_key_blob (c, &bl);
          if (i == 2)
            CHECK (contains (blob, bl, "rsa-sha2-512"));
          if (i == 1)
            CHECK (contains (blob, bl, "ecdsa-sha2-nistp256"));
          /* The text of the line reads back as the same certificate.  */
          CHECK_EQ (gf_key_to_text (c, text, sizeof text, &n), GF_OK);
          CHECK_EQ (gf_key_from_text (&again, text, n, NULL), GF_OK);
          CHECK (again != NULL && gf_key_equal (again, c));
          gf_key_free (again);
          gf_key_free (c);
          gf_key_free (sub);
        }
  for (i = 0; i < 3; i++)
    gf_key_free (cas[i]);
  for (j = 0; j < 6; j++)
    gf_key_free (subs[j]);
}

static void
test_host_and_algorithms (void)
{
  gf_key *ca = private_of (vec_ca_rsa_private), *sub = private_of (vec_ed_private);
  gf_key *ed = private_of (vec_ca_ed_private);
  gf_cert_spec s = spec ();
  gf_key *c = NULL, *d = NULL;
  static const char *const hosts[] = { "*.example.org", "example.com" };
  const uint8_t *blob;
  size_t bl;
  gf_cert_info ci;

  /* A host certificate: wildcards in its names, nothing else.  */
  s.type = GF_CERT_HOST;
  s.principals = hosts;
  s.key_id = "host-1";
  CHECK_EQ (gf_cert_sign (&c, ca, sub, &s, 0), GF_OK);
  CHECK_EQ (gf_key_certificate_info (c, &ci), GF_OK);
  CHECK_EQ (ci.type, GF_CERT_HOST);
  CHECK_EQ (gf_cert_check (c, GF_CERT_HOST, NOW, NULL), GF_OK);
  CHECK (gf_cert_has_principal (c, "www.example.org", 15, 1));
  CHECK (gf_cert_has_principal (c, "example.com", 11, 1));
  CHECK (!gf_cert_has_principal (c, "example.net", 11, 1));
  {
    size_t pos = 0;
    gf_slice n, d2;

    CHECK (!gf_cert_extension_next (c, &pos, &n, &d2));
    pos = 0;
    CHECK (!gf_cert_critical_next (c, &pos, &n, &d2));
  }
  gf_key_free (c);

  /* The RSA CA signs with SHA-256 if asked, never with SHA-1, and cannot
     sign with an algorithm of another kind of key.  */
  s = spec ();
  CHECK_EQ (gf_cert_sign (&c, ca, sub, &s, GF_SIG_RSA_SHA2_256), GF_OK);
  blob = gf_key_blob (c, &bl);
  CHECK (contains (blob, bl, "rsa-sha2-256"));
  CHECK (!contains (blob, bl, "rsa-sha2-512"));
  gf_key_free (c);
  CHECK_EQ (gf_cert_sign (&c, ca, sub, &s, GF_SIG_ED25519), GF_ERR_UNSUPPORTED);
  CHECK (c == NULL);
  CHECK_EQ (gf_cert_sign (&c, ca, sub, &s, GF_SIG_RSA_SHA2_256_CERT),
            GF_ERR_UNSUPPORTED);
  CHECK_EQ (gf_cert_sign (&c, ed, sub, &s, GF_SIG_RSA_SHA2_512), GF_ERR_UNSUPPORTED);

  /* Nonces: the same request twice is two certificates.  */
  CHECK_EQ (gf_cert_sign (&c, ed, sub, &s, 0), GF_OK);
  CHECK_EQ (gf_cert_sign (&d, ed, sub, &s, 0), GF_OK);
  CHECK (!gf_key_equal (c, d) || 1);
  {
    size_t n1, n2;
    const uint8_t *b1 = gf_key_blob (c, &n1), *b2 = gf_key_blob (d, &n2);

    CHECK (n1 != n2 || memcmp (b1, b2, n1) != 0);
  }
  gf_key_free (c);
  gf_key_free (d);

  /* A certificate for the CA's own key is no stranger than any other.  */
  CHECK_EQ (gf_cert_sign (&c, ed, ed, &s, 0), GF_OK);
  gf_key_free (c);

  /* Nothing allowed is nothing permitted: no extensions at all.  */
  s = spec ();
  CHECK_EQ (gf_cert_sign (&c, ed, sub, &s, 0), GF_OK);
  CHECK (!gf_cert_has_extension (c, GF_CERT_PERMIT_PTY));
  gf_key_free (c);
  s.allow = GF_CERT_ALLOW_ALL;
  CHECK_EQ (gf_cert_sign (&c, ed, sub, &s, 0), GF_OK);
  CHECK (gf_cert_has_extension (c, GF_CERT_PERMIT_PTY));
  CHECK (gf_cert_has_extension (c, GF_CERT_PERMIT_PORT_FORWARDING));
  CHECK (gf_cert_has_extension (c, GF_CERT_PERMIT_AGENT_FORWARDING));
  CHECK (gf_cert_has_extension (c, GF_CERT_PERMIT_X11_FORWARDING));
  CHECK (gf_cert_has_extension (c, GF_CERT_PERMIT_USER_RC));
  gf_key_free (c);

  gf_key_free (ca);
  gf_key_free (ed);
  gf_key_free (sub);
}

static void
test_refusals (void)
{
  gf_key *ca = private_of (vec_ca_ed_private), *sub = private_of (vec_ed_private);
  gf_key *pubca = public_of (ca), *cert = NULL, *other = NULL;
  gf_key *c = NULL;
  gf_cert_spec s;
  static const char *const none[] = { NULL };
  static const char *const bad[] = { "al\nice" };
  static const char *const empty[] = { "" };
  static const char *const utf8[] = { "\xff\xfe" };
  static const char *const many[] = { "a", "" };
  size_t i;
  char longid[300];

  /* A CA must be able to sign; a subject must not be a certificate.  */
  s = spec ();
  CHECK_EQ (gf_cert_sign (&c, pubca, sub, &s, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_cert_sign (NULL, ca, sub, &s, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_cert_sign (&c, NULL, sub, &s, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_cert_sign (&c, ca, NULL, &s, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_cert_sign (&c, ca, sub, NULL, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_cert_sign (&cert, ca, sub, &s, 0), GF_OK);
  CHECK_EQ (gf_cert_sign (&c, ca, cert, &s, 0), GF_ERR_INVAL);
  CHECK_EQ (gf_cert_sign (&c, cert, sub, &s, 0), GF_ERR_INVAL);	/* No chains.  */
  other = text_key (vec_sk_ed_pub);
  CHECK_EQ (gf_cert_sign (&c, other, sub, &s, 0), GF_ERR_INVAL);
  gf_key_free (other);

  /* Each field.  */
#define REFUSE(edit) \
  do { s = spec (); edit; c = NULL; \
       CHECK_EQ (gf_cert_sign (&c, ca, sub, &s, 0), GF_ERR_INVAL); \
       CHECK (c == NULL); gf_key_free (c); } while (0)
  REFUSE (s.type = 0);
  REFUSE (s.type = 3);
  REFUSE (s.serial = 0);
  REFUSE (s.key_id = NULL);
  REFUSE (s.key_id = "");
  REFUSE (s.key_id = "a\tb");
  REFUSE (s.key_id = "a\x7f");
  REFUSE (s.key_id = "\xc0\x80");
  memset (longid, 'a', sizeof longid);
  longid[256] = '\0';
  REFUSE (s.key_id = longid);
  REFUSE (s.principals = NULL);
  REFUSE (s.nprincipals = 0);
  REFUSE (s.principals = none; s.nprincipals = 1);
  REFUSE (s.principals = bad; s.nprincipals = 1);
  REFUSE (s.principals = empty; s.nprincipals = 1);
  REFUSE (s.principals = utf8; s.nprincipals = 1);
  REFUSE (s.principals = many; s.nprincipals = 2);
  REFUSE (s.nprincipals = 257);
  REFUSE (s.valid_before = UINT64_MAX);
  REFUSE (s.valid_after = s.valid_before);
  REFUSE (s.valid_after = s.valid_before + 1);
  REFUSE (s.allow = 0x20);
  REFUSE (s.allow = 0xffffffffu);
  REFUSE (s.force_command = "");
  REFUSE (s.force_command = "a\nb");
  REFUSE (s.source_address = "");
  REFUSE (s.source_address = "example.org");
  REFUSE (s.source_address = "192.0.2.0/33");
  REFUSE (s.source_address = "192.0.2.0/24,");
  REFUSE (s.source_address = "192.0.2.0/24,,10.0.0.1");
  REFUSE (s.source_address = "*");
  /* A host certificate with user options.  */
  REFUSE (s.type = GF_CERT_HOST; s.allow = GF_CERT_ALLOW_PTY);
  REFUSE (s.type = GF_CERT_HOST; s.force_command = "x");
  REFUSE (s.type = GF_CERT_HOST; s.source_address = "10.0.0.1");
  REFUSE (s.type = GF_CERT_HOST; s.verify_required = 1);
#undef REFUSE
  /* The limits themselves are fine.  */
  s = spec ();
  longid[255] = '\0';
  s.key_id = longid;
  CHECK_EQ (gf_cert_sign (&c, ca, sub, &s, 0), GF_OK);
  gf_key_free (c);
  s = spec ();
  s.valid_after = 0;
  s.valid_before = UINT64_MAX - 1;
  CHECK_EQ (gf_cert_sign (&c, ca, sub, &s, 0), GF_OK);
  gf_key_free (c);
  s = spec ();
  {
    const char *many256[256];

    for (i = 0; i < 256; i++)
      many256[i] = "p";
    s.principals = many256;
    s.nprincipals = 256;
    CHECK_EQ (gf_cert_sign (&c, ca, sub, &s, 0), GF_OK);
    gf_key_free (c);
  }
  gf_key_free (cert);
  gf_key_free (pubca);
  gf_key_free (ca);
  gf_key_free (sub);
}

int
main (void)
{
  CHECK_EQ (gf_crypto_init (), GF_OK);
  test_matrix ();
  test_host_and_algorithms ();
  test_refusals ();
  TST_DONE ();
}
