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

#include <string.h>

#include <foxtrot/policy.h>

#define ARRAY_LEN(a) (sizeof (a) / sizeof (a)[0])

/* One entry per algorithm.  NAMES holds every name the algorithm is
   offered and accepted under, comma separated, the preferred one first.
   The only alias is the OpenSSH 9.0 name of sntrup761x25519-sha512.  */
struct kex_entry
{
  enum gf_kex kex;
  const char *names;
};

/* Preference order: hybrid post-quantum first, X25519-based ahead of the
   NIST-curve ones, then the classical methods.  A hybrid also holds if
   the post-quantum half were broken, so there is no pure post-quantum
   method.  */
static const struct kex_entry kexes[] = {
  { GF_KEX_MLKEM768X25519_SHA256,   "mlkem768x25519-sha256" },
  { GF_KEX_SNTRUP761X25519_SHA512,
    "sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com" },
  { GF_KEX_MLKEM768NISTP256_SHA256, "mlkem768nistp256-sha256" },
  { GF_KEX_MLKEM1024NISTP384_SHA384, "mlkem1024nistp384-sha384" },
  { GF_KEX_CURVE25519_SHA256,       "curve25519-sha256" },
  { GF_KEX_ECDH_NISTP256_SHA256,    "ecdh-sha2-nistp256" },
  { GF_KEX_ECDH_NISTP384_SHA384,    "ecdh-sha2-nistp384" }
};

static const enum gf_kex default_kex[] = {
  GF_KEX_MLKEM768X25519_SHA256,
  GF_KEX_SNTRUP761X25519_SHA512,
  GF_KEX_MLKEM768NISTP256_SHA256,
  GF_KEX_MLKEM1024NISTP384_SHA384,
  GF_KEX_CURVE25519_SHA256,
  GF_KEX_ECDH_NISTP256_SHA256,
  GF_KEX_ECDH_NISTP384_SHA384
};

struct sig_entry
{
  enum gf_sigalg alg;
  const char *name;
  const char *key_type;		/* Name of the key type in a key blob.  */
  enum gf_sigalg base;		/* The plain algorithm; itself if plain.  */
  int cert;
  int user_only;		/* Never a host key.  */
  int x509;
};

static const struct sig_entry sigs[] = {
  { GF_SIG_ED25519,        "ssh-ed25519",         "ssh-ed25519",
    GF_SIG_ED25519, 0, 0, 0 },
  { GF_SIG_ECDSA_NISTP256, "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256",
    GF_SIG_ECDSA_NISTP256, 0, 0, 0 },
  { GF_SIG_ECDSA_NISTP384, "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384",
    GF_SIG_ECDSA_NISTP384, 0, 0, 0 },
  { GF_SIG_RSA_SHA2_512,   "rsa-sha2-512",        "ssh-rsa",
    GF_SIG_RSA_SHA2_512, 0, 0, 0 },
  { GF_SIG_RSA_SHA2_256,   "rsa-sha2-256",        "ssh-rsa",
    GF_SIG_RSA_SHA2_256, 0, 0, 0 },
  { GF_SIG_ED25519_CERT,   "ssh-ed25519-cert-v01@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com", GF_SIG_ED25519, 1, 0, 0 },
  { GF_SIG_ECDSA_NISTP256_CERT, "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com", GF_SIG_ECDSA_NISTP256, 1, 0, 0 },
  { GF_SIG_ECDSA_NISTP384_CERT, "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com", GF_SIG_ECDSA_NISTP384, 1, 0, 0 },
  { GF_SIG_RSA_SHA2_512_CERT, "rsa-sha2-512-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com", GF_SIG_RSA_SHA2_512, 1, 0, 0 },
  { GF_SIG_RSA_SHA2_256_CERT, "rsa-sha2-256-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com", GF_SIG_RSA_SHA2_256, 1, 0, 0 },
  { GF_SIG_SK_ED25519, "sk-ssh-ed25519@openssh.com",
    "sk-ssh-ed25519@openssh.com", GF_SIG_SK_ED25519, 0, 1, 0 },
  { GF_SIG_SK_ECDSA_NISTP256, "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com", GF_SIG_SK_ECDSA_NISTP256, 0, 1, 0 },
  { GF_SIG_SK_ED25519_CERT, "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com", GF_SIG_SK_ED25519, 1, 1, 0 },
  { GF_SIG_SK_ECDSA_NISTP256_CERT, "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", GF_SIG_SK_ECDSA_NISTP256, 1, 1, 0 },
  { GF_SIG_X509_ECDSA_NISTP256, "x509v3-ecdsa-sha2-nistp256",
    "x509v3-ecdsa-sha2-nistp256", GF_SIG_X509_ECDSA_NISTP256, 0, 0, 1 },
  { GF_SIG_X509_ECDSA_NISTP384, "x509v3-ecdsa-sha2-nistp384",
    "x509v3-ecdsa-sha2-nistp384", GF_SIG_X509_ECDSA_NISTP384, 0, 0, 1 },
  { GF_SIG_X509_RSA2048_SHA256, "x509v3-rsa2048-sha256",
    "x509v3-rsa2048-sha256", GF_SIG_X509_RSA2048_SHA256, 0, 0, 1 }
};

/* Plain algorithms first: a client with no certificate authority to trust
   must not be steered to a certificate by a server that offers both, and
   the X.509 chains, which need a whole PKI to trust, last.  */
static const enum gf_sigalg default_sigs[] = {
  GF_SIG_ED25519,
  GF_SIG_ECDSA_NISTP256,
  GF_SIG_ECDSA_NISTP384,
  GF_SIG_RSA_SHA2_512,
  GF_SIG_RSA_SHA2_256,
  GF_SIG_ED25519_CERT,
  GF_SIG_ECDSA_NISTP256_CERT,
  GF_SIG_ECDSA_NISTP384_CERT,
  GF_SIG_RSA_SHA2_512_CERT,
  GF_SIG_RSA_SHA2_256_CERT,
  GF_SIG_X509_ECDSA_NISTP256,
  GF_SIG_X509_ECDSA_NISTP384,
  GF_SIG_X509_RSA2048_SHA256
};

/* What users may sign with: the plain algorithms, the security keys.  */
static const enum gf_sigalg user_sigs[] = {
  GF_SIG_ED25519,
  GF_SIG_ECDSA_NISTP256,
  GF_SIG_ECDSA_NISTP384,
  GF_SIG_RSA_SHA2_512,
  GF_SIG_RSA_SHA2_256,
  GF_SIG_SK_ED25519,
  GF_SIG_SK_ECDSA_NISTP256
};

struct cipher_entry
{
  enum gf_cipher cipher;
  const char *name;
};

static const struct cipher_entry ciphers[] = {
  { GF_CIPHER_CHACHA20_POLY1305, "chacha20-poly1305@openssh.com" },
  { GF_CIPHER_AES256_GCM,        "aes256-gcm@openssh.com" },
  { GF_CIPHER_AES128_GCM,        "aes128-gcm@openssh.com" }
};

/* ChaCha20-Poly1305 first: it hides the packet length, and is constant
   time in software on a CPU without AES instructions.  */
static const enum gf_cipher default_ciphers[] = {
  GF_CIPHER_CHACHA20_POLY1305,
  GF_CIPHER_AES256_GCM,
  GF_CIPHER_AES128_GCM
};

/* True if the NUL-terminated comma list NAMES has a name of exactly N
   bytes equal to NAME.  */
static int
list_has (const char *names, const char *name, size_t n)
{
  while (*names)
    {
      const char *comma = strchr (names, ',');
      size_t len = comma ? (size_t) (comma - names) : strlen (names);

      if (len == n && memcmp (names, name, n) == 0)
        return 1;
      names += len + (comma ? 1 : 0);
    }
  return 0;
}

const char *
gf_kex_names (enum gf_kex kex)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (kexes); i++)
    if (kexes[i].kex == kex)
      return kexes[i].names;
  return NULL;
}

const char *
gf_kex_name (enum gf_kex kex)
{
  /* The first of the names in the list above.  */
  switch (kex)
    {
    case GF_KEX_CURVE25519_SHA256:	return "curve25519-sha256";
    case GF_KEX_MLKEM768X25519_SHA256:	return "mlkem768x25519-sha256";
    case GF_KEX_MLKEM768NISTP256_SHA256: return "mlkem768nistp256-sha256";
    case GF_KEX_MLKEM1024NISTP384_SHA384: return "mlkem1024nistp384-sha384";
    case GF_KEX_SNTRUP761X25519_SHA512:	return "sntrup761x25519-sha512";
    case GF_KEX_ECDH_NISTP256_SHA256:	return "ecdh-sha2-nistp256";
    case GF_KEX_ECDH_NISTP384_SHA384:	return "ecdh-sha2-nistp384";
    default:				return NULL;
    }
}

enum gf_kex
gf_kex_from_name (const char *name, size_t n)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (kexes); i++)
    if (list_has (kexes[i].names, name, n))
      return kexes[i].kex;
  return 0;
}

const char *
gf_sigalg_name (enum gf_sigalg alg)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (sigs); i++)
    if (sigs[i].alg == alg)
      return sigs[i].name;
  return NULL;
}

const char *
gf_sigalg_key_type (enum gf_sigalg alg)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (sigs); i++)
    if (sigs[i].alg == alg)
      return sigs[i].key_type;
  return NULL;
}

int
gf_sigalg_is_x509 (enum gf_sigalg alg)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (sigs); i++)
    if (sigs[i].alg == alg)
      return sigs[i].x509;
  return 0;
}

int
gf_sigalg_is_user_only (enum gf_sigalg alg)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (sigs); i++)
    if (sigs[i].alg == alg)
      return sigs[i].user_only;
  return 0;
}

int
gf_sigalg_is_cert (enum gf_sigalg alg)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (sigs); i++)
    if (sigs[i].alg == alg)
      return sigs[i].cert;
  return 0;
}

enum gf_sigalg
gf_sigalg_base (enum gf_sigalg alg)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (sigs); i++)
    if (sigs[i].alg == alg)
      return sigs[i].base;
  return alg;
}

const char *
gf_sigalg_signature_name (enum gf_sigalg alg)
{
  /* RFC 6187 section 3: the signature of an X.509 chain names the plain
     signature format of the key in the end certificate, not the "x509v3-"
     algorithm of the key.  */
  switch (alg)
    {
    case GF_SIG_X509_ECDSA_NISTP256:	return "ecdsa-sha2-nistp256";
    case GF_SIG_X509_ECDSA_NISTP384:	return "ecdsa-sha2-nistp384";
    case GF_SIG_X509_RSA2048_SHA256:	return "rsa2048-sha256";
    default:				return gf_sigalg_name (gf_sigalg_base (alg));
    }
}

enum gf_sigalg
gf_sigalg_from_name (const char *name, size_t n)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (sigs); i++)
    if (strlen (sigs[i].name) == n && memcmp (sigs[i].name, name, n) == 0)
      return sigs[i].alg;
  return 0;
}

int
gf_sigalg_matches_key_type (enum gf_sigalg alg, const char *key_type,
                            size_t n)
{
  const char *t = gf_sigalg_key_type (alg);

  return t != NULL && strlen (t) == n && memcmp (t, key_type, n) == 0;
}

const char *
gf_cipher_name (enum gf_cipher cipher)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (ciphers); i++)
    if (ciphers[i].cipher == cipher)
      return ciphers[i].name;
  return NULL;
}

enum gf_cipher
gf_cipher_from_name (const char *name, size_t n)
{
  size_t i;

  for (i = 0; i < ARRAY_LEN (ciphers); i++)
    if (strlen (ciphers[i].name) == n && memcmp (ciphers[i].name, name, n) == 0)
      return ciphers[i].cipher;
  return GF_CIPHER_NONE;
}

const enum gf_kex *
gf_policy_default_kex (size_t *n)
{
  *n = ARRAY_LEN (default_kex);
  return default_kex;
}

const enum gf_sigalg *
gf_policy_default_sigalgs (size_t *n)
{
  *n = ARRAY_LEN (default_sigs);
  return default_sigs;
}

const enum gf_sigalg *
gf_policy_user_sigalgs (size_t *n)
{
  *n = ARRAY_LEN (user_sigs);
  return user_sigs;
}

const enum gf_cipher *
gf_policy_default_ciphers (size_t *n)
{
  *n = ARRAY_LEN (default_ciphers);
  return default_ciphers;
}
