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

/* Host keys and user keys: SSH public key blobs (RFC 4253 section 6.6),
   signatures, and the unencrypted OpenSSH private key file format.

   Key types are Ed25519, ECDSA over NIST P-256 and P-384, and RSA of at
   least GF_MIN_RSA_BITS bits.  Everything is libgcrypt's; no X.509 is
   involved (RFC 6187 keys, if they come, will sit behind the same
   interface with the GnuTLS backend).

   What is refused, and where:
     - gf_key_from_blob refuses an RSA key under GF_MIN_RSA_BITS or over
       16384 bits, one with a public exponent under 65537 or even, an
       ECDSA point that is not on its curve or not in uncompressed form,
       and every key type not listed above (ssh-dss, ECDSA over P-521).
       Security keys (FIDO) are accepted for verification only, with an
       application beginning "ssh:".
     - gf_key_verify and gf_key_sign take the signature algorithm
       explicitly and refuse "ssh-rsa" (RSA with SHA-1): an RSA key signs
       with rsa-sha2-256 or rsa-sha2-512 only, and the signature blob must
       name the algorithm that was negotiated.
     - Ed25519 signatures with a non-canonical S are rejected.  */

#ifndef FOXTROT_KEY_H
#define FOXTROT_KEY_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gf_keytype
{
  GF_KEY_ED25519 = 1,
  GF_KEY_ECDSA_P256,
  GF_KEY_ECDSA_P384,
  GF_KEY_RSA
};

#define GF_RSA_MAX_BITS 16384

typedef struct gf_key gf_key;

/* Generate a key.  BITS is used for RSA only (at least GF_MIN_RSA_BITS,
   default 3072 if 0).  */
int gf_key_generate (gf_key **out, enum gf_keytype type, unsigned bits);

/* Parse a public key blob.  The result has no private part.  */
int gf_key_from_blob (gf_key **out, const uint8_t *blob, size_t len);

/* Read an unencrypted OpenSSH private key file ("-----BEGIN OPENSSH
   PRIVATE KEY-----", the format of ssh-keygen -N ''), given as text.
   A passphrase-protected key is refused with GF_ERR_UNSUPPORTED; see
   gf_key_from_openssh_private_encrypted.  */
int gf_key_from_openssh_private (gf_key **out, const char *text, size_t len);

/* The one-line text form of a public key, as in ssh-keygen's .pub files and
   (without options) authorized_keys: "TYPE BASE64 [COMMENT]".  Blanks before
   and a line end after are allowed, and nothing after that.  TYPE must be the
   name inside the key; the base64 must be exact (padded, no stray bits).
   Refused as gf_key_from_blob refuses.  If COMMENT is not NULL it is set to
   the comment, which points into TEXT (empty if there is none).  */
int gf_key_from_text (gf_key **out, const char *text, size_t len,
                      gf_slice *comment);
/* Write "TYPE BASE64" and a NUL, without a comment or a line end.  OUTLEN, if
   not NULL, receives the length without the NUL.  */
int gf_key_to_text (const gf_key *key, char *out, size_t cap, size_t *outlen);

/* ---- Passphrase-protected private key files ----

   OpenSSH encrypts a private key file with a key derived from the
   passphrase by bcrypt-pbkdf (OpenBSD's, from the bcrypt password hash),
   which libgcrypt does not have and which this library does not implement:
   the application supplies it.  KDF is called with the passphrase, the
   file's salt and round count (1 to GF_KDF_MAX_ROUNDS), and must write
   OUTLEN bytes (the cipher's key and then its IV, at most 48) to OUT, as
   bcrypt_pbkdf(passphrase, salt, rounds, out, outlen) of OpenBSD's libc,
   OpenSSH's openbsd-compat and libbcrypt do.  Return 0 for success.  The
   passphrase is not copied and not kept; the output is wiped after use.

   The file ciphers are aes128-ctr, aes192-ctr, aes256-ctr, which
   ssh-keygen uses by default, and aes128-gcm@openssh.com and
   aes256-gcm@openssh.com, which it can; the other ciphers it knows
   (CBC, 3DES, ChaCha20) are refused.  Counter mode does not authenticate
   the file: a wrong passphrase is told by two check values in the
   plaintext, and a file damaged on the disk by nothing (it is the owner's to
   protect, not the network's).  GCM does, and then a wrong passphrase or a
   damaged file fails its tag.  Both give GF_ERR_PASSPHRASE.  */
#define GF_KDF_MAX_ROUNDS 10000

typedef int (*gf_bcrypt_pbkdf_fn) (void *user, const uint8_t *passphrase,
                                   size_t passlen, const uint8_t *salt,
                                   size_t saltlen, uint32_t rounds,
                                   uint8_t *out, size_t outlen);

/* As gf_key_from_openssh_private, for a file that may be encrypted.  For
   an unencrypted file PASSPHRASE and KDF are not used.  An encrypted file
   with no passphrase or no KDF is refused with GF_ERR_UNSUPPORTED, a wrong
   passphrase gives GF_ERR_PASSPHRASE, and a KDF that fails
   GF_ERR_HANDLER.  */
int gf_key_from_openssh_private_encrypted (gf_key **out, const char *text,
                                           size_t len, const char *passphrase,
                                           gf_bcrypt_pbkdf_fn kdf, void *user);

/* Write the key encrypted with PASSPHRASE: aes256-gcm@openssh.com, a
   random 16-byte salt, ROUNDS (0: 16, as ssh-keygen -a) of bcrypt-pbkdf by
   KDF.  OpenSSH 7.x and later read the result.  Otherwise as
   gf_key_to_openssh_private.  */
int gf_key_to_openssh_private_encrypted (const gf_key *key, char *out,
                                         size_t cap, size_t *outlen,
                                         const char *passphrase,
                                         uint32_t rounds,
                                         gf_bcrypt_pbkdf_fn kdf, void *user);

/* Write the private key in the same format, as PEM text.  */
int gf_key_to_openssh_private (const gf_key *key, char *out, size_t cap,
                               size_t *outlen);

void gf_key_free (gf_key *key);

enum gf_keytype gf_key_type (const gf_key *key);
unsigned gf_key_bits (const gf_key *key);
int gf_key_has_private (const gf_key *key);
/* The name in the key blob: "ssh-ed25519", "ecdsa-sha2-nistp256",
   "ecdsa-sha2-nistp384" or "ssh-rsa".  */
const char *gf_key_type_name (const gf_key *key);
/* The signature algorithms the key can make, in preference order.  *N
   receives the count.  */
const enum gf_sigalg *gf_key_sigalgs (const gf_key *key, size_t *n);

/* The public key blob.  The pointer is valid until the key is freed.  */
const uint8_t *gf_key_blob (const gf_key *key, size_t *len);

/* "SHA256:" and the unpadded base64 of the SHA-256 of the blob, as
   ssh-keygen -l prints it.  A certificate has the fingerprint of the key
   it certifies (gf_key_plain_blob), as with ssh-keygen.  CAP must be at
   least 51.  */
int gf_key_fingerprint (const gf_key *key, char *out, size_t cap);

/* 1 if the two keys have the same public part.  */
int gf_key_equal (const gf_key *a, const gf_key *b);

/* Sign DATA with ALG.  The signature blob (RFC 4253 section 6.6: string
   algorithm name, string signature) is written to OUT.  The key must
   have a private part and ALG must belong to its type.  */
int gf_key_sign (const gf_key *key, enum gf_sigalg alg, const uint8_t *data,
                 size_t len, uint8_t *out, size_t cap, size_t *outlen);

/* Verify a signature blob on DATA.  The blob must carry the name of ALG.
   Returns GF_OK, or GF_ERR_HOSTKEY for a signature that does not verify
   or is malformed.  */
int gf_key_verify (const gf_key *key, enum gf_sigalg alg, const uint8_t *data,
                   size_t len, const uint8_t *sig, size_t siglen);

/* ---- FIDO security keys (PROTOCOL.u2f) ----

   A security key signs on a token held by its user, and the library never
   talks to one: these keys exist here to be verified, by a server that
   authenticates users.  "sk-ssh-ed25519@openssh.com" and
   "sk-ecdsa-sha2-nistp256@openssh.com" keys are an Ed25519 or P-256 key
   with an application string, which must begin "ssh:".  Their signatures
   carry a flags byte and a counter after the signature itself, and sign
   SHA256(application) || flags || counter || SHA256(message), so that a
   signature can not be taken from one relying party to another.  They can
   not be generated, read from a private key file or used to sign here, and
   are never host keys.  A signature made with the token's "user presence"
   flag clear is not accepted. */

#define GF_SK_USER_PRESENT 0x01
#define GF_SK_USER_VERIFIED 0x04

int gf_key_is_security_key (const gf_key *key);
/* The application of a security key (not NUL-terminated), or NULL.  */
const uint8_t *gf_key_application (const gf_key *key, size_t *len);
/* Verify a security key's signature as gf_key_verify does and report its
   flags and counter (either may be NULL).  The user presence flag must be
   set, or the signature is refused.  The counter is not checked: it only
   means something to a server that remembers the last one.  */
int gf_key_verify_sk (const gf_key *key, enum gf_sigalg alg,
                      const uint8_t *data, size_t len, const uint8_t *sig,
                      size_t siglen, uint8_t *flags, uint32_t *counter);

/* ---- OpenSSH certificates (PROTOCOL.certkeys) ----

   A certificate is a public key signed by a certificate authority (a CA
   key) with the names it may be used for and the times it is good for.
   gf_key_from_blob accepts the certificate blob types for Ed25519, ECDSA
   and RSA keys and returns the certificate as a key: its blob is the
   certificate, its type name the certificate's ("ssh-ed25519-cert-v01@
   openssh.com"), and it signs and verifies with the algorithms of
   policy.h that name certificates.  It is refused if its structure is
   malformed (options not in order, a bad type), if the key inside it
   or the CA key is one the policy refuses, or if the CA's signature over it
   does not verify.  A CA that signed with SHA-1 ("ssh-rsa") is refused.

   That the signature verifies shows only that the certificate is what the
   CA made.  Whether to trust the CA, the principals, the times and the
   options is for gf_cert_check and the caller: nothing here trusts anything.  */

#define GF_CERT_USER 1
#define GF_CERT_HOST 2

typedef struct gf_cert_info
{
  uint64_t serial;
  int type;			/* GF_CERT_USER or GF_CERT_HOST.  */
  gf_slice key_id;
  uint64_t valid_after, valid_before;	/* Seconds since 1970; 0 and 2^64-1
					   are "always".  */
  const gf_key *ca;		/* Owned by the certificate.  */
} gf_cert_info;

int gf_key_is_certificate (const gf_key *key);
int gf_key_certificate_info (const gf_key *cert, gf_cert_info *info);
/* The plain key inside a certificate (same key without the wrapper), as a
   blob.  For a plain key, its own blob.  */
const uint8_t *gf_key_plain_blob (const gf_key *key, size_t *len);

/* Iterate the principals, the critical options and the extensions of a
   certificate: start with *POS = 0; each call returns 1 and advances, or 0
   at the end.  */
int gf_cert_principal_next (const gf_key *cert, size_t *pos, gf_slice *name);
int gf_cert_critical_next (const gf_key *cert, size_t *pos, gf_slice *name,
                           gf_slice *data);
int gf_cert_extension_next (const gf_key *cert, size_t *pos, gf_slice *name,
                            gf_slice *data);

/* 1 if the certificate has the extension NAME.  A user certificate says what
   it permits by having extensions, so a restriction is an extension that is
   missing: ssh-keygen's default has all five of these, and
   "ssh-keygen -O clear" has none.  The session enforces them for a server
   (session.h); an application that does not use the session has to ask.  */
#define GF_CERT_PERMIT_PTY "permit-pty"
#define GF_CERT_PERMIT_PORT_FORWARDING "permit-port-forwarding"
#define GF_CERT_PERMIT_AGENT_FORWARDING "permit-agent-forwarding"
#define GF_CERT_PERMIT_X11_FORWARDING "permit-X11-forwarding"
#define GF_CERT_PERMIT_USER_RC "permit-user-rc"
int gf_cert_has_extension (const gf_key *cert, const char *name);

/* 1 if NAME is one of the principals.  With WILDCARDS, a principal may
   contain '*' and '?', as host certificates do.  A certificate with no
   principals names nobody here.  */
int gf_cert_has_principal (const gf_key *cert, const char *name, size_t n,
                           int wildcards);

/* Is the certificate usable now, as a certificate of TYPE?  NOW is wall
   time in seconds since 1970.  GF_OK, or GF_ERR_HOSTKEY with *WHY (if not
   NULL) a short reason: wrong type, not yet valid, expired, a critical
   option on a host certificate, a critical option this library does not
   know.  The known critical options of a user certificate are
   "force-command", "source-address" and "verify-required"; honouring them is
   the caller's (see auth.h), and a "force-command" or "source-address"
   that is empty or not a single string is refused here.  */
int gf_cert_check (const gf_key *cert, int type, uint64_t now,
                   const char **why);

/* The value of the critical option NAME of a user certificate: the string
   inside its data ("force-command" is the command, "source-address" a
   comma-separated list of addresses and CIDR ranges).  Returns 1 with
   *VALUE (valid while the certificate is) if present, 0 if absent, and -1
   if present but malformed.  */
int gf_cert_critical_option (const gf_key *cert, const char *name,
                             gf_slice *value);

/* Does the certificate's "source-address" option, if it has one, allow
   ADDRESS (the client's address in text, IPv4 or IPv6; an IPv4-mapped
   IPv6 address counts as the IPv4 one)?  1 if there is no such option.
   If there is one and ADDRESS is NULL or not an address, or the option is
   malformed, 0: an address restriction that cannot be checked is not met.  */
int gf_cert_source_address_ok (const gf_key *cert, const char *address);

/* Attach CERT to KEY, which must have a private part and be the certificate's
   own key.  The result is a key that presents the certificate and signs for
   it; KEY is unchanged.  */
int gf_key_with_certificate (const gf_key *key, const gf_key *cert,
                             gf_key **out);

/* Largest signature blob a key of this size makes.  */
#define GF_SIG_MAX (4 + 19 + 4 + GF_RSA_MAX_BITS / 8)

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_KEY_H */
