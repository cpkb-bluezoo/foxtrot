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

/* Security policy: the only key exchange methods, host key and signature
   algorithms, ciphers and compression methods foxtrot will ever
   negotiate.

   The lists here are closed.  Anything absent (SSH-1, CBC and CTR
   ciphers, RC4, 3DES, Blowfish, separate MACs of any kind, hmac-sha1,
   finite-field Diffie-Hellman groups and group exchange, SHA-1 anywhere,
   ssh-rsa, ssh-dss, ECDSA over P-521, zlib compression, the "none"
   cipher, "none" authentication of the host) is not a configuration
   option; it is not implemented.  The "Security policy" chapter of the
   manual gives the reasoning behind each choice.

   Algorithm names are the IANA SSH registry names (RFC 4250 section 4.6
   and the later RFCs and drafts that registered them).  */

#ifndef FOXTROT_POLICY_H
#define FOXTROT_POLICY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The only protocol version: RFC 4253 section 4.2 "SSH-2.0-...".  */
#define GF_PROTOCOL_VERSION "2.0"

/* Key exchange methods.  Every one is an ephemeral key agreement in the
   style of RFC 5656 (ECDH_INIT and ECDH_REPLY, or their hybrid names
   KEX_HYBRID_INIT and KEX_HYBRID_REPLY), signed by the server's host
   key.  */
enum gf_kex
{
  GF_KEX_CURVE25519_SHA256 = 1,		/* RFC 8731 */
  GF_KEX_MLKEM768X25519_SHA256,		/* draft-ietf-sshm-mlkem-hybrid-kex */
  GF_KEX_MLKEM768NISTP256_SHA256,	/* same draft */
  GF_KEX_MLKEM1024NISTP384_SHA384,	/* same draft */
  GF_KEX_SNTRUP761X25519_SHA512,	/* draft-ietf-sshm-ntruprime-ssh;
					   also the OpenSSH 9.0 name with
					   "@openssh.com" appended */
  GF_KEX_ECDH_NISTP256_SHA256,		/* RFC 5656 */
  GF_KEX_ECDH_NISTP384_SHA384		/* RFC 5656 */
};

/* Signature algorithms for host keys and for public key authentication.
   Each names a key type and a signature format at once, as SSH does.  */
enum gf_sigalg
{
  GF_SIG_ED25519 = 1,		/* ssh-ed25519, RFC 8709 */
  GF_SIG_ECDSA_NISTP256,	/* ecdsa-sha2-nistp256, RFC 5656 */
  GF_SIG_ECDSA_NISTP384,	/* ecdsa-sha2-nistp384, RFC 5656 */
  GF_SIG_RSA_SHA2_256,		/* rsa-sha2-256, RFC 8332 */
  GF_SIG_RSA_SHA2_512		/* rsa-sha2-512, RFC 8332 */
};

/* Ciphers.  AEAD only: the packet is authenticated by the cipher itself,
   so the MAC lists of KEXINIT are empty and ignored.  */
enum gf_cipher
{
  GF_CIPHER_NONE = 0,		/* Before the first key exchange only.  */
  GF_CIPHER_CHACHA20_POLY1305 = 1,	/* chacha20-poly1305@openssh.com */
  GF_CIPHER_AES256_GCM,		/* aes256-gcm@openssh.com, RFC 5647 */
  GF_CIPHER_AES128_GCM		/* aes128-gcm@openssh.com, RFC 5647 */
};

/* The smallest RSA modulus accepted in a host key or a user key
   (112-bit security, the floor quickstep's trust layer also uses).  */
#define GF_MIN_RSA_BITS 2048

/* Strict key exchange markers (OpenSSH PROTOCOL, "Terrapin" fix).  The
   client adds the first to its key exchange list and the server the
   second; each side requires the other's.  */
#define GF_KEX_STRICT_CLIENT "kex-strict-c-v00@openssh.com"
#define GF_KEX_STRICT_SERVER "kex-strict-s-v00@openssh.com"

/* Extension negotiation (RFC 8308).  */
#define GF_KEX_EXTINFO_CLIENT "ext-info-c"
#define GF_KEX_EXTINFO_SERVER "ext-info-s"

/* Names.  The *_name functions return the preferred name of an algorithm,
   or NULL for an unknown value.  The *_from_name functions take a name of
   N bytes (not NUL-terminated) and return the algorithm, or 0 for
   anything the policy does not permit, including every name that appears
   nowhere in this file.  */
const char *gf_kex_name (enum gf_kex kex);
const char *gf_sigalg_name (enum gf_sigalg alg);
const char *gf_cipher_name (enum gf_cipher cipher);
enum gf_kex gf_kex_from_name (const char *name, size_t n);
enum gf_sigalg gf_sigalg_from_name (const char *name, size_t n);
enum gf_cipher gf_cipher_from_name (const char *name, size_t n);

/* Default preference-ordered lists.  Each returns a static array and
   stores its length in *N.  An application may pass a list of its own
   to a connection (any subset, any order), but only of these.  */
const enum gf_kex *gf_policy_default_kex (size_t *n);
const enum gf_sigalg *gf_policy_default_sigalgs (size_t *n);
const enum gf_cipher *gf_policy_default_ciphers (size_t *n);

/* Key exchange properties.  */
/* The names under which KEX is offered in KEXINIT, comma separated.  */
const char *gf_kex_names (enum gf_kex kex);

/* 1 if the signature algorithm can be made with a key of KEY_TYPE, a key
   type name such as "ssh-ed25519", "ecdsa-sha2-nistp256" or "ssh-rsa" (the
   key type name of an RSA key, which only its signature names refine).  */
int gf_sigalg_matches_key_type (enum gf_sigalg alg, const char *key_type,
                                size_t n);
/* The key type name of an algorithm's keys.  */
const char *gf_sigalg_key_type (enum gf_sigalg alg);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_POLICY_H */
