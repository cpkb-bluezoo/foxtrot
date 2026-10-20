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

/* X.509 certificate chains as keys (RFC 6187), through GnuTLS.

   A key of type x509v3-ecdsa-sha2-nistp256, x509v3-ecdsa-sha2-nistp384 or
   x509v3-rsa2048-sha256 is a chain of certificates, the end certificate
   first, with the signatures of the key in the end certificate: the blob
   (gf_key_from_blob) is the RFC 6187 public key format.  It is a key like
   any other to the transport and the authentication layer, and, like an
   OpenSSH certificate, only shows what its holder claims until the
   application has asked this module whether to believe it.

   What is not here, on purpose: x509v3-ssh-rsa (its signature is
   SHA-1) and x509v3-ssh-dss, the P-521 curve, keys the policy would not
   take outside a certificate (RSA under 2048 bits), and any chain that
   GnuTLS finds to be signed with an algorithm it considers broken.
   OCSP responses that come with the chain are parsed and ignored:
   revocation is checked against the CRLs the application gives the trust
   store, and nothing is fetched from anywhere.

   Without GnuTLS (configure --without-gnutls) these keys are not
   available and every function here returns GF_ERR_UNAVAILABLE.  */

#ifndef FOXTROT_X509_H
#define FOXTROT_X509_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/key.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The end certificate of KEY, and so on up the chain, as DER; the pointer is
   valid until the key is freed.  A key that is not an X.509 chain has none
   (0 certificates).  */
size_t gf_x509_chain_length (const gf_key *key);
int gf_x509_chain_cert (const gf_key *key, size_t index, const uint8_t **der,
                        size_t *len);

/* The key with the chain attached: KEY must have a private part, be an
   ECDSA P-256, ECDSA P-384 or RSA (at least 2048 bits) key, and be the key in
   the first certificate.  The certificates are DER, end certificate first
   and each issued by the next; at most 8.  The result presents the chain and
   signs with KEY's private part under the matching x509v3 algorithm.  */
int gf_key_with_x509 (const gf_key *key, const uint8_t *const *certs,
                      const size_t *lens, size_t n, gf_key **out);

/* Trust: the certificate authorities that may stand at the top of a chain,
   and the revocation lists of them.  Nothing is trusted by default and
   nothing is read from the system.  */
typedef struct gf_x509_trust gf_x509_trust;

int gf_x509_trust_new (gf_x509_trust **out);
void gf_x509_trust_free (gf_x509_trust *t);
/* A CA certificate, DER.  */
int gf_x509_trust_add_ca (gf_x509_trust *t, const uint8_t *der, size_t len);
/* A CRL, DER.  Its signature is checked against the CAs added so far, so add
   these after them; one by a CA that is not trusted is refused.  */
int gf_x509_trust_add_crl (gf_x509_trust *t, const uint8_t *der, size_t len);

#define GF_X509_SERVER 1	/* A host's chain: id-kp-secureShellServer.  */
#define GF_X509_CLIENT 2	/* A user's: id-kp-secureShellClient.  */

/* Does the trust store vouch for the chain of KEY, for PURPOSE, at NOW (seconds
   since 1970)?  GF_OK, or GF_ERR_HOSTKEY with *WHY (if not NULL) a short
   reason.  The checks, all of which must pass:

     - the chain leads from the end certificate, each issued by the next,
       to a CA in the store, none of them signed with MD5 or SHA-1 and none
       of them a key weaker than 112 bits;
     - every certificate, the CA's too, is in its dates at NOW;
     - none is on a CRL of the store;
     - if a certificate has an extended key usage, it allows the purpose (the
       secure shell server or client OID of RFC 6187; "any" and the
       TLS server and client OIDs do not count);
     - the end certificate's key usage, if it has one, includes
       digitalSignature;
     - for GF_X509_SERVER with a NAME, one of the certificate's subject
       alternative names is that host: a dNSName, with a "*." wildcard for one
       label, or an iPAddress.  The common name is not looked at.  Without a
       NAME this is not checked, as for a user.

   Which user the chain's subject is, is for the application: see
   gf_x509_subject and gf_x509_san.  */
int gf_x509_verify (const gf_x509_trust *t, const gf_key *key, int purpose,
                    const char *name, uint64_t now, const char **why);

/* The subject of the end certificate as an RFC 4514 string (UTF-8,
   NUL-terminated).  */
int gf_x509_subject (const gf_key *key, char *out, size_t cap);

/* The subject alternative names of the end certificate, one at a time:
   start with *POS = 0.  Returns 1 and the type and the name (NUL-terminated
   text), or 0 at the end.  Names of other kinds are skipped.  */
#define GF_X509_SAN_DNS 1
#define GF_X509_SAN_EMAIL 2
#define GF_X509_SAN_URI 3
#define GF_X509_SAN_IP 4
#define GF_X509_SAN_UPN 5	/* Microsoft user principal name.  */
int gf_x509_san (const gf_key *key, size_t *pos, int *type, char *out,
                 size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_X509_H */
