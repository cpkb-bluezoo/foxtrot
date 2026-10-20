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

/* Other formats of keys than OpenSSH's own (key.h): RFC 4716 public key
   files, the PEM and DER forms that OpenSSL and others write (SPKI and
   PKCS#1 public keys, PKCS#8, PKCS#1 and SEC1 private keys, and PKCS#8 under
   a passphrase), PuTTY's .ppk files, and the randomart picture of a key.

   Like everything here these are I/O free: the application reads the file
   and passes its text.  Keys are Ed25519, ECDSA over P-256 and P-384, and
   RSA, and are held to the policy of key.h as if they had come in a blob.

   What is refused, with GF_ERR_UNSUPPORTED:
     - the old PEM encryption ("Proc-Type: 4,ENCRYPTED"), whose key is made
       with one round of MD5 from the passphrase and the IV;
     - PKCS#8 under PBES1 (MD5 or SHA-1 with DES or RC2), or PBES2 with a
       PBKDF2 whose hash is SHA-1 (the default if none is named) or a cipher
       other than AES-CBC;
     - PuTTY files of format 1 and 2, whose passphrase becomes a key through
       SHA-1 and whose MAC is HMAC-SHA-1 (puttygen can write version 3 of a
       key it reads);
     - DSA and ECDSA over P-521, and an ECDSA key that is not on a named
       curve, as everywhere in the library.
   Work factors a file asks for are bounded (key.h's rounds, below), so that
   a file cannot make a reader spend minutes or gigabytes.

   A passphrase that is wrong, or a file that the passphrase decrypts to
   nonsense, is GF_ERR_PASSPHRASE; so is an encrypted file and no
   passphrase.  The private parts of a key are checked against the public
   part, whatever the file says.  Buffers that held a private key are wiped.  */

#ifndef FOXTROT_KEYFMT_H
#define FOXTROT_KEYFMT_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/key.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- RFC 4716 public key files ----

   "---- BEGIN SSH2 PUBLIC KEY ----", headers ("Subject:" and "Comment:" are
   understood and the others ignored; a value may continue on the next line
   after a backslash), the key blob in base64, and the END line.  This is
   what ssh-keygen -e writes by default.  Certificates are refused.  If
   COMMENT is not NULL it receives the Comment header (up to CAP bytes, NUL
   terminated, quotes removed), else "".  */
int gf_key_from_rfc4716 (gf_key **out, const char *text, size_t len,
                         char *comment, size_t cap);
/* The file for KEY, with a Comment header if COMMENT is not NULL.  Lines
   are as ssh-keygen -e makes them.  OUT is NUL-terminated; *LEN receives its
   length without the NUL.  */
int gf_key_to_rfc4716 (const gf_key *key, const char *comment, char *out,
                       size_t cap, size_t *len);

/* ---- PEM ----

   One PEM block whose label is
     PUBLIC KEY             an SPKI (what openssl pkey -pubout writes)
     RSA PUBLIC KEY         a PKCS#1 RSAPublicKey
     PRIVATE KEY            PKCS#8, unencrypted (also its version 2 form
                            with the public key in it)
     ENCRYPTED PRIVATE KEY  PKCS#8 under PBES2: PBKDF2 with SHA-256, -384 or
                            -512 and AES-128, -192 or -256 in CBC mode, with
                            at most 5,000,000 iterations
     RSA PRIVATE KEY        PKCS#1
     EC PRIVATE KEY         SEC1, which must carry the public point
   The private forms of ECDSA must carry the public point (every writer
   does); an Ed25519 key's public key is computed from its seed.  PASSPHRASE
   may be NULL for the others.  A private key read is a private key with its
   public part.  */
int gf_key_from_pem (gf_key **out, const char *text, size_t len,
                     const char *passphrase);
/* The "PUBLIC KEY" block (SPKI) for KEY, as openssl pkey -pubout writes it.
   OUT is NUL-terminated; *LEN receives its length without the NUL.  */
int gf_key_to_pem_public (const gf_key *key, char *out, size_t cap,
                          size_t *len);

/* ---- PuTTY ----

   A .ppk file of format 3, unencrypted or under AES-256-CBC with a key made
   by Argon2 (all three variants) of at most 512 MiB, 1000 passes and 16
   lanes, with the MAC checked.  If COMMENT is not NULL it receives the
   file's comment as for RFC 4716.  */
int gf_key_from_ppk (gf_key **out, const char *text, size_t len,
                     const char *passphrase, char *comment, size_t cap);

/* ---- Picture ----

   The randomart image of the SHA-256 fingerprint of KEY (a certificate has
   the one of the key it certifies), the one ssh-keygen -lv prints: nine
   lines of 19 characters, each ending in a newline, the first and last
   being the border with the key type and size and "[SHA256]".  OUT is
   NUL-terminated; *LEN receives its length without the NUL.  The least CAP
   is 200.  */
int gf_key_randomart (const gf_key *key, char *out, size_t cap, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_KEYFMT_H */
