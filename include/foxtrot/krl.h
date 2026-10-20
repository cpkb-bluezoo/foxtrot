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

/* Key revocation lists, in the binary format of OpenSSH (PROTOCOL.krl,
   made by ssh-keygen -k and used by sshd's RevokedKeys).

   The application reads the file (this library does no I/O), loads its
   bytes, and asks of each key it is about to trust whether the list
   revokes it:

     - a key listed in full, or by the SHA-1 or SHA-256 hash of its blob
       (a certificate by the key it certifies, and a certificate is also
       revoked if its CA key is listed so);
     - a certificate, by its serial number or key ID, for the CA that
       signed it or, in a list for no CA in particular, for any.  Serial 0
       is never matched, as no CA that does not number its certificates
       can mean one by it.

   The authentication machine does this for the keys of users if its
   configuration has a list (gf_auth_server_config).  A client checks the
   host key in its host_key callback.

   A list is refused whole if it is malformed, has a section this library
   does not know, a critical extension, a serial number of 0, a range that
   runs backwards or a bitmap that runs past 2^64: a revocation that is not
   understood is never ignored.  So is a list with signature sections, as
   OpenSSH 9.4 and later do (its authors recommend SSHSIG signatures over the
   file instead, for a list fetched over an untrusted channel; nothing here
   verifies where a list came from).

   The hash of SHA-1 sections is the third use of SHA-1 in the library (after
   the hashed names of known_hosts and the OCSP responder names): it only
   recognises a key in files that ssh-keygen -k writes, and could at worst be
   made to revoke a key that was not meant to be.

   Threading: a list is not changed by the check function, so it may be
   shared by readers while nobody loads.  */

#ifndef FOXTROT_KRL_H
#define FOXTROT_KRL_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/key.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The most revocation entries (serial ranges, key IDs, hashes and keys)
   all the lists loaded may hold, and the longest list.  */
#define GF_KRL_MAX_ENTRIES (1u << 22)
#define GF_KRL_MAX_SIZE (64u << 20)

typedef struct gf_krl gf_krl;

int gf_krl_new (gf_krl **out);
void gf_krl_free (gf_krl *k);

/* Add the list in DATA (a whole file; nothing is kept pointing into it).
   Lists add up.  On error (GF_ERR_ENCODING, GF_ERR_UNSUPPORTED for what is
   described above, GF_ERR_RANGE for more than the limits) nothing is
   added.  */
int gf_krl_load (gf_krl *k, const uint8_t *data, size_t len);

/* The number of entries.  */
size_t gf_krl_count (const gf_krl *k);

/* What the list loaded last with the highest version says about itself:
   the version number the maker gave it, the time it was made (seconds
   since 1970) and its comment (valid until the list is freed).  All
   zero and empty if nothing is loaded.  */
typedef struct gf_krl_info
{
  uint64_t version, generated;
  gf_slice comment;
} gf_krl_info;
void gf_krl_get_info (const gf_krl *k, gf_krl_info *info);

/* 1 if KEY (plain, or a user or host certificate) is revoked, 0 if it is
   not, a negative status if that cannot be said (a null argument, or the
   hashes cannot be made): treat anything but 0 as revoked.  */
int gf_krl_check (const gf_krl *k, const gf_key *key);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_KRL_H */
