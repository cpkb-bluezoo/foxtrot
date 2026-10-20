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

/* Known host keys, in the format of OpenSSH's known_hosts files.

   The application reads the file (this library does no I/O), loads its
   text, and asks about the key a server presented from its host_key
   callback.  What it does with the answer is its own: this module says what
   the file says.

     UNKNOWN   nothing in the file concerns the host
     MATCH     the key is the host's: a line for the host names it, or a
               certificate for the host is signed by a CA the file trusts
               for the host (a "@cert-authority" line), is a host
               certificate in its dates and names the host
     CHANGED   the file knows the host, but not by this key.  This is so
               whatever the types: a host that is known by one key, or by a
               CA, and shows another has given no reason to believe the
               second is its own
     REVOKED   a "@revoked" line names the key, or the CA of a certificate

   A line is "[MARKER] HOSTS KEYTYPE BASE64 [COMMENT]".  HOSTS is a comma
   separated list of patterns in which '*' and '?' are wildcards, a leading
   '!' excludes, and a name for a port other than 22 is written
   "[name]:port"; or one hashed name "|1|salt|hash".  Names are compared
   without regard to case.  A line is skipped, and counted, if it is
   malformed or its key is not one the policy accepts (key.h) or is a
   certificate: such a line cannot make a host known.  Comment lines and
   blank lines are not counted.

   Hashed names are HMAC-SHA-1 of the lower-cased name keyed with the salt.
   This is the one place SHA-1 is used, and only to recognise names in files
   that OpenSSH writes (ssh-keygen -H, HashKnownHosts); it is not a
   signature or a key derivation, and nothing about a key depends on it.

   Threading: a table is not changed by the check functions, so it may be
   shared by readers while nobody loads or adds.  */

#ifndef FOXTROT_KNOWNHOSTS_H
#define FOXTROT_KNOWNHOSTS_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/key.h>
#include <foxtrot/policy.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gf_knownhosts gf_knownhosts;

enum gf_hostcheck
{
  GF_HOST_UNKNOWN = 0,
  GF_HOST_MATCH,
  GF_HOST_CHANGED,
  GF_HOST_REVOKED
};

int gf_knownhosts_new (gf_knownhosts **out);
void gf_knownhosts_free (gf_knownhosts *kh);

/* Add the lines of TEXT (the contents of a known_hosts file; the table
   keeps no pointer into it).  *BAD, if not NULL, receives the number of
   lines skipped; the others are in the table.  May be called again to add
   another file.  */
int gf_knownhosts_load (gf_knownhosts *kh, const char *text, size_t len,
                        size_t *bad);

/* Remember KEY as a key of HOST:PORT, as after the user accepted it, in
   the table only (use gf_knownhosts_format for the file).  PORT 0 is 22.
   KEY must not be a certificate.  */
int gf_knownhosts_add (gf_knownhosts *kh, const char *host, unsigned port,
                       const gf_key *key);

/* What the table says of KEY as the key of HOST:PORT (PORT 0 is 22).  NOW is
   wall time in seconds since 1970, for host certificates.  */
enum gf_hostcheck gf_knownhosts_check (const gf_knownhosts *kh,
                                       const char *host, unsigned port,
                                       const gf_key *key, uint64_t now);

/* The signature algorithms to ask for when connecting to HOST:PORT, so that
   a host known by one kind of key cannot answer with another: those of the
   keys the table has for it, and the certificate algorithms if it has a CA
   for it, in the order of policy.h.  If it knows nothing of the host, the
   whole default list.  Returns the number written to OUT (at most CAP),
   suitable for the sigalgs of gf_kex_prefs.  */
size_t gf_knownhosts_sigalgs (const gf_knownhosts *kh, const char *host,
                              unsigned port, enum gf_sigalg *out, size_t cap);

/* A line for a known_hosts file saying KEY is a key of HOST:PORT, ending in
   a newline and NUL-terminated.  With HASH the name is hashed with a fresh
   salt.  KEY must not be a certificate.  *LEN receives the length without
   the NUL.  */
int gf_knownhosts_format (char *out, size_t cap, size_t *len, const char *host,
                          unsigned port, const gf_key *key, int hash);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_KNOWNHOSTS_H */
