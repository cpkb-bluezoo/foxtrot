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

/* Authorized keys, in the format of OpenSSH's authorized_keys files.

   The application reads the user's file (this library does no I/O), loads
   its text, and from the request callback of the authentication machine
   (auth.h) asks whether the request's key is one the user has authorized:

     gf_authkeys_check (table, req, address, hostname, now, &match)

   It answers 1 and describes what the line allows in MATCH, or 0.  The
   key is compared, and the line's options are enforced as far as a library
   that does no I/O can enforce them:

     from="PATTERNS"      the client's address (CIDR ranges and wildcards)
                          or host name matches; a '!' excludes.  A pattern
                          for names matches only if the caller says what the
                          client's name is.  The caller must have checked
                          that a name it gives resolves back to the address.
     expiry-time="TIME"   YYYYMMDD[HHMM[SS]][Z], and not good at that time.
                          The time is UTC whether or not Z is written
                          (OpenSSH reads it in the server's time zone).
     cert-authority       the key is a CA: a certificate signed by it is
                          accepted as the user's key, if its dates are good,
                          its source-address (if any) allows the client, and
                          it names the user (or, with principals=, one of
                          the names listed there).
     principals="NAMES"   with cert-authority: the certificate must have
                          one of these principals (patterns with '*' and
                          '?'), whoever the user is.
     verify-required      for a security key: the token verified its user
                          (PIN or biometrics), which is checked once the
                          request has a signature.  The library requires the
                          user's presence whatever "no-touch-required" says.

   and reported, for the application and the session (session.h) to enforce:

     command="COMMAND"    the command to run in place of what the client
                          asks (gf_session_force)
     no-pty, no-port-forwarding, no-agent-forwarding, no-X11-forwarding,
     no-user-rc, restrict, and the positive pty, port-forwarding,
     agent-forwarding, X11-forwarding, user-rc that undo them after a
     restrict: gf_authkey_permits, with the names of key.h
     permitopen="HOST:PORT", permitlisten="[HOST:]PORT": what a user may
                          forward (gf_authkey_permits_open, _listen)
     environment="NAME=VALUE": gf_authkey_next, to be set if the
                          application allows a user to set variables at all

   Options are not case sensitive.  tunnel= and the other options OpenSSH
   has for devices are accepted and mean nothing, since there is no tun
   forwarding.  A line with an option that is not in this list is skipped, as
   OpenSSH does, and so is one that gives from, command, principals or
   expiry-time twice, one whose key is not one the policy accepts (key.h) or
   is a certificate, and one that is malformed: a restriction that is not
   understood is never ignored.  Skipped lines are counted; comment and
   blank lines are not.

   A certificate is only ever accepted through a cert-authority line.  The
   authentication machine, though, takes a certificate only from a CA in its
   configuration (trusted_user_cas), and checks that the user is one of its
   principals unless principals_by_application is set: an application that
   uses these lines for certificates passes gf_authkeys_cas of the global
   file as the CAs, and sets that flag if it uses principals=.

   Threading: a table is not changed by the check functions, so it may be
   shared by readers while nobody loads.  A match points into its table and
   is valid while the table is.  */

#ifndef FOXTROT_AUTHKEYS_H
#define FOXTROT_AUTHKEYS_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/auth.h>
#include <foxtrot/key.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gf_authkeys gf_authkeys;

int gf_authkeys_new (gf_authkeys **out);
void gf_authkeys_free (gf_authkeys *t);

/* Add the lines of TEXT (the contents of an authorized_keys file; the
   table keeps no pointer into it).  *BAD, if not NULL, receives the number
   of lines skipped; the others are in the table.  */
int gf_authkeys_load (gf_authkeys *t, const char *text, size_t len,
                      size_t *bad);

/* The number of keys in the table.  */
size_t gf_authkeys_count (const gf_authkeys *t);

/* The keys of the cert-authority lines, up to CAP of them, for the
   trusted_user_cas of the authentication machine.  Returns the number of
   them (which may be more than CAP).  Owned by the table.  */
size_t gf_authkeys_cas (const gf_authkeys *t, const gf_key **out, size_t cap);

enum gf_authkey_list
{
  GF_AUTHKEY_PERMITOPEN = 1,
  GF_AUTHKEY_PERMITLISTEN,
  GF_AUTHKEY_ENVIRONMENT
};

typedef struct gf_authkey_match
{
  size_t line;			/* The line of the file, from 1, for logs.  */
  int cert_authority;		/* The key was accepted as a CA.  */
  /* NULL, or the command the user must be given instead of anything else
     (NUL-terminated).  */
  const char *command;
  uint64_t expiry;		/* Seconds since 1970, or 0 for none.  */
  const void *entry;		/* Private.  */
} gf_authkey_match;

/* Is the request's key authorized for the request's user?  REQ is a
   GF_AUTH_PUBLICKEY request.  ADDRESS is the client's address in text and
   HOSTNAME its name, either of them NULL if unknown; NOW is wall time in
   seconds since 1970.  Returns 1 with *MATCH set (if not NULL) for the
   first line that authorizes it, 0 if none does, or a negative status for a
   bad argument.  Whether the key is acceptable at all, what its signature
   says and the rest of auth.h's checks have been done by the machine.  */
int gf_authkeys_check (const gf_authkeys *t, const gf_auth_request *req,
                       const char *address, const char *hostname, uint64_t now,
                       gf_authkey_match *match);

/* Does the line allow PERMISSION, one of the GF_CERT_PERMIT_* names of
   key.h?  Any other name is not allowed.  */
int gf_authkey_permits (const gf_authkey_match *m, const char *permission);

/* May the user be given a direct-tcpip channel to HOST:PORT (host names
   compared without regard to case)?  1 if the line has no permitopen.  */
int gf_authkey_permits_open (const gf_authkey_match *m, const char *host,
                             unsigned port);
/* May the user ask for a remote forward to listen on HOST:PORT (HOST is the
   address in the tcpip-forward request, "" or NULL for the default)?  1 if
   the line has no permitlisten.  */
int gf_authkey_permits_listen (const gf_authkey_match *m, const char *host,
                               unsigned port);

/* May the user be given a direct-streamlocal channel to a Unix socket, or
   listen on one (streamlocal-forward)?  A path cannot be named by
   permitopen or permitlisten, which OpenSSH leaves to the permission of
   port forwarding (gf_authkey_permits), but a user who was restricted to
   some hosts and ports should not get at any socket of the machine
   either: so these are 1 only for a line with no permitopen (open) or no
   permitlisten (listen).  A server also asks gf_authkey_permits for
   "permit-port-forwarding", and decides which paths it allows.  */
int gf_authkey_permits_open_path (const gf_authkey_match *m);
int gf_authkey_permits_listen_path (const gf_authkey_match *m);

/* The values of a repeated option of the line, in order: start with
   *POS = 0; each call returns 1 and sets ITEM (not NUL-terminated; valid
   while the table is), or 0 at the end.  */
int gf_authkey_next (const gf_authkey_match *m, enum gf_authkey_list which,
                     size_t *pos, gf_slice *item);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_AUTHKEYS_H */
