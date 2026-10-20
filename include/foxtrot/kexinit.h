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

/* SSH_MSG_KEXINIT (RFC 4253 section 7.1) and algorithm negotiation.

   Negotiation is the RFC's rule - the first algorithm of the client's
   list that is also on the server's - restricted to the policy: a name
   that policy.h does not know is never chosen, and cannot be chosen by
   being listed first.  There is no fallback.  What would be
   negotiated elsewhere and is fixed here:

     MAC lists      empty when we send them and ignored when received:
                    every cipher is AEAD (RFC 5647 section 5.1)
     compression    "none" must be listed by the peer
     languages      ignored
     first_kex_packet_follows   we never guess, and refuse a peer that does

   Strict key exchange (OpenSSH PROTOCOL, section "transport: strict key
   exchange extension") is required in the first key exchange: the client
   lists kex-strict-c-v00@openssh.com and the server kex-strict-s-v00@
   openssh.com.  A peer without it is refused rather than served without the
   Terrapin protection.  RFC 8308 extension negotiation (ext-info-c,
   ext-info-s) is noted when offered.  Both markers belong to the first
   KEXINIT only.  */

#ifndef FOXTROT_KEXINIT_H
#define FOXTROT_KEXINIT_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/policy.h>
#include <foxtrot/wire.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GF_MSG_KEXINIT 20

struct gf_kexinit
{
  uint8_t cookie[16];
  gf_slice kex, hostkey;
  gf_slice enc_c2s, enc_s2c;
  gf_slice mac_c2s, mac_s2c;
  gf_slice comp_c2s, comp_s2c;
  gf_slice lang_c2s, lang_s2c;
  int first_kex_follows;
};

/* Parse a KEXINIT payload (starting with the message number).  The slices
   point into PAYLOAD.  Every list must be a valid name-list.  */
int gf_kexinit_parse (const uint8_t *payload, size_t len,
                      struct gf_kexinit *out);

/* What an endpoint offers.  A NULL list means the policy default; a list
   may be any subset, in any order, of what policy.h permits.  A server
   must give the signature algorithms of the host keys it has.  */
struct gf_kex_prefs
{
  const enum gf_kex *kex;
  size_t nkex;
  const enum gf_sigalg *sigalgs;
  size_t nsigalgs;
  const enum gf_cipher *ciphers;
  size_t nciphers;
};

/* Build our KEXINIT, message number included, with a fresh cookie.
   INITIAL is nonzero for the first key exchange of a connection, which
   adds the strict and extension markers.  Returns GF_ERR_UNSUPPORTED if
   PREFS names a value policy does not permit.  */
int gf_kexinit_make (uint8_t *buf, size_t cap, size_t *len, int server,
                     int initial, const struct gf_kex_prefs *prefs);

struct gf_algs
{
  enum gf_kex kex;
  enum gf_sigalg hostkey;
  enum gf_cipher c2s, s2c;
  int ext_info;			/* The peer can send/receive SSH_MSG_EXT_INFO.  */
};

/* Choose the algorithms from the client's and the server's KEXINIT.
   Returns GF_OK; GF_ERR_UNSUPPORTED when nothing is in common (or
   compression cannot be turned off); GF_ERR_PROTOCOL when the peer
   guessed (first_kex_follows) or, if INITIAL, lacks strict key exchange.  */
int gf_kexinit_negotiate (const struct gf_kexinit *client,
                          const struct gf_kexinit *server, int initial,
                          struct gf_algs *out);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_KEXINIT_H */
