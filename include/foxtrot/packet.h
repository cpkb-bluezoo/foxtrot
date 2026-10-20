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

/* The SSH binary packet protocol (RFC 4253 section 6), for the AEAD
   ciphers of the policy.

   A gf_packet holds the current read and write protection state and
   nothing else: no buffers, no allocation.  Before the first NEWKEYS a
   direction is plaintext (the key exchange itself travels unprotected);
   afterwards every packet is sealed by one of

     chacha20-poly1305@openssh.com   (OpenSSH PROTOCOL.chacha20poly1305:
                                      the length is encrypted too, by a
                                      second ChaCha20 key)
     aes256-gcm@openssh.com, aes128-gcm@openssh.com
                                     (RFC 5647: the length is the
                                      associated data and travels in the
                                      clear)

   Installing new keys is how NEWKEYS is expressed.  With strict key
   exchange (see policy.h) the sequence number of the direction is reset
   to zero then; the sequence number otherwise runs for the whole
   connection, and no direction may let it wrap: when it reaches 2^32 - 1
   protection and parsing both fail with GF_ERR_RANGE, so a connection must
   rekey long before (conn.h does).

   Reading is a push parser in the style of the rest of the library: hand
   it a buffer holding the stream so far; it consumes whole packets,
   decrypting them in place, and stops at a partial packet (GF_NEED_MORE,
   buffer left at the start of that packet).  A packet is all-or-nothing:
   nothing is delivered before the tag has been verified.  The length field
   is checked as soon as it is readable, so a bogus length is refused
   before any of the packet it announces has to arrive.  Each packet is
   delivered as an event: a slice of the (now plaintext) buffer holding the
   payload, without padding.  The callback may install new keys with
   gf_packet_set_keys; they apply from the next packet.

   Writing takes one payload and produces one packet, with random
   padding.  */

#ifndef FOXTROT_PACKET_H
#define FOXTROT_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include <foxtrot/policy.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest packet this implementation reads or writes, counting the length
   field, padding and tag (RFC 4253 section 6.1).  */
#define GF_MAX_PACKET 35000
/* The largest payload that every implementation must handle.  */
#define GF_MAX_PAYLOAD 32768
/* Most that gf_packet_send adds to a payload: length field, padding length
   byte, up to 19 bytes of padding, and a 16-byte tag.  */
#define GF_PKT_OVERHEAD 40
#define GF_TAG_LEN 16

enum gf_dir
{
  GF_DIR_READ = 1,
  GF_DIR_WRITE
};

struct gf_pkt_dir
{
  enum gf_cipher cipher;
  uint8_t key[64];
  size_t keylen;
  uint8_t iv[12];		/* AES-GCM: fixed part and invocation counter.  */
  uint32_t seq;			/* Packets so far, mod 2^32 unless reset.  */
  uint64_t packets;		/* Packets since these keys were installed.  */
  uint64_t bytes;		/* Bytes of packets since then.  */
};

typedef struct gf_packet
{
  struct gf_pkt_dir read, write;
} gf_packet;

/* Key and IV lengths a cipher takes from the key derivation (RFC 4253
   section 7.2), and its block size for padding.  0 for GF_CIPHER_NONE or
   unknown.  */
size_t gf_cipher_key_len (enum gf_cipher cipher);
size_t gf_cipher_iv_len (enum gf_cipher cipher);
size_t gf_cipher_block_len (enum gf_cipher cipher);

/* Both directions plaintext, sequence numbers zero.  */
void gf_packet_init (gf_packet *p);
/* Wipe the keys.  */
void gf_packet_wipe (gf_packet *p);

/* Install keys for DIR.  KEY and IV are as derived: gf_cipher_key_len and
   gf_cipher_iv_len bytes.  If RESET_SEQ is nonzero the direction's
   sequence number restarts at zero (strict key exchange).  */
int gf_packet_set_keys (gf_packet *p, enum gf_dir dir, enum gf_cipher cipher,
                        const uint8_t *key, size_t keylen,
                        const uint8_t *iv, size_t ivlen, int reset_seq);

/* Sequence number of the next packet in DIR.  */
uint32_t gf_packet_seq (const gf_packet *p, enum gf_dir dir);
/* Packets and bytes since the keys of DIR were installed.  */
uint64_t gf_packet_count (const gf_packet *p, enum gf_dir dir);
uint64_t gf_packet_bytes (const gf_packet *p, enum gf_dir dir);

/* Seal PAYLOAD (LEN bytes, at least 1) into OUT (CAP bytes; LEN +
   GF_PKT_OVERHEAD always suffices) and store the packet's size in *OUTLEN.
   The padding is random.  */
int gf_packet_send (gf_packet *p, const uint8_t *payload, size_t len,
                    uint8_t *out, size_t cap, size_t *outlen);

/* As gf_packet_send with the padding given: PADLEN bytes (at least 4)
   such that the packet has the required alignment.  For known-answer
   tests.  */
int gf_packet_send_padded (gf_packet *p, const uint8_t *payload, size_t len,
                           const uint8_t *padding, size_t padlen,
                           uint8_t *out, size_t cap, size_t *outlen);

/* Event handler: one decrypted payload.  Return 0 to continue, nonzero to
   stop (gf_packet_receive then returns GF_ERR_HANDLER with the buffer
   positioned after this packet).  */
typedef int (*gf_packet_cb) (void *user, const uint8_t *payload, size_t len);

/* Parse packets from *BUF (*LEN bytes), calling CB for each, and advance
   *BUF and *LEN past every packet consumed.  The buffer is modified
   (decrypted in place).  Returns:

     GF_OK           everything was consumed; *LEN is 0
     GF_NEED_MORE    the rest is part of an incomplete packet (*LEN > 0)
     GF_ERR_ENCODING a length or padding field is invalid
     GF_ERR_CRYPTO   the tag does not verify
     GF_ERR_RANGE    the sequence number would wrap
     GF_ERR_HANDLER  CB stopped parsing

   After an error the connection must be closed.  */
int gf_packet_receive (gf_packet *p, uint8_t **buf, size_t *len,
                       gf_packet_cb cb, void *user);

#ifdef __cplusplus
}
#endif

#endif /* FOXTROT_PACKET_H */
