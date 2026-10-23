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

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/ident.h>
#include <foxtrot/kex.h>
#include <foxtrot/conn.h>

#define DEFAULT_REKEY_BYTES (UINT64_C (1) << 30)
#define DEFAULT_REKEY_PACKETS (UINT64_C (1) << 28)
#define DEFAULT_REKEY_INTERVAL_US (UINT64_C (3600) * 1000000)
#define DEFAULT_KEX_TIMEOUT_US (UINT64_C (60) * 1000000)

/* Largest KEXINIT we accept from a peer, and most we hold back while a
   key exchange is under way.  */
#define MAX_PEER_KEXINIT 16384
#define MAX_PENDING (1024 * 1024)

#define SERVICE_USERAUTH "ssh-userauth"

enum state
{
  ST_NEW,			/* gf_conn_start not called.  */
  ST_IDENT,			/* Waiting for the peer's identification.  */
  ST_PACKETS,			/* Binary packets.  */
  ST_CLOSED
};

struct pending_keys
{
  int present;
  enum gf_cipher cipher;
  uint8_t key[64];
  size_t keylen;
  uint8_t iv[12];
  size_t ivlen;
};

struct gf_conn
{
  int server;
  gf_conn_config cfg;
  gf_conn_events ev;
  enum state st;
  uint64_t now;

  uint8_t ident_ours[GF_IDENT_MAX + 1];
  size_t ident_ours_len;	/* Without CR LF.  */
  gf_ident ident_peer;
  gf_packet pkt;

  uint8_t *rbuf;
  size_t rlen, rcap;
  uint8_t *wbuf;
  size_t wcap;

  /* Key exchange.  */
  int established;
  int kex_active;
  int first_kex;
  int sent_kexinit, got_kexinit, sent_newkeys, got_newkeys;
  int kex_done_msg;		/* Our INIT (client) or REPLY (server) is out.  */
  uint8_t *our_kexinit;
  size_t our_kexinit_len;
  uint8_t *peer_kexinit;
  size_t peer_kexinit_len;
  struct gf_algs algs;
  int peer_ext_info;
  gf_kex_client *kexc;
  uint8_t init[GF_KEX_MAX_INIT];
  size_t init_len;
  struct pending_keys read_keys;
  uint8_t session_id[GF_KEX_MAX_HASH];
  size_t sid_len;
  uint8_t host_sig[GF_SIG_MAX];	/* The host key's signature of the first H.  */
  size_t host_sig_len;
  gf_key *peer_key;		/* Client: the server's host key.  */
  const gf_key *sign_key;	/* Server: the key used.  */
  gf_conn_info info;
  int ext_window;		/* EXT_INFO may be the next packet.  */
  int authed;			/* The layer above says the user is in.  */

  uint64_t kex_deadline, rekey_due;

  /* Application messages held during a key exchange: u32 length, bytes.  */
  uint8_t *pend;
  size_t pend_len, pend_cap;

  int fatal;			/* Status that ended the connection.  */
  uint32_t reason;		/* Disconnect reason to send or received.  */
  gf_slice peer_text;
  int closed_called;
  int in_event;
};

/* ------------------------------------------------------------------ */
/* Plumbing                                                           */
/* ------------------------------------------------------------------ */

#define FAIL(c, status, why) \
  do { (c)->reason = (why); return (status); } while (0)

static int
grow (uint8_t **buf, size_t *cap, size_t need)
{
  uint8_t *p;
  size_t n = *cap ? *cap : 1024;

  if (need <= *cap)
    return GF_OK;
  while (n < need)
    n *= 2;
  p = realloc (*buf, n);
  if (p == NULL)
    return GF_ERR_NOMEM;
  *buf = p;
  *cap = n;
  return GF_OK;
}

/* Seal and write one packet.  */
static int
send_packet (gf_conn *c, const uint8_t *payload, size_t len)
{
  size_t outlen;
  int r = grow (&c->wbuf, &c->wcap, len + GF_PKT_OVERHEAD);

  if (r != GF_OK)
    return r;
  r = gf_packet_send (&c->pkt, payload, len, c->wbuf, c->wcap, &outlen);
  if (r != GF_OK)
    return r;
  if (c->ev.write (c->ev.user, c->wbuf, outlen) != 0)
    return GF_ERR_HANDLER;
  return GF_OK;
}

static void
finish_close (gf_conn *c, int error)
{
  c->st = ST_CLOSED;
  if (!c->closed_called)
    {
      c->closed_called = 1;
      if (c->ev.closed)
        c->ev.closed (c->ev.user, error, c->reason, c->peer_text);
    }
}

static uint32_t
reason_for (int status, uint32_t given)
{
  if (given != 0)
    return given;
  switch (status)
    {
    case GF_ERR_CRYPTO:		return GF_DISCONNECT_MAC_ERROR;
    case GF_ERR_UNSUPPORTED:	return GF_DISCONNECT_KEY_EXCHANGE_FAILED;
    case GF_ERR_HOSTKEY:	return GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE;
    case GF_ERR_HANDLER:	return GF_DISCONNECT_BY_APPLICATION;
    case GF_ERR_TIMEOUT:	return GF_DISCONNECT_CONNECTION_LOST;
    default:			return GF_DISCONNECT_PROTOCOL_ERROR;
    }
}

/* What we tell the peer.  English and fixed: the peer's locale is not
   ours, and the text must never carry local detail.  */
static const char *
reason_text (uint32_t reason)
{
  switch (reason)
    {
    case GF_DISCONNECT_PROTOCOL_ERROR:		return "protocol error";
    case GF_DISCONNECT_KEY_EXCHANGE_FAILED:	return "key exchange failed";
    case GF_DISCONNECT_MAC_ERROR:		return "packet integrity error";
    case GF_DISCONNECT_SERVICE_NOT_AVAILABLE:	return "service not available";
    case GF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
      return "protocol version not supported";
    case GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:	return "host key not verifiable";
    case GF_DISCONNECT_CONNECTION_LOST:		return "timed out";
    case GF_DISCONNECT_BY_APPLICATION:		return "disconnected by application";
    default:					return "disconnected";
    }
}

static void
send_disconnect (gf_conn *c, uint32_t reason, const char *text)
{
  uint8_t buf[256];
  gf_writer w;

  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u8 (&w, GF_MSG_DISCONNECT);
  gf_wr_u32 (&w, reason);
  gf_wr_cstring (&w, text ? text : reason_text (reason));
  gf_wr_cstring (&w, "");
  if (gf_wr_status (&w) != GF_OK)
    {
      /* The application's description did not fit: the reason must still
         reach the peer, with the fixed text.  */
      gf_writer_init (&w, buf, sizeof buf);
      gf_wr_u8 (&w, GF_MSG_DISCONNECT);
      gf_wr_u32 (&w, reason);
      gf_wr_cstring (&w, reason_text (reason));
      gf_wr_cstring (&w, "");
    }
  if (gf_wr_status (&w) == GF_OK)
    (void) send_packet (c, buf, w.len);
}

/* A fatal error: say so if the peer can still be told, and close.  */
static int
fail (gf_conn *c, int status)
{
  if (c->st == ST_CLOSED)
    return status;
  c->fatal = status;
  c->reason = reason_for (status, c->reason);
  if (c->st == ST_PACKETS)
    send_disconnect (c, c->reason, reason_text (c->reason));
  finish_close (c, status);
  return status;
}

/* ------------------------------------------------------------------ */
/* Key exchange                                                       */
/* ------------------------------------------------------------------ */

/* The signature algorithms a server can offer: those its keys make,
   in the order of the preferences.  */
static size_t
server_sigalgs (const gf_conn *c, enum gf_sigalg *out, size_t cap)
{
  const enum gf_sigalg *base = c->cfg.prefs.sigalgs;
  size_t nbase = c->cfg.prefs.nsigalgs, n = 0, i, k, j;

  if (base == NULL)
    base = gf_policy_default_sigalgs (&nbase);
  for (i = 0; i < nbase && n < cap; i++)
    for (k = 0; k < c->cfg.nhost_keys; k++)
      {
        size_t na;
        const enum gf_sigalg *a = gf_key_sigalgs (c->cfg.host_keys[k], &na);
        int ok = 0;

        for (j = 0; j < na; j++)
          if (a[j] == base[i])
            ok = 1;
        if (ok)
          {
            out[n++] = base[i];
            break;
          }
      }
  return n;
}

static void
discard_kex (gf_conn *c)
{
  free (c->our_kexinit);
  free (c->peer_kexinit);
  c->our_kexinit = c->peer_kexinit = NULL;
  gf_kex_client_free (c->kexc);
  c->kexc = NULL;
  gf_wipe (&c->read_keys, sizeof c->read_keys);
  gf_wipe (c->init, sizeof c->init);
}

/* Send our KEXINIT and open the exchange.  */
static int
begin_kex (gf_conn *c)
{
  uint8_t buf[4096];
  size_t n;
  struct gf_kex_prefs prefs = c->cfg.prefs;
  enum gf_sigalg sigs[8];
  int r;

  discard_kex (c);
  c->kex_active = 1;
  c->first_kex = !c->established;
  c->sent_kexinit = c->got_kexinit = c->sent_newkeys = c->got_newkeys = 0;
  c->kex_done_msg = 0;
  c->kex_deadline = c->now + (c->cfg.kex_timeout_us ? c->cfg.kex_timeout_us
                              : DEFAULT_KEX_TIMEOUT_US);
  if (c->server)
    {
      prefs.nsigalgs = server_sigalgs (c, sigs, 8);
      prefs.sigalgs = sigs;
      if (prefs.nsigalgs == 0)
        FAIL (c, GF_ERR_INVAL, GF_DISCONNECT_BY_APPLICATION);
    }
  r = gf_kexinit_make (buf, sizeof buf, &n, c->server, c->first_kex, &prefs);
  if (r != GF_OK)
    return r;
  c->our_kexinit = malloc (n);
  if (c->our_kexinit == NULL)
    return GF_ERR_NOMEM;
  memcpy (c->our_kexinit, buf, n);
  c->our_kexinit_len = n;
  r = send_packet (c, buf, n);
  if (r == GF_OK)
    c->sent_kexinit = 1;
  return r;
}

static int
flush_pending (gf_conn *c)
{
  size_t npend = c->pend_len, off = 0;
  int r = GF_OK;

  while (off < npend && r == GF_OK)
    {
      gf_reader rd;
      uint32_t n;

      gf_reader_init (&rd, c->pend + off, npend - off);
      gf_rd_u32 (&rd, &n);
      r = send_packet (c, c->pend + off + 4, n);
      off += 4 + n;
    }
  /* The queue can hold a password or other userauth message.  */
  if (c->pend != NULL && npend > 0)
    gf_wipe (c->pend, npend);
  c->pend_len = 0;
  return r;
}

/* Key and IV material for both directions from K and H.  */
static int
derive_keys (gf_conn *c, const gf_kex_secret *k, const uint8_t *h, size_t hlen)
{
  enum gf_hash alg = gf_kex_hash (c->algs.kex);
  const uint8_t *sid = c->session_id;
  size_t sidlen = c->sid_len;
  struct pending_keys c2s, s2c, *mine, *theirs;
  int r = GF_OK;

  memset (&c2s, 0, sizeof c2s);
  memset (&s2c, 0, sizeof s2c);
  c2s.cipher = c->algs.c2s;
  s2c.cipher = c->algs.s2c;
  c2s.keylen = gf_cipher_key_len (c2s.cipher);
  s2c.keylen = gf_cipher_key_len (s2c.cipher);
  c2s.ivlen = gf_cipher_iv_len (c2s.cipher);
  s2c.ivlen = gf_cipher_iv_len (s2c.cipher);
  if (c->first_kex)
    {
      /* The session identifier is the first exchange hash.  */
      memcpy (c->session_id, h, hlen);
      c->sid_len = hlen;
      sid = c->session_id;
      sidlen = hlen;
    }
  if (c2s.ivlen)
    r = gf_kex_derive (alg, k, h, hlen, sid, sidlen, 'A', c2s.iv, c2s.ivlen);
  if (r == GF_OK && s2c.ivlen)
    r = gf_kex_derive (alg, k, h, hlen, sid, sidlen, 'B', s2c.iv, s2c.ivlen);
  if (r == GF_OK)
    r = gf_kex_derive (alg, k, h, hlen, sid, sidlen, 'C', c2s.key, c2s.keylen);
  if (r == GF_OK)
    r = gf_kex_derive (alg, k, h, hlen, sid, sidlen, 'D', s2c.key, s2c.keylen);
  if (r != GF_OK)
    {
      gf_wipe (&c2s, sizeof c2s);
      gf_wipe (&s2c, sizeof s2c);
      return r;
    }
  c2s.present = s2c.present = 1;
  mine = c->server ? &s2c : &c2s;	/* What we write with.  */
  theirs = c->server ? &c2s : &s2c;	/* What we read with.  */
  c->read_keys = *theirs;

  /* Our NEWKEYS goes out under the old keys; the new ones apply to
     everything after it.  */
  {
    uint8_t nk = GF_MSG_NEWKEYS;

    r = send_packet (c, &nk, 1);
  }
  if (r == GF_OK)
    r = gf_packet_set_keys (&c->pkt, GF_DIR_WRITE, mine->cipher, mine->key,
                            mine->keylen, mine->iv, mine->ivlen, 1);
  if (r == GF_OK)
    c->sent_newkeys = 1;
  gf_wipe (&c2s, sizeof c2s);
  gf_wipe (&s2c, sizeof s2c);
  return r;
}

/* Keep the host key's signature of the first exchange hash, for
   gf_conn_info.  A rekey's is not kept: it is over a later hash.  */
static void
keep_host_sig (gf_conn *c, const uint8_t *sig, size_t len)
{
  if (!c->first_kex)
    return;
  c->host_sig_len = 0;
  if (len <= sizeof c->host_sig)
    {
      memcpy (c->host_sig, sig, len);
      c->host_sig_len = len;
    }
}

static void
fill_info (gf_conn *c)
{
  c->info.kex = c->algs.kex;
  c->info.hostkey_alg = c->algs.hostkey;
  c->info.cipher_c2s = c->algs.c2s;
  c->info.cipher_s2c = c->algs.s2c;
  c->info.session_id = c->session_id;
  c->info.session_id_len = c->sid_len;
  c->info.host_sig = c->host_sig;
  c->info.host_sig_len = c->host_sig_len;
  c->info.peer_ident = gf_ident_string (&c->ident_peer);
  c->info.peer_software = gf_ident_software (&c->ident_peer);
  c->info.host_key = c->server ? c->sign_key : c->peer_key;
  c->info.ext_info = c->peer_ext_info;
}

static int
send_ext_info (gf_conn *c)
{
  uint8_t buf[512];
  char list[256];
  size_t nbase, i, n = 0;
  const enum gf_sigalg *base = gf_policy_user_sigalgs (&nbase);
  gf_writer w;

  /* What the authentication layer takes from users.  The list names plain
     algorithms: a certificate is signed for with the algorithm of its key,
     and OpenSSH, whose list this is, reads it so.  */
  list[0] = '\0';
  for (i = 0; i < nbase; i++)
    {
      const char *name = gf_sigalg_name (base[i]);
      size_t l = strlen (name);

      if (n + l + 2 > sizeof list)
        break;
      if (n)
        list[n++] = ',';
      memcpy (list + n, name, l);
      n += l;
      list[n] = '\0';
    }
  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u8 (&w, GF_MSG_EXT_INFO);
  gf_wr_u32 (&w, c->cfg.announce_hostbound ? 2 : 1);
  gf_wr_cstring (&w, "server-sig-algs");
  gf_wr_string (&w, list, n);
  if (c->cfg.announce_hostbound)
    {
      gf_wr_cstring (&w, "publickey-hostbound@openssh.com");
      gf_wr_cstring (&w, "0");
    }
  if (gf_wr_status (&w) != GF_OK)
    return GF_ERR_BUFSIZE;
  return send_packet (c, buf, w.len);
}

/* Both NEWKEYS have passed: the exchange is over.  */
static int
check_complete (gf_conn *c)
{
  int first, r;

  if (!(c->sent_newkeys && c->got_newkeys))
    return GF_OK;
  first = !c->established;
  c->kex_active = 0;
  c->sent_kexinit = c->got_kexinit = c->sent_newkeys = c->got_newkeys = 0;
  c->kex_done_msg = 0;
  discard_kex (c);
  c->established = 1;
  c->rekey_due = c->now + (c->cfg.rekey_interval_us
                           ? c->cfg.rekey_interval_us
                           : DEFAULT_REKEY_INTERVAL_US);
  fill_info (c);
  c->in_event = 1;
  r = 0;
  if (first && c->ev.established)
    r = c->ev.established (c->ev.user, &c->info);
  else if (!first && c->ev.rekeyed)
    r = c->ev.rekeyed (c->ev.user, &c->info);
  c->in_event = 0;
  return r ? GF_ERR_HANDLER : GF_OK;
}

static int
after_newkeys_sent (gf_conn *c)
{
  int r = flush_pending (c);

  /* RFC 8308: the server's EXT_INFO follows its first NEWKEYS.  */
  if (r == GF_OK && c->server && c->first_kex && c->algs.ext_info)
    r = send_ext_info (c);
  return r;
}

static int
handle_kexinit (gf_conn *c, const uint8_t *p, size_t n)
{
  struct gf_kexinit ours, theirs;
  const struct gf_kexinit *ci, *si;
  int r;

  if (c->got_kexinit)
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
  if (n > MAX_PEER_KEXINIT)
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
  if (!c->kex_active)
    {
      /* A rekey the peer starts.  A server has it only from a user who is
         in: before that each one costs it a key exchange and a signature
         for nobody, and OpenSSH's sshd refuses them too.  A client takes
         one from the server it has authenticated the host of, as OpenSSH's
         does.  */
      if (c->server && !c->authed)
        FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
      r = begin_kex (c);
      if (r != GF_OK)
        return r;
    }
  if (gf_kexinit_parse (p, n, &theirs) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  c->peer_kexinit = malloc (n);
  if (c->peer_kexinit == NULL)
    return GF_ERR_NOMEM;
  memcpy (c->peer_kexinit, p, n);
  c->peer_kexinit_len = n;
  /* Parse again from our copy so the slices outlive this packet.  */
  gf_kexinit_parse (c->peer_kexinit, n, &theirs);
  gf_kexinit_parse (c->our_kexinit, c->our_kexinit_len, &ours);
  c->got_kexinit = 1;

  ci = c->server ? &theirs : &ours;
  si = c->server ? &ours : &theirs;
  r = gf_kexinit_negotiate (ci, si, c->first_kex, &c->algs);
  if (r == GF_ERR_PROTOCOL)
    FAIL (c, r, GF_DISCONNECT_KEY_EXCHANGE_FAILED);
  if (r != GF_OK)
    return r;
  /* RFC 8308 is announced on the first exchange only.  A rekey's KEXINIT
     omits the marker, and negotiate() reports ext_info only for the initial
     exchange, so taking this from the rekey would clear a flag the peer
     did announce.  */
  if (c->first_kex)
    c->peer_ext_info = c->server
      ? c->algs.ext_info
      : gf_namelist_contains (si->kex, GF_KEX_EXTINFO_SERVER);

  if (!c->server)
    {
      r = gf_kex_client_start (&c->kexc, c->algs.kex, c->init, sizeof c->init,
                               &c->init_len);
      if (r == GF_OK)
        {
          uint8_t buf[GF_KEX_MAX_INIT + 16];
          gf_writer w;

          gf_writer_init (&w, buf, sizeof buf);
          gf_wr_u8 (&w, GF_MSG_KEX_ECDH_INIT);
          gf_wr_string (&w, c->init, c->init_len);
          r = gf_wr_status (&w) == GF_OK ? send_packet (c, buf, w.len)
                                         : GF_ERR_BUFSIZE;
          c->kex_done_msg = 1;
        }
      if (r != GF_OK)
        FAIL (c, r, GF_DISCONNECT_KEY_EXCHANGE_FAILED);
    }
  return GF_OK;
}

static const gf_key *
find_host_key (const gf_conn *c, enum gf_sigalg alg)
{
  size_t i, j;

  for (i = 0; i < c->cfg.nhost_keys; i++)
    {
      size_t na;
      const enum gf_sigalg *a = gf_key_sigalgs (c->cfg.host_keys[i], &na);

      for (j = 0; j < na; j++)
        if (a[j] == alg)
          return c->cfg.host_keys[i];
    }
  return NULL;
}

static void
fill_transcript (const gf_conn *c, struct gf_kex_transcript *t)
{
  gf_slice ours, theirs;

  ours.data = c->ident_ours;
  ours.len = c->ident_ours_len;
  theirs = gf_ident_string (&c->ident_peer);
  t->v_c = c->server ? theirs : ours;
  t->v_s = c->server ? ours : theirs;
  t->i_c.data = c->server ? c->peer_kexinit : c->our_kexinit;
  t->i_c.len = c->server ? c->peer_kexinit_len : c->our_kexinit_len;
  t->i_s.data = c->server ? c->our_kexinit : c->peer_kexinit;
  t->i_s.len = c->server ? c->our_kexinit_len : c->peer_kexinit_len;
}

/* Server: SSH_MSG_KEX_ECDH_INIT.  */
static int
handle_kex_init (gf_conn *c, const uint8_t *p, size_t n)
{
  gf_reader rd;
  gf_slice qc;
  uint8_t qs[GF_KEX_MAX_REPLY], h[GF_KEX_MAX_HASH], sig[GF_SIG_MAX];
  uint8_t *msg = NULL;
  size_t qslen, siglen, hlen, bloblen, msgcap;
  gf_kex_secret k;
  struct gf_kex_transcript t;
  const gf_key *key;
  const uint8_t *blob;
  gf_writer w;
  int r;

  if (!c->server || !c->got_kexinit || c->kex_done_msg)
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_string (&rd, &qc) != GF_OK || gf_rd_finish (&rd) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  c->kex_done_msg = 1;

  key = find_host_key (c, c->algs.hostkey);
  if (key == NULL)
    FAIL (c, GF_ERR_UNSUPPORTED, GF_DISCONNECT_KEY_EXCHANGE_FAILED);
  r = gf_kex_server_respond (c->algs.kex, qc.data, qc.len, qs, sizeof qs,
                             &qslen, &k);
  if (r != GF_OK)
    FAIL (c, r == GF_ERR_ENCODING ? GF_ERR_PROTOCOL : r,
          GF_DISCONNECT_KEY_EXCHANGE_FAILED);

  blob = gf_key_blob (key, &bloblen);
  fill_transcript (c, &t);
  t.k_s.data = blob;
  t.k_s.len = bloblen;
  t.q_c = qc;
  t.q_s.data = qs;
  t.q_s.len = qslen;
  hlen = gf_hash_size (gf_kex_hash (c->algs.kex));
  r = gf_kex_exchange_hash (c->algs.kex, &t, &k, h, hlen);
  if (r == GF_OK)
    r = gf_key_sign (key, c->algs.hostkey, h, hlen, sig, sizeof sig, &siglen);
  if (r != GF_OK)
    {
      gf_wipe (&k, sizeof k);
      return r;
    }

  msgcap = 1 + 12 + bloblen + qslen + siglen;
  msg = malloc (msgcap);
  if (msg == NULL)
    {
      gf_wipe (&k, sizeof k);
      return GF_ERR_NOMEM;
    }
  gf_writer_init (&w, msg, msgcap);
  gf_wr_u8 (&w, GF_MSG_KEX_ECDH_REPLY);
  gf_wr_string (&w, blob, bloblen);
  gf_wr_string (&w, qs, qslen);
  gf_wr_string (&w, sig, siglen);
  r = gf_wr_status (&w) == GF_OK ? send_packet (c, msg, w.len) : GF_ERR_BUFSIZE;
  free (msg);
  c->sign_key = key;
  keep_host_sig (c, sig, siglen);
  if (r == GF_OK)
    r = derive_keys (c, &k, h, hlen);
  gf_wipe (&k, sizeof k);
  gf_wipe (h, sizeof h);
  if (r == GF_OK)
    r = after_newkeys_sent (c);
  return r;
}

/* Client: SSH_MSG_KEX_ECDH_REPLY.  */
static int
handle_kex_reply (gf_conn *c, const uint8_t *p, size_t n)
{
  gf_reader rd;
  gf_slice ks, qs, sig;
  uint8_t h[GF_KEX_MAX_HASH];
  size_t hlen;
  gf_kex_secret k;
  struct gf_kex_transcript t;
  gf_key *key = NULL;
  int r;

  /* One REPLY per exchange.  The first exchange travels in the clear, so
     a second copy may be a man in the middle's replay: taking it would
     derive the same keys again, send a second NEWKEYS and restart our
     sequence number, and so reuse a nonce under the keys already in use.
     After it is handled the ephemeral secret is gone (kexc is NULL) and
     our NEWKEYS is out, and either refuses the next.  */
  if (c->server || !c->kex_done_msg || c->kexc == NULL || c->sent_newkeys)
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_string (&rd, &ks) != GF_OK || gf_rd_string (&rd, &qs) != GF_OK
      || gf_rd_string (&rd, &sig) != GF_OK || gf_rd_finish (&rd) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);

  r = gf_key_from_blob (&key, ks.data, ks.len);
  if (r != GF_OK)
    FAIL (c, GF_ERR_HOSTKEY, GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
  if (!gf_sigalg_matches_key_type (c->algs.hostkey, gf_key_type_name (key),
                                   strlen (gf_key_type_name (key))))
    {
      gf_key_free (key);
      FAIL (c, GF_ERR_HOSTKEY, GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
    }
  r = gf_kex_client_finish (c->kexc, qs.data, qs.len, &k);
  /* The ephemeral secret has done its work: wipe it now rather than at the
     end of the exchange.  */
  gf_kex_client_free (c->kexc);
  c->kexc = NULL;
  if (r != GF_OK)
    {
      gf_key_free (key);
      FAIL (c, r == GF_ERR_ENCODING ? GF_ERR_PROTOCOL : r,
            GF_DISCONNECT_KEY_EXCHANGE_FAILED);
    }
  fill_transcript (c, &t);
  t.k_s = ks;
  t.q_c.data = c->init;
  t.q_c.len = c->init_len;
  t.q_s = qs;
  hlen = gf_hash_size (gf_kex_hash (c->algs.kex));
  r = gf_kex_exchange_hash (c->algs.kex, &t, &k, h, hlen);
  if (r == GF_OK)
    r = gf_key_verify (key, c->algs.hostkey, h, hlen, sig.data, sig.len);
  if (r != GF_OK)
    {
      gf_key_free (key);
      gf_wipe (&k, sizeof k);
      FAIL (c, GF_ERR_HOSTKEY, GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
    }

  if (c->first_kex)
    {
      keep_host_sig (c, sig.data, sig.len);
      /* The application decides whether to trust the key; the signature
         has shown that the server holds it.  */
      c->in_event = 1;
      r = c->ev.host_key ? c->ev.host_key (c->ev.user, key) : 1;
      c->in_event = 0;
      if (r != 0)
        {
          gf_key_free (key);
          gf_wipe (&k, sizeof k);
          FAIL (c, GF_ERR_HOSTKEY, GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
        }
      c->peer_key = key;
    }
  else
    {
      /* A rekey must present the same key.  */
      int same = gf_key_equal (key, c->peer_key);

      gf_key_free (key);
      if (!same)
        {
          gf_wipe (&k, sizeof k);
          FAIL (c, GF_ERR_HOSTKEY, GF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
        }
    }
  r = derive_keys (c, &k, h, hlen);
  gf_wipe (&k, sizeof k);
  gf_wipe (h, sizeof h);
  if (r == GF_OK)
    r = after_newkeys_sent (c);
  return r;
}

static int
handle_newkeys (gf_conn *c)
{
  struct pending_keys *k = &c->read_keys;
  int r;

  if (!c->kex_active || !k->present || !c->sent_newkeys || c->got_newkeys)
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
  r = gf_packet_set_keys (&c->pkt, GF_DIR_READ, k->cipher, k->key, k->keylen,
                          k->iv, k->ivlen, 1);
  gf_wipe (k, sizeof *k);
  if (r != GF_OK)
    return r;
  c->got_newkeys = 1;
  if (c->first_kex)
    c->ext_window = 1;
  return check_complete (c);
}

/* ------------------------------------------------------------------ */
/* The other transport messages                                       */
/* ------------------------------------------------------------------ */

static int
handle_disconnect (gf_conn *c, const uint8_t *p, size_t n)
{
  gf_reader rd;
  uint32_t reason;
  gf_slice desc;

  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_u32 (&rd, &reason) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  /* The description and language tag are optional in practice.  */
  if (gf_rd_string (&rd, &desc) != GF_OK)
    {
      desc.data = NULL;
      desc.len = 0;
    }
  c->reason = reason;
  c->peer_text = desc;
  {
    int err = reason == GF_DISCONNECT_BY_APPLICATION ? 0 : GF_ERR_CLOSED;

    /* The closed callback and the return from this receive must agree:
       an application that only checks gf_conn_receive must not think the
       connection is still usable after a peer disconnect.  */
    c->fatal = err == 0 ? GF_OK : err;
    finish_close (c, err);
  }
  return GF_OK;
}

static int
send_unimplemented (gf_conn *c, uint32_t seq)
{
  uint8_t buf[8];
  gf_writer w;

  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u8 (&w, GF_MSG_UNIMPLEMENTED);
  gf_wr_u32 (&w, seq);
  return send_packet (c, buf, w.len);
}

static int
handle_service_request (gf_conn *c, const uint8_t *p, size_t n)
{
  gf_reader rd;
  gf_slice name;
  uint8_t buf[64];
  gf_writer w;

  if (!c->server)
    return send_unimplemented (c, gf_packet_seq (&c->pkt, GF_DIR_READ) - 1);
  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_string (&rd, &name) != GF_OK || gf_rd_finish (&rd) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  if (!gf_slice_equals (name, SERVICE_USERAUTH))
    FAIL (c, GF_ERR_UNSUPPORTED, GF_DISCONNECT_SERVICE_NOT_AVAILABLE);
  if (c->ev.service_request && c->ev.service_request (c->ev.user, name) != 0)
    FAIL (c, GF_ERR_HANDLER, GF_DISCONNECT_SERVICE_NOT_AVAILABLE);
  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u8 (&w, GF_MSG_SERVICE_ACCEPT);
  gf_wr_string (&w, name.data, name.len);
  return send_packet (c, buf, w.len);
}

static int
handle_service_accept (gf_conn *c, const uint8_t *p, size_t n)
{
  gf_reader rd;
  gf_slice name;

  if (c->server)
    return send_unimplemented (c, gf_packet_seq (&c->pkt, GF_DIR_READ) - 1);
  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_string (&rd, &name) != GF_OK || gf_rd_finish (&rd) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  if (c->ev.service_accepted && c->ev.service_accepted (c->ev.user, name) != 0)
    FAIL (c, GF_ERR_HANDLER, GF_DISCONNECT_BY_APPLICATION);
  return GF_OK;
}

static int
handle_ext_info (gf_conn *c, const uint8_t *p, size_t n, int window)
{
  gf_reader rd;
  uint32_t count, i;

  /* RFC 8308 section 2.4: either side may send it, once, as the first
     message after its NEWKEYS of the first key exchange.  */
  if (!window)
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_u32 (&rd, &count) != GF_OK || count > 64)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  for (i = 0; i < count; i++)
    {
      gf_slice name, value;

      if (gf_rd_string (&rd, &name) != GF_OK
          || gf_rd_string (&rd, &value) != GF_OK)
        FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
      if (c->ev.extension && c->ev.extension (c->ev.user, name, value) != 0)
        FAIL (c, GF_ERR_HANDLER, GF_DISCONNECT_BY_APPLICATION);
    }
  if (gf_rd_finish (&rd) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  return GF_OK;
}

static int
handle_debug (gf_conn *c, const uint8_t *p, size_t n)
{
  gf_reader rd;
  int always;
  gf_slice text, lang;

  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_bool (&rd, &always) != GF_OK || gf_rd_string (&rd, &text) != GF_OK
      || gf_rd_string (&rd, &lang) != GF_OK || gf_rd_finish (&rd) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  if (c->ev.debug)
    c->ev.debug (c->ev.user, always, text);
  return GF_OK;
}

static int
handle_ignore (gf_conn *c, const uint8_t *p, size_t n)
{
  gf_reader rd;
  gf_slice data;

  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_string (&rd, &data) != GF_OK || gf_rd_finish (&rd) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  return GF_OK;
}

static int
handle_unimplemented (gf_conn *c, const uint8_t *p, size_t n)
{
  gf_reader rd;
  uint32_t seq;

  gf_reader_init (&rd, p + 1, n - 1);
  if (gf_rd_u32 (&rd, &seq) != GF_OK || gf_rd_finish (&rd) != GF_OK)
    FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
  if (c->ev.unimplemented)
    c->ev.unimplemented (c->ev.user, seq);
  return GF_OK;
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                           */
/* ------------------------------------------------------------------ */

/* Which messages may arrive now?  In the first key exchange, strict mode
   (OpenSSH PROTOCOL) allows nothing but the exchange's own messages -
   no IGNORE or DEBUG to lengthen the transcript unseen, and a KEXINIT
   first.  In any exchange, between the peer's KEXINIT and its NEWKEYS
   the peer may send only transport messages and key exchange ones
   (RFC 4253 section 7.1).  */
static int
message_allowed (const gf_conn *c, uint8_t type)
{
  int peer_in_kex = c->kex_active && c->got_kexinit && !c->got_newkeys;

  if (type == GF_MSG_DISCONNECT)
    return 1;
  if (c->first_kex && !c->established)
    {
      if (!c->got_kexinit)
        return type == GF_MSG_KEXINIT;
      return type == GF_MSG_KEX_ECDH_INIT || type == GF_MSG_KEX_ECDH_REPLY
        || type == GF_MSG_NEWKEYS;
    }
  if (peer_in_kex)
    return (type >= 2 && type <= 4) || type == GF_MSG_NEWKEYS
      || (type >= 30 && type <= 49);
  return 1;
}

static int
dispatch (gf_conn *c, const uint8_t *p, size_t n, int window)
{
  uint8_t type = p[0];

  if (!message_allowed (c, type))
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);

  switch (type)
    {
    case GF_MSG_DISCONNECT:	return handle_disconnect (c, p, n);
    case GF_MSG_IGNORE:		return handle_ignore (c, p, n);
    case GF_MSG_UNIMPLEMENTED:	return handle_unimplemented (c, p, n);
    case GF_MSG_DEBUG:		return handle_debug (c, p, n);
    case GF_MSG_SERVICE_REQUEST:
      if (!c->established)
        FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
      return handle_service_request (c, p, n);
    case GF_MSG_SERVICE_ACCEPT:
      if (!c->established)
        FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
      return handle_service_accept (c, p, n);
    case GF_MSG_EXT_INFO:	return handle_ext_info (c, p, n, window);
    case GF_MSG_KEXINIT:	return handle_kexinit (c, p, n);
    case GF_MSG_NEWKEYS:
      if (n != 1)
        FAIL (c, GF_ERR_ENCODING, GF_DISCONNECT_PROTOCOL_ERROR);
      return handle_newkeys (c);
    case GF_MSG_KEX_ECDH_INIT:	return handle_kex_init (c, p, n);
    case GF_MSG_KEX_ECDH_REPLY:	return handle_kex_reply (c, p, n);
    default:
      break;
    }
  if (type >= 32 && type <= 49)
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
  if (type >= 50 && c->established && c->ev.message != NULL)
    {
      c->in_event = 1;
      if (c->ev.message (c->ev.user, p, n) != 0)
        {
          c->in_event = 0;
          FAIL (c, GF_ERR_HANDLER, GF_DISCONNECT_BY_APPLICATION);
        }
      c->in_event = 0;
      return GF_OK;
    }
  if (type >= 50 && !c->established)
    FAIL (c, GF_ERR_PROTOCOL, GF_DISCONNECT_PROTOCOL_ERROR);
  /* Unknown to us: say so, with the number of the packet.  */
  return send_unimplemented (c, gf_packet_seq (&c->pkt, GF_DIR_READ) - 1);
}

static int
on_packet (void *user, const uint8_t *payload, size_t len)
{
  gf_conn *c = user;
  int window = c->ext_window, r;

  c->ext_window = 0;
  r = dispatch (c, payload, len, window);
  if (r != GF_OK)
    {
      c->fatal = r;
      return 1;
    }
  return c->st == ST_CLOSED;
}

/* Start a rekey if limits say so.  */
static int
maybe_rekey (gf_conn *c)
{
  uint64_t bytes = c->cfg.rekey_bytes ? c->cfg.rekey_bytes
                                      : DEFAULT_REKEY_BYTES;
  uint64_t packets = c->cfg.rekey_packets ? c->cfg.rekey_packets
                                          : DEFAULT_REKEY_PACKETS;
  uint64_t rb = gf_packet_bytes (&c->pkt, GF_DIR_READ);
  uint64_t wb = gf_packet_bytes (&c->pkt, GF_DIR_WRITE);
  uint64_t rp = gf_packet_count (&c->pkt, GF_DIR_READ);
  uint64_t wp = gf_packet_count (&c->pkt, GF_DIR_WRITE);

  /* Not before the user is in: it is put off, not forgotten (the limits
     only grow), and starts as soon as the layer above says so.  */
  if (!c->established || !c->authed || c->kex_active || c->st != ST_PACKETS)
    return GF_OK;
  if (rb < bytes && wb < bytes && rp < packets && wp < packets
      && c->now < c->rekey_due)
    return GF_OK;
  return begin_kex (c);
}

/* ------------------------------------------------------------------ */
/* Public interface                                                   */
/* ------------------------------------------------------------------ */

static int
conn_new (gf_conn **out, int server, const gf_conn_config *config,
          const gf_conn_events *events)
{
  gf_conn *c;
  char software[64];
  const char *sw;
  size_t n;
  int r;

  if (out == NULL || config == NULL || events == NULL || events->write == NULL
      || events->message == NULL)
    return GF_ERR_INVAL;
  if (server && (config->host_keys == NULL || config->nhost_keys == 0))
    return GF_ERR_INVAL;
  r = gf_crypto_init ();
  if (r != GF_OK)
    return r;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return GF_ERR_NOMEM;
  c->server = server;
  c->cfg = *config;
  c->ev = *events;
  sw = config->software;
  if (sw == NULL)
    {
      size_t k = 0;
      const char *v = "foxtrot_" VERSION;

      while (v[k] && k < sizeof software - 1)
        {
          software[k] = v[k] == '-' ? '_' : v[k];
          k++;
        }
      software[k] = '\0';
      sw = software;
    }
  r = gf_ident_format (sw, config->comments, c->ident_ours,
                       sizeof c->ident_ours, &n);
  if (r != GF_OK)
    {
      free (c);
      return r;
    }
  c->ident_ours_len = n - 2;
  gf_ident_init (&c->ident_peer, !server);
  gf_packet_init (&c->pkt);
  c->st = ST_NEW;
  *out = c;
  return GF_OK;
}

int
gf_conn_client_new (gf_conn **out, const gf_conn_config *config,
                    const gf_conn_events *events)
{
  return conn_new (out, 0, config, events);
}

int
gf_conn_server_new (gf_conn **out, const gf_conn_config *config,
                    const gf_conn_events *events)
{
  return conn_new (out, 1, config, events);
}

void
gf_conn_free (gf_conn *c)
{
  if (c == NULL)
    return;
  discard_kex (c);
  gf_packet_wipe (&c->pkt);
  gf_wipe (c->session_id, sizeof c->session_id);
  gf_wipe (c->init, sizeof c->init);
  gf_key_free (c->peer_key);
  if (c->rbuf)
    gf_wipe (c->rbuf, c->rcap);
  if (c->wbuf)
    gf_wipe (c->wbuf, c->wcap);
  if (c->pend)
    gf_wipe (c->pend, c->pend_cap);
  free (c->rbuf);
  free (c->wbuf);
  free (c->pend);
  free (c);
}

int
gf_conn_start (gf_conn *c, uint64_t now_us)
{
  int r;

  if (c == NULL)
    return GF_ERR_INVAL;
  if (c->st != ST_NEW)
    return GF_ERR_STATE;
  c->now = now_us;
  {
    uint8_t line[GF_IDENT_MAX + 2];

    memcpy (line, c->ident_ours, c->ident_ours_len);
    line[c->ident_ours_len] = '\r';
    line[c->ident_ours_len + 1] = '\n';
    if (c->ev.write (c->ev.user, line, c->ident_ours_len + 2) != 0)
      {
        c->st = ST_CLOSED;
        return GF_ERR_HANDLER;
      }
  }
  c->st = ST_IDENT;
  /* Our KEXINIT does not wait for the peer's identification.  */
  r = begin_kex (c);
  if (r != GF_OK)
    {
      c->reason = reason_for (r, c->reason);
      finish_close (c, r);
    }
  return r;
}

int
gf_conn_receive (gf_conn *c, uint64_t now_us, const uint8_t *data, size_t len)
{
  int r;

  if (c == NULL || (data == NULL && len > 0))
    return GF_ERR_INVAL;
  if (c->st == ST_CLOSED)
    return c->fatal ? c->fatal : GF_ERR_CLOSED;
  if (c->st == ST_NEW)
    return GF_ERR_STATE;
  c->now = now_us;

  if (c->st == ST_IDENT)
    {
      r = gf_ident_parse (&c->ident_peer, &data, &len);
      if (r == GF_NEED_MORE)
        return GF_OK;
      if (r != GF_OK)
        {
          c->reason = r == GF_ERR_UNSUPPORTED
            ? GF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED : 0;
          c->fatal = r;
          finish_close (c, r);
          return r;
        }
      c->st = ST_PACKETS;
    }

  while (len > 0 && c->st == ST_PACKETS)
    {
      size_t room, take, left;
      uint8_t *b;

      if (c->rlen == c->rcap)
        {
          r = grow (&c->rbuf, &c->rcap, c->rcap + 1);
          if (r != GF_OK)
            return fail (c, r);
        }
      room = c->rcap - c->rlen;
      take = len < room ? len : room;
      memcpy (c->rbuf + c->rlen, data, take);
      c->rlen += take;
      data += take;
      len -= take;

      b = c->rbuf;
      left = c->rlen;
      r = gf_packet_receive (&c->pkt, &b, &left, on_packet, c);
      /* The packets just handled were plaintext, perhaps a password:
         do not leave them in the buffer.  */
      gf_wipe (c->rbuf, (size_t) (b - c->rbuf));
      memmove (c->rbuf, b, left);
      c->rlen = left;
      if (r == GF_ERR_HANDLER)
        {
          if (c->st == ST_CLOSED)
            return c->fatal == GF_OK ? GF_OK : fail (c, c->fatal);
          return fail (c, c->fatal != GF_OK ? c->fatal : GF_ERR_HANDLER);
        }
      if (r != GF_OK && r != GF_NEED_MORE)
        {
          if (r == GF_ERR_ENCODING || r == GF_ERR_RANGE)
            c->reason = GF_DISCONNECT_PROTOCOL_ERROR;
          return fail (c, r);
        }
    }
  if (c->st == ST_PACKETS)
    {
      r = maybe_rekey (c);
      if (r != GF_OK)
        return fail (c, r);
    }
  return c->st == ST_CLOSED && c->fatal ? c->fatal : GF_OK;
}

uint64_t
gf_conn_timeout (const gf_conn *c)
{
  if (c == NULL || c->st == ST_CLOSED || c->st == ST_NEW)
    return UINT64_MAX;
  if (c->kex_active)
    return c->kex_deadline;
  /* A rekey that is due but put off is not a time to wake for.  */
  if (c->established && c->authed)
    return c->rekey_due;
  return UINT64_MAX;
}

int
gf_conn_on_timeout (gf_conn *c, uint64_t now_us)
{
  int r;

  if (c == NULL)
    return GF_ERR_INVAL;
  if (c->st == ST_CLOSED)
    return GF_ERR_CLOSED;
  if (c->st == ST_NEW)
    return GF_ERR_STATE;
  c->now = now_us;
  if (c->kex_active && now_us >= c->kex_deadline)
    return fail (c, GF_ERR_TIMEOUT);
  if (c->st == ST_PACKETS)
    {
      r = maybe_rekey (c);
      if (r != GF_OK)
        return fail (c, r);
    }
  return GF_OK;
}

static int
ready_to_send (gf_conn *c, uint64_t now_us)
{
  if (c == NULL)
    return GF_ERR_INVAL;
  if (c->st == ST_CLOSED)
    return GF_ERR_CLOSED;
  if (c->st != ST_PACKETS || !c->established)
    return GF_ERR_STATE;
  c->now = now_us;
  return GF_OK;
}

int
gf_conn_send (gf_conn *c, uint64_t now_us, const uint8_t *payload, size_t len)
{
  int r = ready_to_send (c, now_us);

  if (r != GF_OK)
    return r;
  if (payload == NULL || len == 0 || payload[0] < 50)
    return GF_ERR_INVAL;
  if (len > GF_MAX_PAYLOAD)
    return GF_ERR_RANGE;

  if (c->kex_active && !c->sent_newkeys)
    {
      if (c->pend_len + 4 + len > MAX_PENDING)
        return GF_ERR_AGAIN;
      r = grow (&c->pend, &c->pend_cap, c->pend_len + 4 + len);
      if (r != GF_OK)
        return r;
      c->pend[c->pend_len] = (uint8_t) (len >> 24);
      c->pend[c->pend_len + 1] = (uint8_t) (len >> 16);
      c->pend[c->pend_len + 2] = (uint8_t) (len >> 8);
      c->pend[c->pend_len + 3] = (uint8_t) len;
      memcpy (c->pend + c->pend_len + 4, payload, len);
      c->pend_len += 4 + len;
      return GF_OK;
    }
  r = send_packet (c, payload, len);
  if (r == GF_OK && !c->in_event)
    r = maybe_rekey (c);
  return r == GF_OK ? GF_OK : fail (c, r);
}

int
gf_conn_reject_message (gf_conn *c)
{
  if (c == NULL)
    return GF_ERR_INVAL;
  if (c->st != ST_PACKETS || !c->in_event)
    return GF_ERR_STATE;
  return send_unimplemented (c, gf_packet_seq (&c->pkt, GF_DIR_READ) - 1);
}

int
gf_conn_send_ignore (gf_conn *c, uint64_t now_us, const uint8_t *data,
                     size_t len)
{
  uint8_t *buf;
  gf_writer w;
  int r = ready_to_send (c, now_us);

  if (r != GF_OK)
    return r;
  if ((data == NULL && len > 0) || len > GF_MAX_PAYLOAD - 8)
    return GF_ERR_INVAL;
  buf = malloc (len + 8);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, len + 8);
  gf_wr_u8 (&w, GF_MSG_IGNORE);
  gf_wr_string (&w, data, len);
  r = send_packet (c, buf, w.len);
  free (buf);
  return r == GF_OK ? GF_OK : fail (c, r);
}

int
gf_conn_send_debug (gf_conn *c, uint64_t now_us, int always_display,
                    const char *text)
{
  uint8_t *buf;
  size_t n;
  gf_writer w;
  int r = ready_to_send (c, now_us);

  if (r != GF_OK)
    return r;
  if (text == NULL)
    return GF_ERR_INVAL;
  n = strlen (text);
  if (n > 4096)
    return GF_ERR_RANGE;
  buf = malloc (n + 16);
  if (buf == NULL)
    return GF_ERR_NOMEM;
  gf_writer_init (&w, buf, n + 16);
  gf_wr_u8 (&w, GF_MSG_DEBUG);
  gf_wr_bool (&w, always_display);
  gf_wr_string (&w, text, n);
  gf_wr_cstring (&w, "");
  r = send_packet (c, buf, w.len);
  free (buf);
  return r == GF_OK ? GF_OK : fail (c, r);
}

int
gf_conn_request_service (gf_conn *c, uint64_t now_us, const char *name)
{
  uint8_t buf[64];
  gf_writer w;
  int r = ready_to_send (c, now_us);

  if (r != GF_OK)
    return r;
  if (c->server || name == NULL || strlen (name) > 40)
    return GF_ERR_INVAL;
  if (c->kex_active && !c->sent_newkeys)
    return GF_ERR_AGAIN;
  gf_writer_init (&w, buf, sizeof buf);
  gf_wr_u8 (&w, GF_MSG_SERVICE_REQUEST);
  gf_wr_cstring (&w, name);
  r = send_packet (c, buf, w.len);
  return r == GF_OK ? GF_OK : fail (c, r);
}

int
gf_conn_rekey (gf_conn *c, uint64_t now_us)
{
  int r = ready_to_send (c, now_us);

  if (r != GF_OK)
    return r;
  if (!c->authed)
    return GF_ERR_STATE;
  if (c->kex_active)
    return GF_OK;
  r = begin_kex (c);
  return r == GF_OK ? GF_OK : fail (c, r);
}

int
gf_conn_set_authenticated (gf_conn *c)
{
  if (c == NULL)
    return GF_ERR_INVAL;
  if (c->st == ST_CLOSED)
    return GF_ERR_CLOSED;
  if (!c->established)
    return GF_ERR_STATE;
  c->authed = 1;
  return GF_OK;
}

int
gf_conn_disconnect (gf_conn *c, uint64_t now_us, uint32_t reason,
                    const char *description)
{
  if (c == NULL)
    return GF_ERR_INVAL;
  if (c->st == ST_CLOSED)
    return GF_ERR_CLOSED;
  c->now = now_us;
  c->reason = reason;
  if (c->st == ST_PACKETS)
    send_disconnect (c, reason, description);
  c->fatal = GF_OK;
  finish_close (c, reason == GF_DISCONNECT_BY_APPLICATION ? 0 : GF_ERR_CLOSED);
  return GF_OK;
}

int
gf_conn_is_established (const gf_conn *c)
{
  return c->established && c->st != ST_CLOSED;
}

int
gf_conn_is_closed (const gf_conn *c)
{
  return c->st == ST_CLOSED;
}

const gf_conn_info *
gf_conn_get_info (const gf_conn *c)
{
  return c->established ? &c->info : NULL;
}

uint32_t
gf_conn_seq (const gf_conn *c, enum gf_dir dir)
{
  return gf_packet_seq (&c->pkt, dir);
}
