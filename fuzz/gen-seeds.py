#!/usr/bin/env python3
# Make the seed corpus (corpus/) from the test vectors in ../tests and from
# messages written here.  Run it after the vectors change:
#
#     python3 gen-seeds.py
#
# The seeds are only starting points, written as corpus/TARGET/seed-NAME; the
# inputs that found something are kept beside them under other names (found-*,
# crash-*), and are left alone when this is run again.  Nothing here is
# trusted.
import os, re, shutil, struct

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.join(HERE, '..', 'tests')
OUT = os.path.join(HERE, 'corpus')

def consts(fname):
    """name -> bytes of text for every static string constant in a header."""
    s = open(os.path.join(TESTS, fname)).read()
    out = {}
    for m in re.finditer(r'static const char (?:\*const )?(\w+)(?:\[\])? =\s*((?:"(?:[^"\\]|\\.)*"\s*)+);', s):
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2))
        text = ''.join(parts).encode().decode('unicode_escape')
        out[m.group(1)] = text
    return out

def hexc(fname):
    """The hex constants of a header, as bytes."""
    r = {}
    for k, v in consts(fname).items():
        if re.fullmatch(r'(?:[0-9a-f]{2})+', v):
            r[k] = bytes.fromhex(v)
    return r

def textc(fname):
    return {k: v for k, v in consts(fname).items() if not re.fullmatch(r'(?:[0-9a-f]{2})*', v)}

def s(b):
    if isinstance(b, str): b = b.encode()
    return struct.pack('>I', len(b)) + b
def u32(n): return struct.pack('>I', n)
def u64(n): return struct.pack('>Q', n)
def frame(*msgs): return b''.join(struct.pack('>H', len(m)) + m for m in msgs)

seeds = {}
def add(target, name, data):
    if isinstance(data, str): data = data.encode()
    seeds.setdefault(target, {})[name] = data

key = hexc('vectors-key.h')
cert = hexc('vectors-cert.h')
sk = hexc('vectors-sk.h')
x509 = hexc('vectors-x509.h')
kh = consts('vectors-knownhosts.h')
keyfile = consts('vectors-keyfile.h')

# ---- wire ----
add('wire', 'ops', bytes([12]) + bytes([5, 5, 8, 9, 6, 7, 1, 2, 3, 0, 4, 10]) + s('hello') + s(b'\x00\x80\x01') + s('a,b,c') + s('text') + s('\xc3\xa9') + b'\0\0\0\1\2\3\4\5\6\7\x08\x09')
add('wire', 'mpint', bytes([3, 8, 8, 8]) + s(b'\x00\xff\x00') + s(b'') + s(b'\x01'))
add('wire', 'names', bytes([3, 9, 9, 9]) + s('a,b') + s('') + s(',,'))

# ---- ident ----
add('ident', 'plain', b'\x00\x20' + b'SSH-2.0-OpenSSH_9.6\r\n')
add('ident', 'client-prefix', b'\x01\x05' + b'banner text\r\nmore\r\nSSH-2.0-foxtrot_0.0.1 comment\r\n')
add('ident', 'v1', b'\x00\x20' + b'SSH-1.99-old\r\n')
add('ident', 'bare-lf', b'\x00\x03' + b'SSH-2.0-x\n')

# ---- packet ----
def plain_packet(payload, pad=8):
    padlen = 4 + ((8 - (5 + len(payload) + 4) % 8) % 8)
    body = bytes([padlen]) + payload + bytes(padlen)
    return struct.pack('>I', len(body)) + body
add('packet', 'plain1', bytes([0, 30]) + plain_packet(b'\x15' + bytes(3)) + plain_packet(b'\x01'))
add('packet', 'short', bytes([0, 1]) + plain_packet(b'\x05abc'))
for i, c in enumerate(('none', 'chacha', 'aes256gcm', 'aes128gcm')):
    add('packet', 'roundtrip-' + c, bytes([4 + i, 7]) + b'payload for ' + c.encode())
    add('packet', 'damaged-' + c, bytes([4 + i, 6]) + b'a payload that is damaged afterwards' )
    add('packet', 'cipher-' + c, bytes([i, 33]) + os.urandom(0) + bytes(range(64)))

# ---- kexinit ----
def kexinit(kex, host, enc, comp='none', first=False):
    return (b'\x14' + bytes(range(16)) + s(kex) + s(host) + s(enc) + s(enc) + s('') + s('')
            + s(comp) + s(comp) + s('') + s('') + (b'\1' if first else b'\0') + u32(0))
add('kexinit', 'client', kexinit('curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com', 'ssh-ed25519', 'chacha20-poly1305@openssh.com'))
add('kexinit', 'server', kexinit('curve25519-sha256,kex-strict-s-v00@openssh.com', 'ssh-ed25519', 'chacha20-poly1305@openssh.com'))
add('kexinit', 'openssh', kexinit('sntrup761x25519-sha512@openssh.com,curve25519-sha256,ecdh-sha2-nistp256,ext-info-c,kex-strict-c-v00@openssh.com',
    'ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256',
    'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com', 'none,zlib@openssh.com'))
add('kexinit', 'guess', kexinit('curve25519-sha256', 'ssh-ed25519', 'chacha20-poly1305@openssh.com', first=True))
add('kexinit', 'legacy', kexinit('diffie-hellman-group14-sha1', 'ssh-rsa', 'aes128-cbc'))
add('kexinit', 'usersk', kexinit('curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com', 'sk-ssh-ed25519@openssh.com,x509v3-ecdsa-sha2-nistp256', 'aes256-gcm@openssh.com'))

# ---- key (blob, signature, data) ----
def keyseed(name, blob, sig=b'', data=b'foxtrot'):
    add('key', name, frame(blob, sig) + data)
for t in ('ed', 'p256', 'p384', 'rsa'):
    keyseed('plain-' + t, key['vec_%s_blob' % t], key.get('vec_%s_sig' % t, key.get('vec_rsa_sig256', b'')), key['vec_msg'])
for t in ('ed', 'p256', 'p384', 'rsa'):
    keyseed('usercert-' + t, cert['vec_%s_user_cert' % t], cert.get('vec_%s_sig' % t, cert.get('vec_rsa_sig256', b'')), cert['vec_msg'])
    keyseed('hostcert-' + t, cert['vec_%s_host_cert' % t])
for n in ('expired_cert', 'future_cert', 'unknown_critical_cert', 'forever_cert', 'p256ca_cert', 'sha1_ca_cert', 'verify_cert',
          'noperm_cert', 'pty_only_cert', 'fwd_only_cert'):
    keyseed(n, cert['vec_' + n])
for n in ('ed', 'p256', 'ed_app'):
    keyseed('sk-' + n, sk['vec_sk_%s_blob' % n], sk['vec_sk_%s_sig_up' % n], sk['vec_msg'])
    keyseed('sk-noup-' + n, sk['vec_sk_%s_blob' % n], sk['vec_sk_%s_sig_noup' % n], sk['vec_msg'])
for n in ('ed_cert', 'p256_cert', 'ed_cert_uv'):
    keyseed('skcert-' + n, sk['vec_sk_' + n], sk['vec_sk_ed_sig_up'], sk['vec_msg'])
for k, v in x509.items():
    if k.endswith('_blob'):
        keyseed('x509-' + k[6:-5], v, x509.get('vec_x_p256_sig', b''), x509['vec_x_msg'])

# ---- keytext ----
for k, v in textc('vectors-key.h').items():
    if k.endswith('_pub'): add('keytext', k, v)
for k, v in textc('vectors-sk.h').items():
    if k.endswith('_pub'): add('keytext', k, v)
add('keytext', 'comment', 'ssh-ed25519 ' + kh['vec_kh_e'].split()[1] + ' a comment here\n')
add('keytext', 'tabs', '  \t' + kh['vec_kh_p'].replace(' ', '\t', 1) + '\r\n')
add('keytext', 'bad', 'ssh-ed25519 AAAA\n')

# ---- keyfile ----
for k, v in textc('vectors-key.h').items():
    if k.endswith('_private'): add('keyfile', k, v)
for k, v in keyfile.items():
    if k.endswith('_enc') or k.endswith('_plain'): add('keyfile', k, v)

# ---- knownhosts: [hostlen][host][port][text] ----
def khseed(name, host, port, text):
    add('knownhosts', name, bytes([len(host)]) + host.encode() + struct.pack('>H', port) + text.encode())
khseed('file-example', 'example.org', 22, kh['vec_kh_file'])
khseed('file-bastion', 'bastion.example.org', 2222, kh['vec_kh_file'])
khseed('file-ca', 'host.ca.example.net', 22, kh['vec_kh_file'])
khseed('file-hashed', 'hashed.example.org', 22, kh['vec_kh_file'])
khseed('file-wild', 'a.corp.example.com', 22, kh['vec_kh_file'])
khseed('small', 'h', 22, 'h ' + kh['vec_kh_e'] + '\n@revoked * ' + kh['vec_kh_rev'] + '\n')
khseed('cert-authority', 'x.example.net', 22, '@cert-authority *.example.net ' + kh['vec_kh_ca'] + '\n')

# ---- x509 ----
for k, v in x509.items():
    if k.endswith('_blob'):
        add('x509', k[6:-5], v)

# ---- auth: first byte 1 = server, 0 = client; then two schedule bytes (server) / flags (client); frames ----
def authreq(user, method, rest, service='ssh-connection'):
    return b'\x32' + s(user) + s(service) + s(method) + rest
pkblob = key['vec_ed_blob']
sigblob = key['vec_ed_sig']
srv = [
    authreq('alice', 'none', b''),
    authreq('alice', 'password', b'\0' + s('secret')),
    authreq('alice', 'password', b'\1' + s('old') + s('new')),
    authreq('alice', 'publickey', b'\0' + s('ssh-ed25519') + s(pkblob)),
    authreq('alice', 'publickey', b'\1' + s('ssh-ed25519') + s(pkblob) + s(sigblob)),
    authreq('alice', 'publickey-hostbound@openssh.com', b'\1' + s('ssh-ed25519') + s(pkblob) + s(b'\0' * 51) + s(sigblob)),
    authreq('alice', 'publickey', b'\0' + s('ssh-ed25519-cert-v01@openssh.com') + s(cert['vec_ed_user_cert'])),
    authreq('alice', 'publickey', b'\1' + s('ssh-ed25519-cert-v01@openssh.com') + s(cert['vec_ed_user_cert']) + s(sigblob)),
    authreq('alice', 'publickey', b'\0' + s('sk-ssh-ed25519@openssh.com') + s(sk['vec_sk_ed_blob'])),
    authreq('alice', 'publickey', b'\1' + s('sk-ssh-ed25519@openssh.com') + s(sk['vec_sk_ed_blob']) + s(sk['vec_sk_ed_sig_up'])),
    authreq('alice', 'publickey', b'\0' + s('x509v3-ecdsa-sha2-nistp256') + s(x509['vec_x_client_blob'])),
    authreq('alice', 'keyboard-interactive', s('') + s('')),
    b'\x3d' + u32(2) + s('a') + s('b'),
    authreq('bob', 'none', b''),
    authreq('alice', 'none', b'', service='ssh-userauth'),
]
add('auth', 'server-all', b'\x01\x00\x00' + frame(*srv))
add('auth', 'server-accept', b'\x01\x55\x55' + frame(*srv))
add('auth', 'server-slow', b'\x01\x00\x40' + frame(*srv))
add('auth', 'server-probe-reject', b'\x01\x00\x80' + frame(*srv))
cli = [
    b'\x33' + s('publickey,password,keyboard-interactive') + b'\0',
    b'\x35' + s('banner text') + s(''),
    b'\x3c' + s('ssh-ed25519') + s(pkblob),
    b'\x3c' + s('name') + s('instr') + s('') + u32(2) + s('Code: ') + b'\0' + s('Again: ') + b'\1',
    b'\x33' + s('publickey') + b'\1',
    b'\x33' + s('password') + b'\0',
    b'\x34',
]
add('auth', 'client-all', b'\x00\x01' + frame(*cli))
add('auth', 'client-plain', b'\x00\x00' + frame(*cli))
add('auth', 'client-success', b'\x00\x00' + frame(b'\x34'))

# ---- chans: [sched lo][sched hi] frames each followed by an action byte ----
def chan_open(t, sender, window=2048, maxp=1024, extra=b''):
    return b'\x5a' + s(t) + u32(sender) + u32(window) + u32(maxp) + extra
def req(recip, name, want, rest=b''):
    return b'\x62' + u32(recip) + s(name) + (b'\1' if want else b'\0') + rest
ch = [
    b'\x5b' + u32(0) + u32(701) + u32(2048) + u32(1024),
    chan_open('direct-tcpip', 802, extra=s('h') + u32(80) + s('o') + u32(1234)),
    chan_open('session', 803),
    chan_open('x11', 804),
    b'\x5e' + u32(0) + s(b'data bytes'),
    b'\x5f' + u32(0) + u32(1) + s(b'stderr bytes'),
    b'\x5d' + u32(0) + u32(100000),
    b'\x60' + u32(0),
    req(0, 'exec', True, s('ls')),
    req(0, 'pty-req', True, s('xterm') + u32(80) + u32(24) + u32(0) + u32(0) + s(b'\x00')),
    req(0, 'env', False, s('LANG') + s('C')),
    req(0, 'window-change', False, u32(80) + u32(24) + u32(0) + u32(0)),
    req(0, 'signal', False, s('TERM')),
    req(0, 'exit-status', False, u32(3)),
    req(0, 'exit-signal', False, s('KILL') + b'\1' + s('msg') + s('')),
    req(0, 'subsystem', True, s('sftp')),
    req(0, 'x11-req', True, b'\0' + s('MIT-MAGIC-COOKIE-1') + s('00') + u32(0)),
    b'\x50' + s('tcpip-forward') + b'\1' + s('0.0.0.0') + u32(8080),
    b'\x50' + s('cancel-tcpip-forward') + b'\1' + s('0.0.0.0') + u32(8080),
    b'\x50' + s('no-more-sessions@openssh.com') + b'\0',
    b'\x50' + s('keepalive@openssh.com') + b'\1',
    b'\x51', b'\x52' + u32(1234), b'\x53',
    b'\x61' + u32(0), b'\x61' + u32(1),
]
add('chans', 'all', b'\x55\x01' + b''.join(struct.pack('>H', len(m)) + m + bytes([i % 256]) for i, m in enumerate(ch)))
add('chans', 'auto', b'\x00\x01' + b''.join(struct.pack('>H', len(m)) + m + bytes([(i * 7) % 256]) for i, m in enumerate(ch)))
add('chans', 'flaky', b'\xaa\x80' + b''.join(struct.pack('>H', len(m)) + m + bytes([(i * 3) % 256]) for i, m in enumerate(ch)))

# ---- authkeys: [alen][addr][hlen][host][ulen][user][text] ----
import base64
def lp(x): x = x.encode() if isinstance(x, str) else x; return bytes([len(x)]) + x
def aseed(name, addr, host, user, text): add('authkeys', name, lp(addr) + lp(host) + lp(user) + text.encode())
edpub = 'ssh-ed25519 ' + kh['vec_kh_e'].split()[1]
p256pub = kh['vec_kh_p']
capub = 'ssh-ed25519 ' + base64.b64encode(cert['vec_ca_ed_blob']).decode()
aseed('plain', '192.0.2.50', '', 'alice', '# keys\n' + edpub + ' me\n' + p256pub + '\n')
aseed('options', '192.0.2.50', 'host.example.org', 'alice',
      'no-pty,command="/bin/ls -l",from="192.0.2.0/24,*.example.org,!bad.example.org" ' + edpub + '\n'
      'restrict,pty,permitopen="db:5432",permitopen="[2001:db8::1]:22",permitlisten="8080",environment="A=1",'
      'expiry-time="20991231" ' + p256pub + '\n')
aseed('ca', '192.0.2.50', '', 'alice', 'cert-authority,principals="al*,bob" ' + capub + '\n')
aseed('ca-plain', '192.0.2.50', '', 'bob', 'cert-authority ' + capub + '\n' + edpub + '\n')
aseed('bad', '', '', '', 'command="x ' + edpub + '\nfrom="" ' + edpub + '\nunknown="x" ' + edpub + '\n')
aseed('expiry', '10.0.0.1', '', 'alice', 'expiry-time="20231114221320Z" ' + edpub + '\nexpiry-time="2024" ' + edpub + '\n')

# ---- krl: the list itself ----
krlc = hexc('vectors-krl.h')
add('krl', 'main', krlc['vec_krl_main'])
add('krl', 'wild', krlc['vec_krl_wild'])
add('krl', 'header-only', krlc['vec_krl_wild'][:50])

# ---- certsign: [type][allow][flags][serial][after][before] strings ----
def csseed(name, typ, allow, flags, serial, after, before, keyid, cmd, addr, *princ):
    d = bytes([typ, allow, flags]) + u64(serial) + u64(after) + u64(before)
    for x in (keyid, cmd, addr) + princ:
        x = x.encode(); d += bytes([len(x)]) + x
    add('certsign', name, d)
csseed('user', 1, 0x1f, 0, 7, 1000, 2000, 'alice@example.org', '/bin/true', '192.0.2.0/24,2001:db8::/32', 'alice', 'bob')
csseed('host', 2, 0, 0, 8, 1000, 2000, 'host', '', '', '*.example.org', 'example.com')
csseed('plain', 1, 0, 1, 9, 5, 6, 'id', '', '', 'p')
csseed('bad-times', 1, 0, 0, 9, 6, 5, 'id', '', '', 'p')
csseed('bad-addr', 1, 0, 0, 9, 5, 6, 'id', '', 'example.org', 'p')

# ---- sftp: [mode][schedule][chunk] raw ----
def sftp(t, body): return u32(len(body) + 1) + bytes([t]) + body
srv_stream = (sftp(1, u32(3)) + sftp(16, u32(1) + s('.')) + sftp(3, u32(2) + s('/a') + u32(1) + u32(0))
              + sftp(4, u32(3) + s(b'h')) + sftp(5, u32(4) + s(b'h') + u64(0) + u32(100))
              + sftp(6, u32(5) + s(b'h') + u64(0) + s(b'data')) + sftp(7, u32(6) + s('/a')) + sftp(17, u32(7) + s('/a'))
              + sftp(11, u32(8) + s('/')) + sftp(12, u32(9) + s(b'h')) + sftp(13, u32(10) + s('/x'))
              + sftp(14, u32(11) + s('/d') + u32(0)) + sftp(15, u32(12) + s('/d')) + sftp(18, u32(13) + s('/a') + s('/b'))
              + sftp(19, u32(14) + s('/l')) + sftp(20, u32(15) + s('target') + s('/l'))
              + sftp(9, u32(16) + s('/a') + u32(4) + u32(0o644)) + sftp(10, u32(17) + s(b'h') + u32(4) + u32(0o600))
              + sftp(8, u32(18) + s(b'h')) + sftp(200, u32(19) + s('x@y') + s('z')))
add('sftp', 'server-session', b'\x00\x00\x40' + srv_stream)
add('sftp', 'server-flaky', b'\x00\x80\x07' + srv_stream)
cli_stream = (sftp(101, u32(0) + u32(0) + s('ok') + s('')) + sftp(102, u32(1) + s(b'h')) + sftp(103, u32(2) + s(b'data'))
              + sftp(104, u32(3) + u32(1) + s('f') + s('-rw f') + u32(5) + u64(10) + u32(0o644))
              + sftp(105, u32(4) + u32(5) + u64(10) + u32(0o644)) + sftp(201, u32(5) + s('reply')) + sftp(101, u32(6) + u32(1) + s('eof') + s('')))
add('sftp', 'client-session', b'\x01\x00\x40' + cli_stream)
add('sftp', 'client-flaky', b'\x01\x80\x05' + cli_stream)

# ---- conn: [which][chunk] bytes ----
def pkt(payload):
    padlen = 4 + ((8 - (5 + len(payload) + 4) % 8) % 8)
    body = bytes([padlen]) + payload + bytes(padlen)
    return struct.pack('>I', len(body)) + body
cinit = (b'SSH-2.0-OpenSSH_9.6\r\n'
         + pkt(kexinit('curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com', 'ssh-ed25519', 'chacha20-poly1305@openssh.com'))
         + pkt(b'\x1e' + s(bytes(range(1, 33)))) + pkt(b'\x15') + bytes(100))
add('conn', 'server-flight', b'\x01\x20' + cinit)
add('conn', 'server-cut', b'\x01\x03' + cinit)
sinit = (b'SSH-2.0-sshd\r\n'
         + pkt(kexinit('curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com', 'ssh-ed25519', 'chacha20-poly1305@openssh.com'))
         + pkt(b'\x1f' + s(b'\0' * 51) + s(bytes(range(1, 33))) + s(b'\0' * 83)) + pkt(b'\x15'))
add('conn', 'client-flight', b'\x00\x20' + sinit)
add('conn', 'client-cut', b'\x00\x05' + sinit)
add('conn', 'ident-only', b'\x01\x01SSH-2.0-x\r\n')
add('conn', 'garbage', b'\x01\x20' + b'SSH-2.0-x\r\n' + bytes(range(256)))

n = 0
for target, items in seeds.items():
    d = os.path.join(OUT, target)
    os.makedirs(d, exist_ok=True)
    for old in os.listdir(d):
        if old.startswith('seed-'):
            os.remove(os.path.join(d, old))
    for name, data in items.items():
        open(os.path.join(d, 'seed-' + name), 'wb').write(data)
        n += 1
print('%d seeds in %d targets' % (n, len(seeds)))
