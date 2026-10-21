#!/usr/bin/env python3
# Generate tests/vectors-skfile.h: FIDO security key files as ssh-keygen
# writes them for "-t ed25519-sk" and "-t ecdsa-sk" (PROTOCOL.u2f: the private
# section holds the application, the flags and the key handle, and no key),
# unprotected and under a passphrase (bcrypt-pbkdf from the python "bcrypt"
# package, aes256-ctr), and tokens' signatures in the two forms a FIDO
# library gives them (raw Ed25519, DER ECDSA) with the blob they must be
# packed into.
#
# The files are written here from the format description, since enrolling a
# key needs a token (or OpenSSH's own dummy provider, which is not
# installed).  Each is checked against OpenSSH itself: ssh-keygen -y must
# read it, with the passphrase where there is one, and print the public key
# that is in the file.
#
# Usage: python3 gen-skfile-vectors.py > vectors-skfile.h
import base64, hashlib, os, struct, subprocess, tempfile
import bcrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PASS = 'correct horse'
WRONG = 'wrong horse'
ROUNDS = 4
MSG = b'foxtrot security key test message'

def s(b): return struct.pack('>I', len(b)) + b
def mpint(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if b and b[0] & 0x80: b = b'\0' + b
    return s(b)

def emit(name, data):
    if isinstance(data, bytes):
        data = data.hex()
    print('static const char *const %s =' % name)
    for i in range(0, len(data), 100):
        print('  "%s"%s' % (data[i:i+100], ';' if i + 100 >= len(data) else ''))

def text(name, t):
    lines = t.splitlines(keepends=True)
    print('static const char %s[] =' % name)
    for i, l in enumerate(lines):
        print('  "%s\\n"%s' % (l.rstrip('\n'), ';' if i == len(lines) - 1 else ''))

d = tempfile.mkdtemp()

def armor(raw):
    b64 = base64.b64encode(raw).decode()
    return ('-----BEGIN OPENSSH PRIVATE KEY-----\n'
            + ''.join(b64[i:i+70] + '\n' for i in range(0, len(b64), 70))
            + '-----END OPENSSH PRIVATE KEY-----\n')

class SK:
    def __init__(self, kind, app, flags, handle):
        self.kind, self.app, self.flags, self.handle = kind, app, flags, handle
        if kind == 'ed':
            self.key = ed25519.Ed25519PrivateKey.generate()
            self.name = b'sk-ssh-ed25519@openssh.com'
            self.pk = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.blob = s(self.name) + s(self.pk) + s(app)
            self.fields = s(self.pk)
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
            self.name = b'sk-ecdsa-sha2-nistp256@openssh.com'
            self.pk = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            self.blob = s(self.name) + s(b'nistp256') + s(self.pk) + s(app)
            self.fields = s(b'nistp256') + s(self.pk)

    def private_section(self, block):
        chk = os.urandom(4)
        p = chk + chk + s(self.name) + self.fields + s(self.app) + bytes([self.flags]) \
            + s(self.handle) + s(b'') + s(b'')
        pad = 1
        while len(p) % block:
            p += bytes([pad]); pad += 1
        return p

    def file(self, passphrase=None):
        if passphrase is None:
            priv = self.private_section(8)
            raw = b'openssh-key-v1\0' + s(b'none') + s(b'none') + s(b'') + struct.pack('>I', 1) \
                + s(self.blob) + s(priv)
            return armor(raw), None
        salt = os.urandom(16)
        km = bcrypt.kdf(passphrase.encode(), salt, 48, ROUNDS, ignore_few_rounds=True)
        enc = Cipher(algorithms.AES(km[:32]), modes.CTR(km[32:48])).encryptor()
        priv = enc.update(self.private_section(16)) + enc.finalize()
        raw = b'openssh-key-v1\0' + s(b'aes256-ctr') + s(b'bcrypt') \
            + s(s(salt) + struct.pack('>I', ROUNDS)) + struct.pack('>I', 1) + s(self.blob) + s(priv)
        return armor(raw), (passphrase, salt, ROUNDS, km)

    def publine(self):
        return self.name.decode() + ' ' + base64.b64encode(self.blob).decode()

    def signdata(self, msg, flags, counter):
        return hashlib.sha256(self.app).digest() + bytes([flags]) + struct.pack('>I', counter) + hashlib.sha256(msg).digest()

    def der(self, msg, flags, counter):
        return self.key.sign(self.signdata(msg, flags, counter), ec.ECDSA(hashes.SHA256()))

    def raw(self, msg, flags, counter):
        return self.key.sign(self.signdata(msg, flags, counter))

def blob_for(sk, sig_string, flags, counter):
    return s(sk.name) + s(sig_string) + bytes([flags]) + struct.pack('>I', counter)

def check(sk, content, kdf):
    f = os.path.join(d, 'k')
    open(f, 'w').write(content)
    os.chmod(f, 0o600)
    cmd = ['ssh-keygen', '-y', '-f', f]
    r = subprocess.run(cmd + (['-P', kdf[0]] if kdf else []), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split()[:2] == sk.publine().split(), (r.stdout, sk.publine())
    if kdf:
        r = subprocess.run(cmd + ['-P', WRONG], capture_output=True, text=True)
        assert r.returncode != 0

print('/* Generated by gen-skfile-vectors.py; do not edit.  Throwaway keys.  */')
print()

kdfs = []
cases = [
    ('ed', 'ed', b'ssh:', 0x01, os.urandom(64)),
    ('p256', 'p256', b'ssh:', 0x01, os.urandom(64)),
    # A resident key with user verification, a longer application and the
    # longest key handle there is.
    ('ed_res', 'ed', b'ssh:foxtrot', 0x21 | 0x04, os.urandom(255)),
    # "-O no-touch-required" stores no user presence flag.
    ('p256_notouch', 'p256', b'ssh:', 0x00, os.urandom(32)),
]
sks = {}
for tag, kind, app, flags, handle in cases:
    sk = SK(kind, app, flags, handle)
    sks[tag] = sk
    plain, _ = sk.file()
    check(sk, plain, None)
    text('vec_skf_%s_plain' % tag, plain)
    emit('vec_skf_%s_blob' % tag, sk.blob)
    emit('vec_skf_%s_handle' % tag, handle)
    print('static const char vec_skf_%s_app[] = "%s";' % (tag, app.decode()))
    print('#define VEC_SKF_%s_FLAGS 0x%02x' % (tag.upper(), flags))
    if tag in ('ed', 'p256'):
        enc, kdf = sk.file(PASS)
        check(sk, enc, kdf)
        text('vec_skf_%s_enc' % tag, enc)
        kdfs.append(kdf)

print()
print('struct vec_skf_kdf { const char *pass; const char *salt; unsigned rounds; unsigned outlen; const char *out; };')
print('static const struct vec_skf_kdf vec_skf_kdfs[] = {')
for p, salt, rounds, km in kdfs:
    print('  { "%s", "%s", %d, 48, "%s" },' % (p, salt.hex(), rounds, km.hex()))
    wrong = bcrypt.kdf(WRONG.encode(), salt, 48, rounds, ignore_few_rounds=True)
    print('  { "%s", "%s", %d, 48, "%s" },' % (WRONG, salt.hex(), rounds, wrong.hex()))
print('};')
print()

# What a token returns.  The message and the counter are the ones the
# signature tests use; the Ed25519 answer is the 64 raw bytes, the ECDSA one
# DER.  The expected blobs are what OpenSSH's own sshkey_verify reads.
FL, CTR = 0x05, 0x01020304
emit('vec_skf_msg', MSG)
ed, p256 = sks['ed'], sks['p256']
raw = ed.raw(MSG, FL, CTR)
emit('vec_skf_ed_raw', raw)
emit('vec_skf_ed_packed', blob_for(ed, raw, FL, CTR))

def der_parts(der):
    r, sv = utils.decode_dss_signature(der)
    return r, sv

# A signature for each shape of integer: both with the high bit set (so a
# leading zero byte in DER and in an mpint), one with a short r, one with a
# short s.
shapes = {}
while len(shapes) < 3:
    der = p256.der(MSG, FL, CTR)
    r, sv = der_parts(der)
    if r.bit_length() == 256 and sv.bit_length() == 256: name = 'both_high'
    elif r.bit_length() <= 248 and sv.bit_length() > 248: name = 'short_r'
    elif sv.bit_length() <= 248 and r.bit_length() > 248: name = 'short_s'
    else: name = None
    if name and name not in shapes:
        shapes[name] = der
for name, der in shapes.items():
    r, sv = der_parts(der)
    emit('vec_skf_p256_der_%s' % name, der)
    emit('vec_skf_p256_packed_%s' % name, blob_for(p256, mpint(r) + mpint(sv), FL, CTR))
print('#define VEC_SKF_FLAGS 0x%02x' % FL)
print('#define VEC_SKF_COUNTER 0x%08x' % CTR)
