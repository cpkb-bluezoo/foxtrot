#!/usr/bin/env python3
# Generate tests/vectors-agent.h: the messages of a real OpenSSH ssh-agent.
# It starts an agent, adds keys with ssh-add (Ed25519, ECDSA over P-256,
# P-384 and P-521, RSA of 2048 and 1024 bits, DSA, and certificates for an
# Ed25519 and an RSA key), and records over its socket
#
#   - the answer to REQUEST_IDENTITIES, with the keys foxtrot refuses in it
#     (P-521, the short RSA key, DSA);
#   - for each key the foxtrot accepts, the SIGN_REQUEST that was sent, built
#     here from the draft and not by the library, and the SIGN_RESPONSE the
#     agent made; and the agent's FAILURE for a key it does not hold;
#   - an empty IDENTITIES_ANSWER from an agent with no keys;
#   - the session-bind@openssh.com request, built here, which the agent
#     verifies (it answers SUCCESS for a good signature and FAILURE for a bad
#     one), and what it answers;
#   - a public security key (sk-ssh-ed25519@openssh.com) made here, which
#     only a request is made for: an agent signs for one through a token.
#
# Each signature is checked here with python's cryptography package, which
# shares no code with the library; tests/test-agent.c checks them with
# gf_key_verify.
#
# Usage: python3 gen-agent-vectors.py > vectors-agent.h
# Needs ssh-agent, ssh-add and ssh-keygen from OpenSSH with DSA support (9.7 and
# earlier) for the DSA key, which is left out otherwise.
import base64, os, shutil, socket, struct, subprocess, sys, tempfile, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

MSG = b'foxtrot agent test message'
SESSION_ID = bytes(range(32))

d = tempfile.mkdtemp()

def run(*a, **kw):
    return subprocess.run(list(a), cwd=d, capture_output=True, text=True, check=True, **kw)

def s(b):
    if isinstance(b, str): b = b.encode()
    return struct.pack('>I', len(b)) + b
def u32(n): return struct.pack('>I', n)
def frame(payload): return u32(len(payload)) + payload

def emit(name, data):
    h = data.hex()
    print('static const char *const %s =' % name)
    for i in range(0, max(len(h), 1), 100):
        print('  "%s"%s' % (h[i:i + 100], ';' if i + 100 >= len(h) else ''))

def emit_parts(name, data):
    """As emit, for data that is longer than the 4095 characters of a string
    that C99 compilers must take: a list of pieces, ended by NULL."""
    h = data.hex()
    print('static const char *const %s[] = {' % name)
    for i in range(0, len(h), 2000):
        print('  "%s",' % h[i:i + 2000])
    print('  NULL')
    print('};')

# ---- The agent's socket ----

sock_path = os.path.join(d, 'agent.sock')

def start_agent():
    p = subprocess.Popen(['ssh-agent', '-D', '-a', sock_path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        if os.path.exists(sock_path):
            return p
        time.sleep(0.05)
    sys.exit('ssh-agent did not start')

def talk(payload):
    """Send one frame, return the payload of the reply."""
    c = socket.socket(socket.AF_UNIX)
    c.connect(sock_path)
    c.sendall(frame(payload))
    def rd(n):
        b = b''
        while len(b) < n:
            x = c.recv(n - len(b))
            if not x: sys.exit('agent closed')
            b += x
        return b
    n = struct.unpack('>I', rd(4))[0]
    r = rd(n)
    c.close()
    return r

def ssh_add(*files):
    env = dict(os.environ, SSH_AUTH_SOCK=sock_path)
    subprocess.run(['ssh-add'] + list(files), cwd=d, env=env, check=True,
                   capture_output=True)

# ---- Keys ----

def keygen(name, kind, *args, load=True):
    run('ssh-keygen', '-q', '-t', kind, '-N', '', '-C', 'foxtrot-' + name, '-f', name, *args)
    pub = base64.b64decode(open(os.path.join(d, name + '.pub')).read().split()[1])
    priv = None
    if load:
        priv = serialization.load_ssh_private_key(open(os.path.join(d, name), 'rb').read(), None)
    return pub, priv

def certify(ca, name, ident, serial):
    run('ssh-keygen', '-q', '-s', ca, '-I', ident, '-z', str(serial), '-n', 'alice',
        '-V', '20200101:20991231', name + '.pub')
    return base64.b64decode(open(os.path.join(d, name + '-cert.pub')).read().split()[1])

# ---- Checking a signature without the library ----

def sig_parts(blob):
    n = struct.unpack('>I', blob[:4])[0]
    name = blob[4:4 + n]
    m = struct.unpack('>I', blob[4 + n:8 + n])[0]
    return name.decode(), blob[8 + n:8 + n + m], blob[8 + n + m:]

def mpints(b):
    out = []
    while b:
        n = struct.unpack('>I', b[:4])[0]
        out.append(int.from_bytes(b[4:4 + n], 'big'))
        b = b[4 + n:]
    return out

def check(priv, alg, sig_blob, data):
    name, raw, rest = sig_parts(sig_blob)
    assert name == alg, (name, alg)
    pub = priv.public_key()
    if isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(raw, data)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        r, sv = mpints(raw)
        h = hashes.SHA256() if alg.endswith('256') else hashes.SHA384()
        pub.verify(utils.encode_dss_signature(r, sv), data, ec.ECDSA(h))
    else:
        h = hashes.SHA256() if alg == 'rsa-sha2-256' else hashes.SHA512()
        pub.verify(raw, data, padding.PKCS1v15(), h)
    assert rest == b'', 'trailing bytes after the signature'

# ---- Requests, as the draft has them ----

def sign_request(blob, data, flags):
    return bytes([13]) + s(blob) + s(data) + u32(flags)

def bind_request(hostkey, sid, sig):
    return bytes([27]) + s('session-bind@openssh.com') + s(hostkey) + s(sid) + s(sig) + b'\x00'

def parse_identities(payload):
    assert payload[0] == 12
    n = struct.unpack('>I', payload[1:5])[0]
    p = 5
    out = []
    for _ in range(n):
        k = struct.unpack('>I', payload[p:p + 4])[0]; p += 4
        blob = payload[p:p + k]; p += k
        c = struct.unpack('>I', payload[p:p + 4])[0]; p += 4
        out.append((blob, payload[p:p + c].decode())); p += c
    assert p == len(payload)
    return out

# ---- Make the keys, start an agent that has none ----

agent = start_agent()
try:
    empty = talk(bytes([11]))
    assert empty == bytes([12, 0, 0, 0, 0]), empty

    ed, ed_k = keygen('ed25519', 'ed25519')
    p256, p256_k = keygen('p256', 'ecdsa', '-b', '256')
    p384, p384_k = keygen('p384', 'ecdsa', '-b', '384')
    rsa2k, rsa_k = keygen('rsa2048', 'rsa', '-b', '2048')
    # What foxtrot refuses.
    p521, _ = keygen('p521', 'ecdsa', '-b', '521')
    rsa1k, _ = keygen('rsa1024', 'rsa', '-b', '1024')
    try:
        dsa, _ = keygen('dsa', 'dsa', load=False)
    except Exception:
        dsa = None
    # Certificates, from a CA of their own.
    ca, _ = keygen('ca', 'ed25519')
    ed_cert = certify('ca', 'ed25519', 'agent-ed', 11)
    rsa_cert = certify('ca', 'rsa2048', 'agent-rsa', 12)

    ssh_add('ed25519', 'p256', 'p384', 'rsa2048', 'p521', 'rsa1024')
    if dsa is not None:
        ssh_add('dsa')

    ident = talk(bytes([11]))
    ids = parse_identities(ident)
    byblob = {b: c for b, c in ids}
    for b in (ed, p256, p384, rsa2k, p521, rsa1k, ed_cert, rsa_cert):
        assert b in byblob, 'the agent does not list a key'

    # ---- Signatures ----
    cases = []   # (name, key blob, algorithm name, key, flags)
    cases.append(('ed25519', ed, 'ssh-ed25519', ed_k, 0))
    cases.append(('p256', p256, 'ecdsa-sha2-nistp256', p256_k, 0))
    cases.append(('p384', p384, 'ecdsa-sha2-nistp384', p384_k, 0))
    cases.append(('rsa256', rsa2k, 'rsa-sha2-256', rsa_k, 2))
    cases.append(('rsa512', rsa2k, 'rsa-sha2-512', rsa_k, 4))
    cases.append(('ed25519_cert', ed_cert, 'ssh-ed25519', ed_k, 0))
    cases.append(('rsa256_cert', rsa_cert, 'rsa-sha2-256', rsa_k, 2))
    cases.append(('rsa512_cert', rsa_cert, 'rsa-sha2-512', rsa_k, 4))
    signs = []
    for name, blob, alg, key, flags in cases:
        req = sign_request(blob, MSG, flags)
        resp = talk(req)
        assert resp[0] == 14, (name, resp[:1])
        sb = resp[1:]
        assert struct.unpack('>I', sb[:4])[0] == len(sb) - 4
        check(key, alg, sb[4:], MSG)
        signs.append((name, blob, alg, flags, req, resp))

    # The agent refusing: a key it does not hold.
    other, _ = keygen('other', 'ed25519')
    failure = talk(sign_request(other, MSG, 0))
    assert failure == bytes([5]), failure

    # ---- session-bind ----
    # The "host key" is the Ed25519 key; its signature over a session
    # identifier is what the agent checks.
    good_sig = s('ssh-ed25519') + s(ed_k.sign(SESSION_ID))
    bad_sig = s('ssh-ed25519') + s(ed_k.sign(SESSION_ID[::-1]))
    bind_good = bind_request(ed, SESSION_ID, good_sig)
    bind_bad = bind_request(ed, SESSION_ID, bad_sig)
    ok = talk(bind_good)
    no = talk(bind_bad)
    assert ok == bytes([6]), ok
    assert no == bytes([5]), no
    # An agent that has not heard of an extension.
    unknown = talk(bytes([27]) + s('nonexistent@example.com'))
finally:
    agent.terminate()
    agent.wait()
    shutil.rmtree(d, ignore_errors=True)

# ---- Write the header ----

print('/* Generated by gen-agent-vectors.py; do not edit.  Throwaway test keys,')
print('   and the messages an OpenSSH ssh-agent made for them.  */')
print()
emit('vec_agent_msg', MSG)
emit('vec_agent_session_id', SESSION_ID)
emit('vec_agent_empty_answer', empty)
emit('vec_agent_failure', failure)
emit('vec_agent_unknown_extension_answer', unknown)
print()
print('/* The IDENTITIES_ANSWER, and what each of its keys is.  */')
emit_parts('vec_agent_identities', ident)
print('struct vec_agent_id')
print('{')
print('  const char *blob;')
print('  const char *comment;')
print('  int accepted;			/* gf_key_from_blob takes it.  */')
print('};')
print()
accepted = {ed, p256, p384, rsa2k, ed_cert, rsa_cert}
for i, (b, c) in enumerate(ids):
    emit('vec_agent_id%d_blob' % i, b)
print('static const struct vec_agent_id vec_agent_ids[] = {')
for i, (b, c) in enumerate(ids):
    print('  { vec_agent_id%d_blob, "%s", %d },' % (i, c, 1 if b in accepted else 0))
print('};')
print()
print('/* A SIGN_REQUEST (as the library must make it), the agent\'s SIGN_RESPONSE,')
print('   for MSG; ALG is the signature algorithm the library is asked for.  */')
print('struct vec_agent_sign')
print('{')
print('  const char *name;')
print('  const char *alg;')
print('  const char *blob;')
print('  unsigned flags;')
print('  const char *request;		/* The payload.  */')
print('  const char *response;')
print('};')
print()
for i, (name, blob, alg, flags, req, resp) in enumerate(signs):
    emit('vec_agent_sign%d_blob' % i, blob)
    emit('vec_agent_sign%d_request' % i, req)
    emit('vec_agent_sign%d_response' % i, resp)
print('static const struct vec_agent_sign vec_agent_signs[] = {')
for i, (name, blob, alg, flags, req, resp) in enumerate(signs):
    print('  { "%s", "%s%s", vec_agent_sign%d_blob, %d, vec_agent_sign%d_request,' % (
        name, alg, '-cert-v01@openssh.com' if name.endswith('_cert') else '', i, flags, i))
    print('    vec_agent_sign%d_response },' % i)
print('};')
print()
print('/* session-bind@openssh.com: the host key (the Ed25519 key above), the session')
print('   identifier and a good and a bad signature of it, and the two requests the')
print('   agent answered SUCCESS and FAILURE to.  */')
emit('vec_agent_bind_hostkey', ed)
emit('vec_agent_bind_sig', good_sig)
emit('vec_agent_bind_bad_sig', bad_sig)
emit('vec_agent_bind_request', bind_good)
emit('vec_agent_bind_bad_request', bind_bad)
print()
print('/* A security key, made from the Ed25519 key above: it is only named in a')
print('   request (the agent would need a token to sign).  */')
n = struct.unpack('>I', ed[:4])[0]
raw_pk = ed[8 + n:]
assert len(raw_pk) == 32
emit('vec_agent_sk_blob', s('sk-ssh-ed25519@openssh.com') + s(raw_pk) + s('ssh:'))
