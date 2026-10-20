#!/usr/bin/env python3
# Generate tests/vectors-x509.h: a small PKI made with the python
# "cryptography" package (root and intermediate CAs, end certificates of each
# key type with the extensions and the faults the tests need, and a CRL),
# RFC 6187 key blobs built from it, signatures by the end certificates' keys
# in the RFC's format, and the end certificates' private keys as OpenSSH
# files.  Whether a chain is good at the test's time is checked here against
# "openssl verify", which shares no code with GnuTLS or with the library.
#
# Usage: python3 gen-x509-vectors.py > vectors-x509.h
import datetime, os, struct, subprocess, tempfile, warnings
warnings.simplefilter('ignore')
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
import ipaddress

NOW = 1700000000
MSG = b'foxtrot x509 test message'
D = datetime.datetime
UTC = datetime.timezone.utc
def dt(y, m=1, d=1): return D(y, m, d, tzinfo=UTC)
SSH_SERVER = x509.ObjectIdentifier('1.3.6.1.5.5.7.3.22')
SSH_CLIENT = x509.ObjectIdentifier('1.3.6.1.5.5.7.3.21')

def s(b): return struct.pack('>I', len(b)) + b
def mpint(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if b and b[0] & 0x80: b = b'\0' + b
    return s(b)
def emit(name, data):
    if isinstance(data, bytes): data = data.hex()
    print('static const char *const %s =' % name)
    for i in range(0, len(data), 100):
        print('  "%s"%s' % (data[i:i+100], ';' if i + 100 >= len(data) else ''))
def text(name, t):
    lines = t.splitlines(keepends=True)
    print('static const char %s[] =' % name)
    for i, l in enumerate(lines):
        print('  "%s\\n"%s' % (l.rstrip('\n'), ';' if i == len(lines) - 1 else ''))

serial = [100]
def nextserial():
    serial[0] += 1
    return serial[0]

def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def newkey(kind):
    if kind == 'p256': return ec.generate_private_key(ec.SECP256R1())
    if kind == 'p384': return ec.generate_private_key(ec.SECP384R1())
    if kind == 'p521': return ec.generate_private_key(ec.SECP521R1())
    if kind == 'rsa': return rsa.generate_private_key(65537, 2048)
    if kind == 'rsa1024': return rsa.generate_private_key(65537, 1024)
    if kind == 'ed': return ed25519.Ed25519PrivateKey.generate()

def make(subject_cn, key, issuer_cn, issuer_key, ca=False, pathlen=None, start=dt(2020), end=dt(2099),
         san=None, eku=None, ku=None, sigalg=hashes.SHA256(), sn=None, nokeyusage=False):
    b = (x509.CertificateBuilder().subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
         .public_key(key.public_key()).serial_number(sn or nextserial())
         .not_valid_before(start).not_valid_after(end))
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    elif ku is not None:
        b = b.add_extension(ku, critical=True)
    elif not nokeyusage:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        return b.sign(issuer_key, None)
    return b.sign(issuer_key, sigalg)

def der(c): return c.public_bytes(serialization.Encoding.DER)
def pem(c): return c.public_bytes(serialization.Encoding.PEM)

# The PKI.
root_k, ca2_k = newkey('p256'), newkey('p256')
inter_k, inter2_k, inter1_k = newkey('p384'), newkey('p384'), newkey('p384')
root = make('Root CA', root_k, 'Root CA', root_k, ca=True)
ca2 = make('Other Root CA', ca2_k, 'Other Root CA', ca2_k, ca=True)
inter = make('Intermediate CA', inter_k, 'Root CA', root_k, ca=True, pathlen=0, sigalg=hashes.SHA384())
inter2 = make('Other Intermediate CA', inter2_k, 'Other Root CA', ca2_k, ca=True, pathlen=0)
# An intermediate CA that is itself expired, and a root that is.
old_root_k = newkey('p256')
old_root = make('Old Root CA', old_root_k, 'Old Root CA', old_root_k, ca=True, start=dt(2010), end=dt(2011))
old_inter = make('Old Intermediate', inter1_k, 'Old Root CA', old_root_k, ca=True, pathlen=0, start=dt(2010), end=dt(2011))

SERVER = [SSH_SERVER]
sans = [x509.DNSName('host.example.org'), x509.DNSName('*.wild.example.org'),
        x509.IPAddress(ipaddress.ip_address('192.0.2.7'))]
leaves = {}   # tag -> (cert, key, chain list of certs)
def leaf(tag, kind, cn='host', issuer=('Intermediate CA', inter_k, [inter]), **kw):
    k = newkey(kind)
    kw.setdefault('san', sans)
    kw.setdefault('eku', SERVER)
    c = make(cn, k, issuer[0], issuer[1], **kw)
    leaves[tag] = (c, k, [c] + issuer[2])
    return c, k

leaf('p256', 'p256')
leaf('p384', 'p384')
leaf('rsa', 'rsa')
leaf('client', 'p256', cn='alice', san=[x509.RFC822Name('alice@example.org')], eku=[SSH_CLIENT])
leaf('noeku', 'p256', eku=None)
leaf('tlsonly', 'p256', eku=[ExtendedKeyUsageOID.SERVER_AUTH])
leaf('anyeku', 'p256', eku=[x509.ObjectIdentifier('2.5.29.37.0')])
leaf('expired', 'p256', start=dt(2010), end=dt(2011))
leaf('future', 'p256', start=dt(2098), end=dt(2099))
leaf('nosan', 'p256', cn='cn.example.org', san=None)
leaf('wrongca', 'p256', issuer=('Other Intermediate CA', inter2_k, [inter2]))
leaf('nodsig', 'p256', ku=x509.KeyUsage(False, False, True, False, False, False, False, False, False))
leaf('revoked', 'p256', sn=900)
leaf('oldinter', 'p256', issuer=('Old Intermediate', inter1_k, [old_inter]))
leaf('oldroot', 'p256', issuer=('Old Root CA', old_root_k, []))
# Names that must not be taken for what they look like.
leaf('dnsip', 'p256', san=[x509.DNSName('10.1.2.3')])
leaf('widestar', 'p256', san=[x509.DNSName('*.org'), x509.DNSName('*.example'), x509.DNSName('*'), x509.DNSName('h*.example.org')])
leaf('ip6', 'p256', san=[x509.IPAddress(ipaddress.ip_address('2001:db8::1')), x509.IPAddress(ipaddress.ip_address('192.0.2.7'))])
# An intermediate whose own extended key usage is the web's, and one with a
# weak key.
ekuca_k = newkey('p384')
ekuca = make('Web Only CA', ekuca_k, 'Root CA', root_k, ca=True, pathlen=0, eku=[ExtendedKeyUsageOID.SERVER_AUTH])
leaf('ekuca', 'p256', issuer=('Web Only CA', ekuca_k, [ekuca]))
weak_k = newkey('rsa1024')
weakca = make('Weak CA', weak_k, 'Root CA', root_k, ca=True, pathlen=0)
leaf('weakca', 'p256', issuer=('Weak CA', weak_k, [weakca]))
leaf('rsa1024', 'rsa1024')
leaf('ed', 'ed')
leaf('p521', 'p521')
leaf('p256_chainroot', 'p256')

# A leaf signed with SHA-1, by the openssl command (python's package will not).
def sha1_leaf():
    d = tempfile.mkdtemp()
    k = newkey('p256')
    open(d + '/ca.pem', 'wb').write(pem(inter))
    open(d + '/ca.key', 'wb').write(inter_k.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    csr = (x509.CertificateSigningRequestBuilder().subject_name(name('host'))
           .sign(k, hashes.SHA256()))
    open(d + '/leaf.csr', 'wb').write(csr.public_bytes(serialization.Encoding.PEM))
    open(d + '/ext', 'w').write('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n'
        'extendedKeyUsage=1.3.6.1.5.5.7.3.22\nsubjectAltName=DNS:host.example.org\n')
    subprocess.check_call(['openssl', 'x509', '-req', '-in', d + '/leaf.csr', '-CA', d + '/ca.pem',
        '-CAkey', d + '/ca.key', '-set_serial', '777', '-days', '36000', '-sha1',
        '-extfile', d + '/ext', '-out', d + '/leaf.pem'], stderr=subprocess.DEVNULL)
    c = x509.load_pem_x509_certificate(open(d + '/leaf.pem', 'rb').read())
    leaves['sha1'] = (c, k, [c, inter])
sha1_leaf()

# The CRL by the intermediate, listing serial 900.
crl = (x509.CertificateRevocationListBuilder().issuer_name(name('Intermediate CA'))
       .last_update(dt(2023, 1, 1)).next_update(dt(2099))
       .add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(900)
                                .revocation_date(dt(2023, 1, 2)).build())
       .sign(inter_k, hashes.SHA384()))
crl_bad = (x509.CertificateRevocationListBuilder().issuer_name(name('Other Intermediate CA'))
           .last_update(dt(2023, 1, 1)).next_update(dt(2099))
           .sign(inter2_k, hashes.SHA256()))

def keyname(kind):
    return {'p256': 'x509v3-ecdsa-sha2-nistp256', 'p384': 'x509v3-ecdsa-sha2-nistp384',
            'rsa': 'x509v3-rsa2048-sha256'}[kind]

def blob(name_, chain, ocsp=()):
    b = s(name_.encode()) + struct.pack('>I', len(chain))
    for c in chain: b += s(der(c))
    b += struct.pack('>I', len(ocsp))
    for o in ocsp: b += s(o)
    return b

def sigblob(kind, key, msg):
    n = keyname(kind)
    if kind == 'rsa':
        return s(n.encode()) + s(key.sign(msg, padding.PKCS1v15(), hashes.SHA256()))
    h = hashes.SHA256() if kind == 'p256' else hashes.SHA384()
    r, sv = utils.decode_dss_signature(key.sign(msg, ec.ECDSA(h)))
    return s(n.encode()) + s(mpint(r) + mpint(sv))

# openssl verify as the oracle for chains.
tmp = tempfile.mkdtemp()
def openssl_ok(chain, trusted, crl_der=None, at=NOW):
    cafile = os.path.join(tmp, 'ca.pem')
    open(cafile, 'wb').write(b''.join(pem(c) for c in trusted))
    untr = os.path.join(tmp, 'untr.pem')
    open(untr, 'wb').write(b''.join(pem(c) for c in chain[1:]) or b'')
    leaf_f = os.path.join(tmp, 'leaf.pem')
    open(leaf_f, 'wb').write(pem(chain[0]))
    cmd = ['openssl', 'verify', '-attime', str(at), '-CAfile', cafile, '-no-CApath', '-no-CAstore']
    if chain[1:]: cmd += ['-untrusted', untr]
    if crl_der is not None:
        crlf = os.path.join(tmp, 'crl.pem')
        open(crlf, 'wb').write(crl_der.public_bytes(serialization.Encoding.PEM))
        cmd += ['-crl_check', '-CRLfile', crlf]
    cmd.append(leaf_f)
    return subprocess.run(cmd, capture_output=True).returncode == 0

# What openssl says of each chain, for the checks that are about the PKI and
# not about SSH (names and purposes are ours to check).
for tag in ('p256', 'p384', 'rsa', 'client', 'noeku', 'tlsonly', 'anyeku', 'nosan', 'nodsig', 'ed'):
    assert openssl_ok(leaves[tag][2], [root]), tag
assert not openssl_ok(leaves['expired'][2], [root]), 'expired'
assert not openssl_ok(leaves['future'][2], [root]), 'future'
assert not openssl_ok(leaves['wrongca'][2], [root]), 'wrongca'
assert not openssl_ok(leaves['oldinter'][2], [root, old_root]), 'oldinter'  # root old too
assert not openssl_ok(leaves['oldroot'][2], [old_root]), 'oldroot'
assert openssl_ok(leaves['revoked'][2], [root]), 'revoked without the CRL'
assert not openssl_ok(leaves['revoked'][2], [root], crl_der=crl), 'revoked with the CRL'
assert openssl_ok(leaves['p256'][2], [root], crl_der=crl), 'good with the CRL'

print('/* Generated by gen-x509-vectors.py; do not edit.  Throwaway keys.  */')
print()
emit('vec_x_msg', MSG)
for tag, c in (('root', root), ('ca2', ca2), ('inter', inter), ('inter2', inter2), ('old_root', old_root)):
    emit('vec_x_%s' % tag, der(c))
emit('vec_x_crl', crl.public_bytes(serialization.Encoding.DER))
emit('vec_x_crl_bad', crl_bad.public_bytes(serialization.Encoding.DER))
for tag, (c, k, chain) in leaves.items():
    emit('vec_x_%s_leaf' % tag, der(c))
    kind = {'p256': 'p256', 'p384': 'p384', 'rsa': 'rsa'}.get(tag)
    ck = {'ip6': 'p256', 'dnsip': 'p256', 'widestar': 'p256', 'ekuca': 'p256', 'weakca': 'p256', 'oldroot': 'p256', 'client': 'p256', 'noeku': 'p256', 'tlsonly': 'p256', 'anyeku': 'p256', 'expired': 'p256',
          'future': 'p256', 'sha1': 'p256', 'nosan': 'p256', 'wrongca': 'p256', 'nodsig': 'p256',
          'revoked': 'p256', 'oldinter': 'p256', 'p256_chainroot': 'p256'}.get(tag, kind)
    if ck:
        emit('vec_x_%s_blob' % tag, blob(keyname(ck), chain))
        emit('vec_x_%s_sig' % tag, sigblob(ck, k, MSG))
    text('vec_x_%s_private' % tag, k.private_bytes(serialization.Encoding.PEM,
         serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
         if not isinstance(k, rsa.RSAPrivateKey) or True else '')
# Chains in other shapes: with the root appended, unsorted, with OCSP bytes.
c, k, chain = leaves['p256']
emit('vec_x_p256_with_root_blob', blob(keyname('p256'), [c, inter, root]))
emit('vec_x_p256_unsorted_blob', blob(keyname('p256'), [c, root, inter]))
emit('vec_x_p256_alone_blob', blob(keyname('p256'), [c]))
emit('vec_x_p256_ocsp_blob', blob(keyname('p256'), chain, [b'\x30\x03\x0a\x01\x00', b'junk']))
emit('vec_x_p256_as_p384_blob', blob('x509v3-ecdsa-sha2-nistp384', chain))
emit('vec_x_p256_as_rsa_blob', blob('x509v3-rsa2048-sha256', chain))
emit('vec_x_rsa_as_p256_blob', blob('x509v3-ecdsa-sha2-nistp256', leaves['rsa'][2]))
emit('vec_x_p256_as_sshrsa_blob', blob('x509v3-ssh-rsa', chain))
emit('vec_x_p256_as_p521_blob', blob('x509v3-ecdsa-sha2-nistp521', chain))
emit('vec_x_rsa1024_blob', blob(keyname('rsa'), leaves['rsa1024'][2]))
emit('vec_x_ed_blob', blob(keyname('p256'), leaves['ed'][2]))
emit('vec_x_p521_blob', blob(keyname('p384'), leaves['p521'][2]))
