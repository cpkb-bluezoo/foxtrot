#!/bin/sh
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
# This file is part of foxtrot.
#
# foxtrot is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# foxtrot is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <https://www.gnu.org/licenses/>.

# Certificates made by foxtrot (gf_cert_sign), checked by OpenSSH: ssh-keygen
# -L reads every field, and sshd and ssh accept (or refuse) them as they do
# certificates from ssh-keygen -s: user certificates from CAs of each kind
# for keys of each kind, their dates, principals, source address, forced
# command and permissions, and host certificates against known_hosts.
# Needs ssh, ssh-keygen and sshd (set SSHD if it is not in /usr/sbin);
# skips itself (exit 77) when they are missing, and when GF_NO_INTEROP is
# set.

srcdir=${srcdir:-.}
builddir=${builddir:-.}

[ -n "$GF_NO_INTEROP" ] && exit 77
SSH=${SSH:-ssh}
SSH_KEYGEN=${SSH_KEYGEN:-ssh-keygen}
SSHD=${SSHD:-/usr/sbin/sshd}
command -v "$SSH" >/dev/null 2>&1 || exit 77
command -v "$SSH_KEYGEN" >/dev/null 2>&1 || exit 77
[ -x "$SSHD" ] || exit 77

SIGN=$builddir/interop-sign
dir=$(mktemp -d "${TMPDIR:-/tmp}/foxtrot-certsign.XXXXXX") || exit 99
sshd_pid=
cleanup ()
{
  [ -n "$sshd_pid" ] && kill "$sshd_pid" 2>/dev/null
  rm -rf "$dir"
}
trap cleanup EXIT HUP INT TERM

fails=0
fail ()
{
  echo "FAIL: $*"
  fails=$((fails + 1))
}

user=$(id -un)
now=$(date +%s)
from=$((now - 3600))
to=$((now + 3600))
export TZ=UTC

keys="ed25519 ecdsa rsa"
for t in $keys; do
  b=; [ $t = rsa ] && b="-b 2048"
  $SSH_KEYGEN -q -t $t $b -N '' -f "$dir/ca_$t" || exit 99
  $SSH_KEYGEN -q -t $t $b -N '' -f "$dir/uk_$t" || exit 99
  $SSH_KEYGEN -q -t $t $b -N '' -f "$dir/hk_$t" || exit 99
done

sign ()		# ARGS...    (foxtrot's signer)
{
  "$SIGN" "$@" || { fail "interop-sign $*"; return 1; }
}

# ---------------------------------------------------------------------
# What ssh-keygen -L reads
# ---------------------------------------------------------------------

sign --ca "$dir/ca_ed25519" --key "$dir/uk_ecdsa.pub" --out "$dir/all.pub" \
  --id 'full id' --principals alice,bob --serial 123456789012 \
  --from 1577836800 --to 4102444799 --allow all \
  --force-command '/bin/echo hi' --source-address 192.0.2.0/24,2001:db8::/32
$SSH_KEYGEN -L -f "$dir/all.pub" > "$dir/L.out" 2>&1 || fail "ssh-keygen -L would not read the certificate"
for want in 'ecdsa-sha2-nistp256-cert-v01@openssh.com user certificate' \
  'Key ID: "full id"' 'Serial: 123456789012' \
  'from 2020-01-01T00:00:00 to 2099-12-31T23:59:59' \
  'alice' 'bob' 'force-command /bin/echo hi' \
  'source-address 192.0.2.0/24,2001:db8::/32' 'permit-pty' \
  'permit-port-forwarding' 'permit-agent-forwarding' 'permit-X11-forwarding' \
  'permit-user-rc' '(using ssh-ed25519)'; do
  grep -qF -- "$want" "$dir/L.out" || { fail "ssh-keygen -L: no \"$want\""; cat "$dir/L.out"; }
done
sign --ca "$dir/ca_rsa" --key "$dir/hk_rsa.pub" --out "$dir/host.pub" --host \
  --id host --principals '*.example.org,example.com' --from 1577836800 --to 4102444799
$SSH_KEYGEN -L -f "$dir/host.pub" > "$dir/L.out" 2>&1 || fail "ssh-keygen -L: host certificate"
grep -q 'ssh-rsa-cert-v01@openssh.com host certificate' "$dir/L.out" || fail "ssh-keygen -L: not a host certificate"
grep -q '(using rsa-sha2-512)' "$dir/L.out" || fail "ssh-keygen -L: RSA CA did not sign with SHA-512"
grep -q '\*\.example\.org' "$dir/L.out" || fail "ssh-keygen -L: host principals"
sign --ca "$dir/ca_rsa" --key "$dir/hk_rsa.pub" --out "$dir/host256.pub" --host \
  --id host --principals example.com --alg rsa-sha2-256
$SSH_KEYGEN -L -f "$dir/host256.pub" 2>&1 | grep -q '(using rsa-sha2-256)' || fail "ssh-keygen -L: SHA-256 was not used when asked"
sign --ca "$dir/ca_ed25519" --key "$dir/uk_ed25519.pub" --out "$dir/none.pub" \
  --id none --principals alice
$SSH_KEYGEN -L -f "$dir/none.pub" > "$dir/L.out" 2>&1
grep -q 'Critical Options: (none)' "$dir/L.out" || fail "ssh-keygen -L: options on a certificate with none"
grep -q 'Extensions: (none)' "$dir/L.out" || fail "ssh-keygen -L: extensions on a certificate that permits nothing"

# ---------------------------------------------------------------------
# sshd takes them
# ---------------------------------------------------------------------

cat "$dir"/ca_*.pub > "$dir/trusted_cas"
port=$((20000 + $$ % 20000 + 7))
# The host key's certificate, signed by foxtrot (each kind of CA in turn).
sign --ca "$dir/ca_ed25519" --key "$dir/hk_ed25519.pub" --out "$dir/hk_ed25519-cert.pub" \
  --host --id host-ed --principals 127.0.0.1,localhost --from "$from" --to "$to"
sign --ca "$dir/ca_ecdsa" --key "$dir/hk_ecdsa.pub" --out "$dir/hk_ecdsa-cert.pub" \
  --host --id host-ec --principals 127.0.0.1,localhost --from "$from" --to "$to"
sign --ca "$dir/ca_rsa" --key "$dir/hk_rsa.pub" --out "$dir/hk_rsa-cert.pub" \
  --host --id host-rsa --principals 127.0.0.1,localhost --from "$from" --to "$to"
cat > "$dir/sshd_config" <<EOT
Port $port
ListenAddress 127.0.0.1
HostKey $dir/hk_ed25519
HostKey $dir/hk_ecdsa
HostKey $dir/hk_rsa
HostCertificate $dir/hk_ed25519-cert.pub
HostCertificate $dir/hk_ecdsa-cert.pub
HostCertificate $dir/hk_rsa-cert.pub
PidFile $dir/sshd.pid
TrustedUserCAKeys $dir/trusted_cas
AuthorizedKeysFile none
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
LogLevel ERROR
EOT
"$SSHD" -D -e -f "$dir/sshd_config" > "$dir/sshd.log" 2>&1 &
sshd_pid=$!
i=0
while [ $i -lt 50 ]; do
  (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break
  kill -0 "$sshd_pid" 2>/dev/null || break
  sleep 0.1
  i=$((i + 1))
done
if ! kill -0 "$sshd_pid" 2>/dev/null; then
  cat "$dir/sshd.log"
  echo "sshd would not start; skipping"
  sshd_pid=
  exit 77
fi

# The host certificates are trusted by the CAs: all three are in known_hosts.
for t in $keys; do
  echo "@cert-authority * $(cut -d' ' -f1,2 "$dir/ca_$t.pub")"
done > "$dir/known_hosts"

# run_ssh KEY CERT [SSH-OPTION...] -- COMMAND...
sshopts="-o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$dir/known_hosts -o IdentitiesOnly=yes -o ConnectTimeout=10 -p $port"
run_ssh ()
{
  rk=$1; rc=$2; shift 2
  ro=
  while [ $# -gt 0 ] && [ "$1" != -- ]; do ro="$ro $1"; shift; done
  [ "$1" = -- ] && shift
  # shellcheck disable=SC2086
  timeout 60 "$SSH" $sshopts -i "$dir/$rk" -o CertificateFile="$dir/$rc" $ro \
    "$user@127.0.0.1" "$@" > "$dir/ssh.out" 2> "$dir/ssh.err" < /dev/null
}

# A certificate from a CA of each kind for a key of each kind.
for ca in $keys; do
  for k in $keys; do
    sign --ca "$dir/ca_$ca" --key "$dir/uk_$k.pub" --out "$dir/u_${ca}_$k.pub" \
      --id "u-$ca-$k" --principals "$user" --from "$from" --to "$to" --allow all
    run_ssh uk_$k u_${ca}_$k.pub -- echo ok-$ca-$k \
      || { fail "ssh with a $ca-signed certificate for a $k key"; cat "$dir/ssh.err"; }
    grep -q "^ok-$ca-$k" "$dir/ssh.out" || fail "ssh $ca $k: no output"
  done
done

# What must not work.
refuse ()	# NAME CERT
{
  if run_ssh uk_ed25519 "$2" -- true; then
    fail "sshd accepted $1"
  fi
}
sign --ca "$dir/ca_ed25519" --key "$dir/uk_ed25519.pub" --out "$dir/expired.pub" \
  --id expired --principals "$user" --from $((now - 7200)) --to $((now - 3600))
refuse "an expired certificate" expired.pub
sign --ca "$dir/ca_ed25519" --key "$dir/uk_ed25519.pub" --out "$dir/early.pub" \
  --id early --principals "$user" --from $((now + 3600)) --to $((now + 7200))
refuse "a certificate not yet valid" early.pub
sign --ca "$dir/ca_ed25519" --key "$dir/uk_ed25519.pub" --out "$dir/other.pub" \
  --id other --principals somebody-else --from "$from" --to "$to"
refuse "a certificate for another principal" other.pub
sign --ca "$dir/ca_ed25519" --key "$dir/uk_ed25519.pub" --out "$dir/elsewhere.pub" \
  --id elsewhere --principals "$user" --from "$from" --to "$to" --source-address 192.0.2.0/24
refuse "a certificate for another source address" elsewhere.pub
$SSH_KEYGEN -q -t ed25519 -N '' -f "$dir/ca_other" || exit 99
sign --ca "$dir/ca_other" --key "$dir/uk_ed25519.pub" --out "$dir/untrusted.pub" \
  --id untrusted --principals "$user" --from "$from" --to "$to"
refuse "a certificate from a CA it does not trust" untrusted.pub
# One that is not ours any more: a bit flipped in the signed part.
python3 - "$dir/u_ed25519_ed25519.pub" "$dir/flipped.pub" <<'PY' 2>/dev/null || true
import base64, sys
t, k, *rest = open(sys.argv[1]).read().split()
b = bytearray(base64.b64decode(k))
b[100] ^= 1
open(sys.argv[2], 'w').write(t + ' ' + base64.b64encode(bytes(b)).decode() + '\n')
PY
[ -f "$dir/flipped.pub" ] && refuse "a certificate with a bit changed" flipped.pub

# Forced command and source address, honoured by sshd.
sign --ca "$dir/ca_ed25519" --key "$dir/uk_ed25519.pub" --out "$dir/forced.pub" \
  --id forced --principals "$user" --from "$from" --to "$to" \
  --force-command 'echo forced' --source-address 127.0.0.0/8
run_ssh uk_ed25519 forced.pub -- echo asked || fail "ssh with a forced command certificate"
grep -q '^forced' "$dir/ssh.out" || fail "sshd did not run the forced command"
grep -q '^asked' "$dir/ssh.out" && fail "sshd ran the command the client asked for"

# Permissions: a pty only if the certificate says so.
sign --ca "$dir/ca_ed25519" --key "$dir/uk_ed25519.pub" --out "$dir/nopty.pub" \
  --id nopty --principals "$user" --from "$from" --to "$to"
run_ssh uk_ed25519 nopty.pub -tt -- true
grep -q 'PTY allocation request failed' "$dir/ssh.err" || fail "sshd gave a pty to a certificate that permits none"
sign --ca "$dir/ca_ed25519" --key "$dir/uk_ed25519.pub" --out "$dir/pty.pub" \
  --id pty --principals "$user" --from "$from" --to "$to" --allow pty
run_ssh uk_ed25519 pty.pub -tt -- true
grep -q 'PTY allocation request failed' "$dir/ssh.err" && fail "sshd refused a pty to a certificate that permits one"

# ---------------------------------------------------------------------
# ssh takes the host certificates (sshd presented them above, for each
# algorithm in turn) and refuses them from CAs it does not know.
# ---------------------------------------------------------------------

for h in ssh-ed25519-cert-v01@openssh.com ecdsa-sha2-nistp256-cert-v01@openssh.com \
         rsa-sha2-512-cert-v01@openssh.com; do
  run_ssh uk_ed25519 u_ed25519_ed25519.pub -o HostKeyAlgorithms=$h -- echo host-ok \
    || { fail "ssh with the host certificate $h"; cat "$dir/ssh.err"; }
  grep -q host-ok "$dir/ssh.out" || fail "ssh $h: no output"
done
echo "@cert-authority * $(cut -d' ' -f1,2 "$dir/ca_other.pub")" > "$dir/known_hosts"
run_ssh uk_ed25519 u_ed25519_ed25519.pub -o HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com -- true \
  && fail "ssh trusted a host certificate from a CA it does not know"
echo "@cert-authority www.example.org $(cut -d' ' -f1,2 "$dir/ca_ed25519.pub")" > "$dir/known_hosts"
run_ssh uk_ed25519 u_ed25519_ed25519.pub -o HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com -- true \
  && fail "ssh trusted a host certificate for another name"

if [ $fails -ne 0 ]; then
  echo "$fails certificate signing failures"
  exit 1
fi
echo "certificate signing: all passed"
exit 0
