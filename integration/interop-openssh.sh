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

# The transport layer against OpenSSH: foxtrot's client against sshd, and
# ssh against foxtrot's server, for the algorithms they have in common, with
# rekeying, and with the algorithms foxtrot refuses to check that they are
# refused.  Needs ssh, ssh-keygen and sshd (set SSHD if it is not in
# /usr/sbin); skips itself (exit 77) when they are missing, and when
# GF_NO_INTEROP is set.

srcdir=${srcdir:-.}
builddir=${builddir:-.}

[ -n "$GF_NO_INTEROP" ] && exit 77
SSH=${SSH:-ssh}
SSH_KEYGEN=${SSH_KEYGEN:-ssh-keygen}
SSHD=${SSHD:-/usr/sbin/sshd}
command -v "$SSH" >/dev/null 2>&1 || exit 77
command -v "$SSH_KEYGEN" >/dev/null 2>&1 || exit 77
[ -x "$SSHD" ] || exit 77

CLIENT=$builddir/interop-client
SERVER=$builddir/interop-server

dir=$(mktemp -d "${TMPDIR:-/tmp}/foxtrot-interop.XXXXXX") || exit 99
sshd_pid=
cleanup ()
{
  [ -n "$sshd_pid" ] && kill "$sshd_pid" 2>/dev/null
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null
  rm -rf "$dir"
}
trap cleanup EXIT HUP INT TERM

fails=0
fail ()
{
  echo "FAIL: $*"
  fails=$((fails + 1))
}

# A port that nothing listens on.
pick_port ()
{
  p=$(( 20000 + $$ % 20000 + $1 ))
  echo "$p"
}

for t in ed25519 ecdsa rsa; do
  b=; [ $t = rsa ] && b="-b 2048"
  $SSH_KEYGEN -q -t $t $b -N '' -f "$dir/hk_$t" || exit 99
done

# ---------------------------------------------------------------------
# foxtrot client against sshd
# ---------------------------------------------------------------------

port=$(pick_port 1)
cat > "$dir/sshd_config" <<EOT
Port $port
ListenAddress 127.0.0.1
HostKey $dir/hk_ed25519
HostKey $dir/hk_ecdsa
HostKey $dir/hk_rsa
PidFile $dir/sshd.pid
AuthorizedKeysFile none
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
  grep -q 'Server listening\|Bind' "$dir/sshd.log" 2>/dev/null && break
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

client ()
{
  "$CLIENT" "$port" "$@" > "$dir/client.out" 2>&1
}

# Key exchange methods OpenSSH 9.6 has in common with the policy.
for kex in curve25519-sha256 sntrup761x25519-sha512@openssh.com \
           ecdh-sha2-nistp256 ecdh-sha2-nistp384; do
  client --kex $kex || { fail "client kex $kex"; cat "$dir/client.out"; }
  grep -q "^KEX .* chacha20" "$dir/client.out" || fail "client kex $kex: not negotiated"
done
for c in chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com; do
  client --cipher $c || { fail "client cipher $c"; cat "$dir/client.out"; }
  grep -q "^KEX .* $c " "$dir/client.out" || fail "client cipher $c: not negotiated"
done
for h in ssh-ed25519 ecdsa-sha2-nistp256 rsa-sha2-512 rsa-sha2-256; do
  client --hostkey $h || { fail "client hostkey $h"; cat "$dir/client.out"; }
  grep -q "^KEX .* $h\$" "$dir/client.out" || fail "client hostkey $h: not negotiated"
done
# The host key fingerprint is the one ssh-keygen prints.
fp=$($SSH_KEYGEN -l -f "$dir/hk_ed25519.pub" | cut -d' ' -f2)
client --hostkey ssh-ed25519 --fingerprint "$fp" || fail "client fingerprint match"
client --hostkey ssh-ed25519 --fingerprint SHA256:wrong && fail "client accepted a wrong fingerprint"

kill "$sshd_pid" 2>/dev/null
wait "$sshd_pid" 2>/dev/null
sshd_pid=

# The same server, but one that only has ciphers foxtrot refuses.
port=$(pick_port 2)
sed -e "s/^Port .*/Port $port/" "$dir/sshd_config" > "$dir/sshd_config2"
echo "Ciphers aes128-ctr,aes256-ctr,aes128-cbc" >> "$dir/sshd_config2"
"$SSHD" -D -e -f "$dir/sshd_config2" > "$dir/sshd2.log" 2>&1 &
sshd_pid=$!
sleep 1
client && fail "client connected to a server with only CTR/CBC ciphers"
grep -q '^CLOSED' "$dir/client.out" || fail "refusal not reported"
kill "$sshd_pid" 2>/dev/null
wait "$sshd_pid" 2>/dev/null
sshd_pid=

# ---------------------------------------------------------------------
# ssh against foxtrot's server
# ---------------------------------------------------------------------

sshopts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
-o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes \
-o PreferredAuthentications=publickey -o LogLevel=ERROR"

run_ssh ()    # PORT-OFFSET HOSTKEY [ssh options...]
{
  off=$1; hk=$2; shift 2
  sport=$(pick_port $off)
  "$SERVER" "$dir/$hk" "$sport" > "$dir/server.out" 2>&1 &
  server_pid=$!
  i=0
  while [ $i -lt 30 ] && ! grep -q READY "$dir/server.out" 2>/dev/null; do
    sleep 0.1
    i=$((i + 1))
  done
  # shellcheck disable=SC2086
  timeout 30 "$SSH" $sshopts -p "$sport" "$@" nobody@127.0.0.1 true \
    > "$dir/ssh.out" 2>&1
  sleep 0.3
  kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null
  server_pid=
}

n=10
for hk in hk_ed25519 hk_ecdsa hk_rsa; do
  n=$((n + 1))
  run_ssh $n $hk
  grep -q 'Permission denied (publickey)' "$dir/ssh.out" \
    || { fail "ssh against foxtrot with $hk"; cat "$dir/ssh.out" "$dir/server.out"; }
  grep -q '^KEX ' "$dir/server.out" || fail "server $hk: no transport"
  want=$(grep '^HOSTKEY' "$dir/server.out" | cut -d' ' -f2)
  [ -n "$want" ] || fail "server $hk: no fingerprint"
done

# Each cipher and key exchange OpenSSH can offer that foxtrot accepts.
for c in chacha20-poly1305@openssh.com aes128-gcm@openssh.com aes256-gcm@openssh.com; do
  n=$((n + 1))
  run_ssh $n hk_ed25519 -o Ciphers=$c
  grep -q 'Permission denied (publickey)' "$dir/ssh.out" \
    || { fail "ssh cipher $c"; cat "$dir/ssh.out"; }
  grep -q "^KEX .* $c " "$dir/server.out" || fail "server cipher $c: not negotiated"
done
for k in curve25519-sha256 sntrup761x25519-sha512@openssh.com ecdh-sha2-nistp256 ecdh-sha2-nistp384; do
  n=$((n + 1))
  run_ssh $n hk_ed25519 -o KexAlgorithms=$k
  grep -q 'Permission denied (publickey)' "$dir/ssh.out" \
    || { fail "ssh kex $k"; cat "$dir/ssh.out"; }
done
n=$((n + 1))
run_ssh $n hk_rsa -o HostKeyAlgorithms=rsa-sha2-256
grep -q 'Permission denied (publickey)' "$dir/ssh.out" \
  || { fail "ssh rsa-sha2-256"; cat "$dir/ssh.out"; }

# What foxtrot refuses, which OpenSSH still can do: none of these may connect.
for opt in "-o Ciphers=aes128-ctr" "-o Ciphers=aes256-cbc" \
           "-o KexAlgorithms=diffie-hellman-group14-sha256" \
           "-o KexAlgorithms=diffie-hellman-group-exchange-sha256" \
           "-o KexAlgorithms=ecdh-sha2-nistp521" \
           "-o HostKeyAlgorithms=ecdsa-sha2-nistp521 -o KexAlgorithms=ecdh-sha2-nistp256" \
           "-o HostKeyAlgorithms=ssh-rsa"; do
  n=$((n + 1))
  # shellcheck disable=SC2086
  run_ssh $n hk_ed25519 $opt
  if grep -q 'Permission denied' "$dir/ssh.out"; then
    fail "foxtrot server let ssh $opt connect"
  fi
  # The server ended the exchange itself, having established nothing.
  grep -q '^CLOSED -' "$dir/server.out" \
    || { fail "ssh $opt: not refused by the server"; cat "$dir/ssh.out" "$dir/server.out"; }
  grep -q '^KEX ' "$dir/server.out" && fail "ssh $opt: transport established"
done

if [ $fails -ne 0 ]; then
  echo "$fails interop failures"
  exit 1
fi
echo "OpenSSH interoperability: all passed"
exit 0
