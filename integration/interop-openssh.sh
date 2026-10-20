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

# The transport and user authentication against OpenSSH: foxtrot's client
# against sshd, and ssh against foxtrot's server, for the algorithms they
# have in common, with public key (also host-bound), password and
# keyboard-interactive authentication, with rekeying after authentication,
# and with the algorithms foxtrot refuses, to check that they are refused.  Needs ssh, ssh-keygen and sshd (set SSHD if it is not in
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
command -v sftp >/dev/null 2>&1 || exit 77
[ -x "$SSHD" ] || exit 77

CLIENT=$builddir/interop-client
SERVER=$builddir/interop-server

dir=$(mktemp -d "${TMPDIR:-/tmp}/foxtrot-interop.XXXXXX") || exit 99
sshd_pid=
server_pid=
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

# A port that nothing listens on, we hope: one per call.
portn=0
pick_port ()
{
  portn=$((portn + 1))
  echo $(( 20000 + $$ % 20000 + portn ))
}

for t in ed25519 ecdsa rsa; do
  b=; [ $t = rsa ] && b="-b 2048"
  $SSH_KEYGEN -q -t $t $b -N '' -f "$dir/hk_$t" || exit 99
  # User keys, and the one sshd will not know.
  $SSH_KEYGEN -q -t $t $b -N '' -f "$dir/uk_$t" || exit 99
done
$SSH_KEYGEN -q -t ed25519 -N '' -f "$dir/stranger" || exit 99
cat "$dir"/uk_*.pub > "$dir/authorized_keys"
user=$(id -un)

# ---------------------------------------------------------------------
# foxtrot client against sshd
# ---------------------------------------------------------------------

port=$(pick_port)
cat > "$dir/sshd_config" <<EOT
Port $port
ListenAddress 127.0.0.1
HostKey $dir/hk_ed25519
HostKey $dir/hk_ecdsa
HostKey $dir/hk_rsa
PidFile $dir/sshd.pid
AuthorizedKeysFile $dir/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
LogLevel ERROR
Subsystem sftp internal-sftp
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

client ()
{
  "$CLIENT" "$port" "$@" > "$dir/client.out" 2>&1
}

# Key exchange methods OpenSSH 9.6 has in common with the policy.
for kex in curve25519-sha256 sntrup761x25519-sha512@openssh.com \
           ecdh-sha2-nistp256 ecdh-sha2-nistp384; do
  client --no-auth --kex $kex || { fail "client kex $kex"; cat "$dir/client.out"; }
  grep -q "^KEX .* chacha20" "$dir/client.out" || fail "client kex $kex: not negotiated"
done
for c in chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com; do
  client --no-auth --cipher $c || { fail "client cipher $c"; cat "$dir/client.out"; }
  grep -q "^KEX .* $c " "$dir/client.out" || fail "client cipher $c: not negotiated"
done
for h in ssh-ed25519 ecdsa-sha2-nistp256 rsa-sha2-512 rsa-sha2-256; do
  client --no-auth --hostkey $h || { fail "client hostkey $h"; cat "$dir/client.out"; }
  grep -q "^KEX .* $h\$" "$dir/client.out" || fail "client hostkey $h: not negotiated"
done
# The host key fingerprint is the one ssh-keygen prints.
fp=$($SSH_KEYGEN -l -f "$dir/hk_ed25519.pub" | cut -d' ' -f2)
client --no-auth --hostkey ssh-ed25519 --fingerprint "$fp" || fail "client fingerprint match"
client --no-auth --hostkey ssh-ed25519 --fingerprint SHA256:wrong && fail "client accepted a wrong fingerprint"

# Public key authentication with each kind of key; sshd announces host-bound
# authentication and foxtrot's client then uses it.
for t in ed25519 ecdsa rsa; do
  client --user "$user" --key "$dir/uk_$t" \
    || { fail "client publickey $t"; cat "$dir/client.out"; }
  grep -q '^AUTH OK' "$dir/client.out" || fail "client publickey $t: not authenticated"
done
# A key sshd does not know, and a user it does not have.
client --user "$user" --key "$dir/stranger" && fail "client authenticated with an unknown key"
grep -q '^AUTH FAILED' "$dir/client.out" || fail "unknown key: no failure reported"
client --user no-such-user-here --key "$dir/uk_ed25519" && fail "client authenticated as an unknown user"
# Rekeying after authentication, in the middle of the session.
client --user "$user" --key "$dir/uk_ed25519" --rekey \
  || { fail "client rekey"; cat "$dir/client.out"; }
grep -q '^REKEYED' "$dir/client.out" || fail "client rekey: no rekey"
client --user "$user" --key "$dir/uk_ecdsa" --rekey --kex curve25519-sha256 \
  --cipher aes256-gcm@openssh.com \
  || { fail "client rekey aes-gcm"; cat "$dir/client.out"; }
# Commands in session channels: output, exit status, standard error, and
# bulk data both ways through the flow control, with rekeys on the way.
cli_exec ()
{
  client --user "$user" --key "$dir/uk_ed25519" "$@" \
    || { fail "client exec $*"; cat "$dir/client.out"; }
}
cli_exec --exec "echo hello"
grep -q '^OUT hello' "$dir/client.out" || fail "client exec: no output"
cli_exec --exec "echo oops 1>&2; exit 3"
grep -q '^EXIT 3$' "$dir/client.out" && grep -q '^STDERR 5$' "$dir/client.out" \
  || { fail "client exec: exit status or stderr"; cat "$dir/client.out"; }
cli_exec --exec "head -c 5000000 /dev/zero"
grep -q '^RECEIVED 5000000$' "$dir/client.out" || { fail "client download"; cat "$dir/client.out"; }
cli_exec --exec "wc -c" --send 3000000
grep -q '^OUT 3000000' "$dir/client.out" || { fail "client upload"; cat "$dir/client.out"; }
cli_exec --exec "head -c 8000000 /dev/zero" --rekey-bytes 1000000
grep -q '^RECEIVED 8000000$' "$dir/client.out" && grep -q '^REKEYED' "$dir/client.out" \
  || { fail "client download with rekeys"; cat "$dir/client.out"; }
cli_exec --exec cat --send 6000000 --check-pattern --rekey-bytes 1500000 \
  --cipher aes256-gcm@openssh.com
grep -q '^RECEIVED 6000000$' "$dir/client.out" && grep -q '^SENT 6000000$' "$dir/client.out" \
  && grep -q '^REKEYED' "$dir/client.out" && ! grep -q 'BAD DATA' "$dir/client.out" \
  || { fail "client cat roundtrip with rekeys"; cat "$dir/client.out"; }
# A command that does not exist is a status, not a failure of the protocol.
cli_exec --exec "exit 7"
grep -q '^EXIT 7$' "$dir/client.out" || fail "client exit 7"
# SFTP: a big file both ways through pipelined reads and writes, with rekeys,
# the other operations, and the statuses of the ones that fail.
mkdir "$dir/cr" "$dir/cr/d"
head -c 12000000 /dev/urandom > "$dir/cr/up.bin"
echo "from sshd" > "$dir/cr/remote.txt"
cli_exec --sftp "put $dir/cr/up.bin $dir/cr/up.copy; get $dir/cr/up.copy $dir/cr/down.bin" \
  --rekey-bytes 3000000
cmp -s "$dir/cr/up.bin" "$dir/cr/up.copy" || fail "sftp put of 12 MB"
cmp -s "$dir/cr/up.bin" "$dir/cr/down.bin" || fail "sftp get of 12 MB"
grep -q '^REKEYED' "$dir/client.out" || fail "sftp: no rekey during the transfer"
cli_exec --sftp "stat $dir/cr/up.copy; chmod 600 $dir/cr/up.copy; stat $dir/cr/up.copy; mkdir $dir/cr/d/e; ls $dir/cr/d; mv $dir/cr/up.copy $dir/cr/d/e/moved; ln remote.txt $dir/cr/lnk; readlink $dir/cr/lnk; realpath $dir/cr/d/../remote.txt; rm $dir/cr/lnk; rmdir $dir/cr/d/e; get $dir/cr/nosuch $dir/cr/x; rmdir $dir/cr/nodir; stat $dir/cr/nosuch"
grep -q '^STAT size=12000000 perms=644$' "$dir/client.out" \
  && grep -q '^STAT size=12000000 perms=600$' "$dir/client.out" \
  && grep -q '^LS e ' "$dir/client.out" && grep -q '^NAME remote.txt$' "$dir/client.out" \
  && grep -q "^NAME $dir/cr/remote.txt\$" "$dir/client.out" \
  || { fail "sftp operations"; cat "$dir/client.out"; }
[ "$(grep -c '^RESULT .* 2$' "$dir/client.out")" = 3 ] || fail "sftp: missing-file statuses"
grep -q '^RESULT rmdir 4$' "$dir/client.out" || fail "sftp: rmdir of a non-empty directory"
# Keys alone offer nothing sshd (password and k-i off) would take.
client --user "$user" --password hunter2 && fail "client authenticated with a password sshd does not take"

kill "$sshd_pid" 2>/dev/null
wait "$sshd_pid" 2>/dev/null
sshd_pid=

# The same server, but one that only has ciphers foxtrot refuses.
port=$(pick_port)
sed -e "s/^Port .*/Port $port/" "$dir/sshd_config" > "$dir/sshd_config2"
echo "Ciphers aes128-ctr,aes256-ctr,aes128-cbc" >> "$dir/sshd_config2"
"$SSHD" -D -e -f "$dir/sshd_config2" > "$dir/sshd2.log" 2>&1 &
sshd_pid=$!
sleep 1
client --no-auth && fail "client connected to a server with only CTR/CBC ciphers"
grep -q '^CLOSED' "$dir/client.out" || fail "refusal not reported"
kill "$sshd_pid" 2>/dev/null
wait "$sshd_pid" 2>/dev/null
sshd_pid=

# ---------------------------------------------------------------------
# ssh against foxtrot's server
# ---------------------------------------------------------------------

sshopts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
-o ConnectTimeout=10 -o IdentitiesOnly=yes -o LogLevel=ERROR"

# The askpass program answers every prompt with $ASKPASS_ANSWER.
cat > "$dir/askpass" <<'EOT'
#!/bin/sh
echo "$ASKPASS_ANSWER"
EOT
chmod +x "$dir/askpass"

# run_ssh HOSTKEY SERVER-OPTIONS -- SSH-OPTIONS
run_ssh ()
{
  hk=$1; shift
  sopts=
  while [ $# -gt 0 ] && [ "$1" != -- ]; do sopts="$sopts $1"; shift; done
  [ "$1" = -- ] && shift
  sport=$(pick_port)
  # shellcheck disable=SC2086
  "$SERVER" "$dir/$hk" "$sport" $sopts > "$dir/server.out" 2>&1 &
  server_pid=$!
  i=0
  while [ $i -lt 30 ] && ! grep -q READY "$dir/server.out" 2>/dev/null; do
    sleep 0.1
    i=$((i + 1))
  done
  # shellcheck disable=SC2086
  SSH_ASKPASS="$dir/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=none \
  timeout 60 "$SSH" $sshopts -p "$sport" "$@" "$user@127.0.0.1" ${SSH_CMD:-true} \
    > "${SSH_OUT:-$dir/ssh.out}" 2> "$dir/ssh.err" < "${SSH_IN:-/dev/null}"
  cat "$dir/ssh.err" >> "$dir/ssh.out" 2>/dev/null
  sleep 0.3
  kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null
  server_pid=
}

# Each kind of host key, with public key authentication.
for hk in hk_ed25519 hk_ecdsa hk_rsa; do
  run_ssh $hk --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes -i "$dir/uk_ed25519"
  grep -q "^AUTH OK $user publickey\$" "$dir/server.out" \
    || { fail "ssh against foxtrot with $hk"; cat "$dir/ssh.out" "$dir/server.out"; }
done

# Each kind of user key.
for t in ed25519 ecdsa rsa; do
  run_ssh hk_ed25519 --auth-key "$dir/uk_$t" -- -o BatchMode=yes -i "$dir/uk_$t"
  grep -q "^AUTH OK $user publickey\$" "$dir/server.out" \
    || { fail "ssh user key $t"; cat "$dir/ssh.out" "$dir/server.out"; }
done
# Host-bound: ssh uses it when the server announces it.
run_ssh hk_ed25519 --auth-key "$dir/uk_ecdsa" --hostbound -- -o BatchMode=yes -i "$dir/uk_ecdsa"
grep -q "^AUTH OK $user publickey-hostbound\$" "$dir/server.out" \
  || { fail "ssh host-bound publickey"; cat "$dir/ssh.out" "$dir/server.out"; }
# A key the server does not know.
run_ssh hk_ed25519 --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes -i "$dir/stranger"
grep -q '^AUTH OK' "$dir/server.out" && fail "ssh authenticated with an unknown key"
# Password, right and wrong.
ASKPASS_ANSWER=hunter2 run_ssh hk_ed25519 --password hunter2 -- \
  -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1
grep -q "^AUTH OK $user password\$" "$dir/server.out" \
  || { fail "ssh password"; cat "$dir/ssh.out" "$dir/server.out"; }
ASKPASS_ANSWER=wrong run_ssh hk_ed25519 --password hunter2 -- \
  -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1
grep -q '^AUTH OK' "$dir/server.out" && fail "ssh authenticated with a wrong password"
# Keyboard-interactive.
ASKPASS_ANSWER=4711 run_ssh hk_ed25519 --code 4711 -- \
  -o PreferredAuthentications=keyboard-interactive -o NumberOfPasswordPrompts=1
grep -q "^AUTH OK $user keyboard-interactive\$" "$dir/server.out" \
  || { fail "ssh keyboard-interactive"; cat "$dir/ssh.out" "$dir/server.out"; }
ASKPASS_ANSWER=0000 run_ssh hk_ed25519 --code 4711 -- \
  -o PreferredAuthentications=keyboard-interactive -o NumberOfPasswordPrompts=1
grep -q '^AUTH OK' "$dir/server.out" && fail "ssh authenticated with a wrong code"
# The server offers only what it has: a client that has a password and
# the server only a key.
ASKPASS_ANSWER=hunter2 run_ssh hk_ed25519 --auth-key "$dir/uk_ed25519" -- \
  -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1
grep -q '^AUTH OK' "$dir/server.out" && fail "ssh used a method the server does not offer"

# Commands in session channels served by foxtrot, bulk data both ways with
# rekeys, standard error, and exit status.
SSH_CMD="echo hello world" run_ssh hk_ed25519 --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes -i "$dir/uk_ed25519"
grep -q '^hello world$' "$dir/ssh.out" || { fail "ssh exec echo"; cat "$dir/ssh.out" "$dir/server.out"; }
SSH_CMD="exit 5" run_ssh hk_ed25519 --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes -i "$dir/uk_ed25519"
grep -q '^EXEC exit 5$' "$dir/server.out" || fail "ssh exec exit 5: not run"
SSH_CMD="stderr oops" run_ssh hk_ed25519 --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes -i "$dir/uk_ed25519"
grep -q '^oops' "$dir/ssh.out" || fail "ssh exec stderr"
head -c 3000000 /dev/urandom > "$dir/big.bin"
SSH_CMD=cat SSH_IN="$dir/big.bin" SSH_OUT="$dir/big.out" run_ssh hk_ed25519 \
  --auth-key "$dir/uk_ed25519" --rekey-bytes 700000 -- -o BatchMode=yes -i "$dir/uk_ed25519"
cmp -s "$dir/big.bin" "$dir/big.out" || { fail "ssh cat roundtrip of 3 MB with rekeys"; ls -l "$dir/big.out"; cat "$dir/server.out"; }
SSH_CMD="bytes 5000000" SSH_OUT="$dir/bytes.out" run_ssh hk_ed25519 \
  --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes -i "$dir/uk_ed25519"
[ "$(wc -c < "$dir/bytes.out")" = 5000000 ] || fail "ssh bytes 5000000"
# SFTP served by foxtrot to OpenSSH's sftp client, over a directory.
mkdir "$dir/sroot" "$dir/local"
echo "hello sftp" > "$dir/sroot/small.txt"
head -c 20000000 /dev/urandom > "$dir/local/big.bin"
cat > "$dir/batch" <<EOT
pwd
ls
get small.txt $dir/local/small.copy
put $dir/local/big.bin up.bin
mkdir sub
rename up.bin sub/up2.bin
ls -l sub
chmod 600 sub/up2.bin
ln -s small.txt sub/lnk
get sub/up2.bin $dir/local/big.back
rm sub/lnk
rm sub/up2.bin
rmdir sub
get ../../../../etc/passwd $dir/local/escape
EOT
sport=$(pick_port)
"$SERVER" "$dir/hk_ed25519" "$sport" --auth-key "$dir/uk_ed25519" --sftp-root "$dir/sroot" \
  --rekey-bytes 5000000 > "$dir/server.out" 2>&1 &
server_pid=$!
i=0
while [ $i -lt 30 ] && ! grep -q READY "$dir/server.out" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
# shellcheck disable=SC2086
timeout 120 sftp $sshopts -o BatchMode=yes -i "$dir/uk_ed25519" -P "$sport" -b "$dir/batch" \
  "$user@127.0.0.1" > "$dir/sftp.out" 2>&1
sleep 0.3
kill "$server_pid" 2>/dev/null
wait "$server_pid" 2>/dev/null
server_pid=
cmp -s "$dir/local/big.bin" "$dir/local/big.back" || { fail "sftp 20 MB roundtrip through foxtrot"; cat "$dir/sftp.out" "$dir/server.out"; }
[ "$(cat "$dir/local/small.copy" 2>/dev/null)" = "hello sftp" ] || fail "sftp get of a small file"
[ -e "$dir/sroot/sub" ] && fail "sftp: directory left behind"
[ -e "$dir/local/escape" ] && fail "sftp: a path with .. left the root"
grep -q 'Remote working directory: /' "$dir/sftp.out" || { fail "sftp pwd"; cat "$dir/sftp.out"; }
grep -q '^SFTP START' "$dir/server.out" || fail "sftp: server did not start it"

# Port forwarding: ssh -L through a direct-tcpip channel that foxtrot echoes,
# and -R, which foxtrot grants.
if command -v python3 >/dev/null 2>&1; then
  sport=$(pick_port)
  "$SERVER" "$dir/hk_ed25519" "$sport" --auth-key "$dir/uk_ed25519" > "$dir/server.out" 2>&1 &
  server_pid=$!
  i=0
  while [ $i -lt 30 ] && ! grep -q READY "$dir/server.out" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
  lport=$((sport + 1000))
  rport=$((sport + 2000))
  # shellcheck disable=SC2086
  $SSH $sshopts -o BatchMode=yes -o ExitOnForwardFailure=yes -i "$dir/uk_ed25519" \
    -N -L "$lport:echo.example:7" -R "$rport:localhost:9" -p "$sport" \
    "$user@127.0.0.1" > "$dir/fwd.out" 2>&1 &
  fwd_pid=$!
  sleep 1.5
  python3 - "$lport" > "$dir/fwd.py.out" 2>&1 <<'EOT'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
data = bytes(range(256)) * 4000
s.sendall(data)
s.shutdown(socket.SHUT_WR)
got = b""
while True:
    d = s.recv(65536)
    if not d:
        break
    got += d
print("OK" if got == data else "MISMATCH")
EOT
  grep -q '^OK$' "$dir/fwd.py.out" || { fail "ssh -L through foxtrot"; cat "$dir/fwd.py.out" "$dir/fwd.out"; }
  kill "$fwd_pid" 2>/dev/null
  wait "$fwd_pid" 2>/dev/null
  sleep 0.3
  grep -q '^FORWARD echo.example 7$' "$dir/server.out" || fail "ssh -L: no direct-tcpip request"
  grep -q '^TCPIP-FORWARD localhost' "$dir/server.out" || fail "ssh -R: no tcpip-forward request"
  kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null
  server_pid=
fi

# Each cipher and key exchange OpenSSH can offer that foxtrot accepts.
for c in chacha20-poly1305@openssh.com aes128-gcm@openssh.com aes256-gcm@openssh.com; do
  run_ssh hk_ed25519 --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes \
    -i "$dir/uk_ed25519" -o Ciphers=$c
  grep -q "^KEX .* $c " "$dir/server.out" || fail "server cipher $c: not negotiated"
  grep -q '^AUTH OK' "$dir/server.out" || fail "ssh cipher $c"
done
for k in curve25519-sha256 sntrup761x25519-sha512@openssh.com ecdh-sha2-nistp256 ecdh-sha2-nistp384; do
  run_ssh hk_ed25519 --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes \
    -i "$dir/uk_ed25519" -o KexAlgorithms=$k
  grep -q '^AUTH OK' "$dir/server.out" || { fail "ssh kex $k"; cat "$dir/ssh.out"; }
done
run_ssh hk_rsa --auth-key "$dir/uk_rsa" -- -o BatchMode=yes -i "$dir/uk_rsa" \
  -o HostKeyAlgorithms=rsa-sha2-256
grep -q '^AUTH OK' "$dir/server.out" || { fail "ssh rsa-sha2-256"; cat "$dir/ssh.out"; }

# What foxtrot refuses, which OpenSSH still can do: none of these may connect.
for opt in "-o Ciphers=aes128-ctr" "-o Ciphers=aes256-cbc" \
           "-o KexAlgorithms=diffie-hellman-group14-sha256" \
           "-o KexAlgorithms=diffie-hellman-group-exchange-sha256" \
           "-o KexAlgorithms=ecdh-sha2-nistp521" \
           "-o HostKeyAlgorithms=ecdsa-sha2-nistp521 -o KexAlgorithms=ecdh-sha2-nistp256" \
           "-o HostKeyAlgorithms=ssh-rsa"; do
  # shellcheck disable=SC2086
  run_ssh hk_ed25519 --auth-key "$dir/uk_ed25519" -- -o BatchMode=yes \
    -i "$dir/uk_ed25519" $opt
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
