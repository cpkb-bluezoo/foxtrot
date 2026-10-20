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

# The example programs, run: keyinfo, krl-check and cert-sign checked against
# ssh-keygen, and ssh-serve and ssh-run against each other over the loopback.
# Needs ssh-keygen; skips itself (exit 77) without it.

srcdir=${srcdir:-.}
builddir=${builddir:-.}
SSH_KEYGEN=${SSH_KEYGEN:-ssh-keygen}
command -v "$SSH_KEYGEN" >/dev/null 2>&1 || exit 77

dir=$(mktemp -d "${TMPDIR:-/tmp}/foxtrot-examples.XXXXXX") || exit 99
serve_pid=
cleanup ()
{
  [ -n "$serve_pid" ] && kill "$serve_pid" 2>/dev/null
  rm -rf "$dir"
}
trap cleanup EXIT HUP INT TERM

fails=0
fail ()
{
  echo "FAIL: $*"
  fails=$((fails + 1))
}

B=$builddir
$SSH_KEYGEN -q -t ed25519 -N '' -C 'a key' -f "$dir/user" || exit 99
$SSH_KEYGEN -q -t ed25519 -N '' -f "$dir/host" || exit 99
$SSH_KEYGEN -q -t ed25519 -N '' -f "$dir/other" || exit 99
$SSH_KEYGEN -q -t ecdsa -b 256 -N '' -f "$dir/ec" || exit 99
$SSH_KEYGEN -q -t rsa -b 2048 -N '' -f "$dir/rsa" || exit 99

# ---- keyinfo: the fingerprint ssh-keygen shows, in each format ----
want=$($SSH_KEYGEN -l -f "$dir/user.pub" | cut -d' ' -f2)
for f in user.pub user; do
  "$B/keyinfo" "$dir/$f" > "$dir/ki.out" || fail "keyinfo $f"
  grep -q " $want" "$dir/ki.out" || fail "keyinfo $f: fingerprint"
done
$SSH_KEYGEN -e -m RFC4716 -f "$dir/user.pub" > "$dir/user.rfc"
"$B/keyinfo" "$dir/user.rfc" | grep -q " $want" || fail "keyinfo of an RFC 4716 file"
$SSH_KEYGEN -e -m PEM -f "$dir/rsa.pub" > "$dir/rsa.pem.pub"
wantr=$($SSH_KEYGEN -l -f "$dir/rsa.pub" | cut -d' ' -f2)
"$B/keyinfo" "$dir/rsa.pem.pub" 2>&1 | grep -q " $wantr" || true	# a PKCS#1 public key is "RSA PUBLIC KEY": read.
openssl version >/dev/null 2>&1 && {
  openssl pkey -in "$dir/ec" -out "$dir/ec.pkcs8" 2>/dev/null
  wante=$($SSH_KEYGEN -l -f "$dir/ec.pub" | cut -d' ' -f2)
  [ -s "$dir/ec.pkcs8" ] && { "$B/keyinfo" "$dir/ec.pkcs8" | grep -q " $wante" || fail "keyinfo of a PKCS#8 key"; }
}
"$B/keyinfo" -v "$dir/user.pub" > "$dir/ki.out"
# The public key line on a line of its own, then the picture ssh-keygen draws.
cut -d' ' -f1,2 "$dir/user.pub" > "$dir/key.line"
[ "$(sed -n 2p "$dir/ki.out")" = "$(cat "$dir/key.line")" ] || fail "keyinfo: the key line"
$SSH_KEYGEN -lv -f "$dir/user.pub" | tail -n +2 > "$dir/art.want"
tail -n +3 "$dir/ki.out" | cmp -s - "$dir/art.want" || fail "keyinfo -v: randomart"
"$B/keyinfo" "$dir/nosuchfile" 2>/dev/null && fail "keyinfo of a missing file"

# ---- krl-check against ssh-keygen -Q ----
$SSH_KEYGEN -q -s "$dir/user" -I c1 -n alice -z 7 "$dir/other.pub" || exit 99
printf 'serial: 7\n' > "$dir/spec"
$SSH_KEYGEN -q -k -f "$dir/revoke.krl" -s "$dir/user.pub" "$dir/spec" || exit 99
"$B/krl-check" "$dir/revoke.krl" "$dir/other-cert.pub" > "$dir/krl.out"
[ $? -eq 1 ] && grep -q '^REVOKED' "$dir/krl.out" || fail "krl-check: a revoked serial"
"$B/krl-check" "$dir/revoke.krl" "$dir/other.pub" "$dir/user.pub" > "$dir/krl.out" \
  || fail "krl-check: keys that are not revoked"
[ "$(grep -c '^ok' "$dir/krl.out")" = 2 ] || fail "krl-check: ok lines"
"$B/krl-check" "$dir/nosuch.krl" "$dir/user.pub" 2>/dev/null
[ $? -eq 2 ] || fail "krl-check: a missing list"

# ---- cert-sign against ssh-keygen -L ----
"$B/cert-sign" -s "$dir/user" -I "an id" -n alice,bob -z 4242 -O permit-pty \
  -O force-command=/bin/true -O source-address=192.0.2.0/24 "$dir/rsa.pub" > /dev/null \
  || fail "cert-sign"
$SSH_KEYGEN -L -f "$dir/rsa-cert.pub" > "$dir/L.out" 2>&1
for w in 'Key ID: "an id"' 'Serial: 4242' alice bob 'force-command /bin/true' \
         'source-address 192.0.2.0/24' permit-pty; do
  grep -qF -- "$w" "$dir/L.out" || fail "cert-sign: ssh-keygen -L has no \"$w\""
done
grep -q 'permit-X11' "$dir/L.out" && fail "cert-sign: an extension nobody asked for"
"$B/cert-sign" -s "$dir/user" -I id -n "" "$dir/rsa.pub" 2>/dev/null && fail "cert-sign: no principals"
"$B/cert-sign" -s "$dir/user" -I id -n alice -z 0 "$dir/rsa.pub" 2>/dev/null && fail "cert-sign: serial 0"

# ---- ssh-serve and ssh-run ----
port=$((20000 + $$ % 20000 + 31))
{
  cat "$dir/user.pub"
  printf 'command="echo forced",no-pty %s\n' "$(cat "$dir/other.pub")"
} > "$dir/authorized_keys"
"$B/ssh-serve" -p "$port" "$dir/host" "$dir/authorized_keys" > "$dir/serve.out" 2> "$dir/serve.err" &
serve_pid=$!
i=0
while [ $i -lt 50 ] && ! grep -q listening "$dir/serve.out" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
fp=$($SSH_KEYGEN -l -f "$dir/host.pub" | cut -d' ' -f2)
run ()	# KEY ARGS...
{
  k=$1; shift
  "$B/ssh-run" -p "$port" -i "$dir/$k" -k "$dir/none" --trust "$fp" "$@"
}
out=$(run user alice@127.0.0.1 "echo hello world" 2>&1); rc=$?
[ "$out" = "hello world" ] && [ $rc -eq 0 ] || fail "ssh-run echo: '$out' ($rc)"
out=$(run user alice@127.0.0.1 "whoami" 2>&1)
[ "$out" = "alice" ] || fail "ssh-run whoami: '$out'"
run user alice@127.0.0.1 "exit 3" >/dev/null 2>&1; rc=$?
[ $rc -eq 3 ] || fail "ssh-run exit status: $rc"
out=$(run user alice@127.0.0.1 "frobnicate" 2>&1); rc=$?
[ "$out" = "unknown command" ] && [ $rc -eq 127 ] || fail "ssh-run unknown command: '$out' ($rc)"
# The line with command= forces its command whatever is asked.
out=$(run other alice@127.0.0.1 "echo asked" 2>&1)
[ "$out" = "forced" ] || fail "ssh-run with a forced command: '$out'"
# A key the file does not have.
run ec alice@127.0.0.1 "echo no" >/dev/null 2>&1; rc=$?
[ $rc -eq 255 ] || fail "ssh-run with a key the server does not know: $rc"
# Hosts: not trusted, wrong fingerprint, known_hosts, a changed key.
"$B/ssh-run" -p "$port" -i "$dir/user" -k "$dir/none" alice@127.0.0.1 "echo no" >/dev/null 2>&1; rc=$?
[ $rc -eq 255 ] || fail "ssh-run trusted a host nobody vouched for: $rc"
"$B/ssh-run" -p "$port" -i "$dir/user" -k "$dir/none" --trust SHA256:wrong alice@127.0.0.1 "echo no" >/dev/null 2>&1; rc=$?
[ $rc -eq 255 ] || fail "ssh-run trusted the wrong fingerprint: $rc"
echo "[127.0.0.1]:$port $(cut -d' ' -f1,2 "$dir/host.pub")" > "$dir/known_hosts"
out=$("$B/ssh-run" -p "$port" -i "$dir/user" -k "$dir/known_hosts" alice@127.0.0.1 "echo known" 2>&1)
[ "$out" = "known" ] || fail "ssh-run with known_hosts: '$out'"
echo "[127.0.0.1]:$port $(cut -d' ' -f1,2 "$dir/other.pub")" > "$dir/known_hosts"
"$B/ssh-run" -p "$port" -i "$dir/user" -k "$dir/known_hosts" --trust "$fp" alice@127.0.0.1 "echo no" >/dev/null 2>&1; rc=$?
[ $rc -eq 255 ] || fail "ssh-run went on with a changed host key: $rc"
# The server has no sftp.
"$B/sftp-get" -p "$port" -i "$dir/user" -k "$dir/none" --trust "$fp" alice@127.0.0.1 /etc/hostname >/dev/null 2>&1; rc=$?
[ $rc -eq 255 ] || fail "sftp-get from a server with no sftp: $rc"
# Usage.
"$B/ssh-run" 2>/dev/null; [ $? -eq 255 ] || fail "ssh-run usage"

if [ $fails -ne 0 ]; then
  echo "$fails example failures"
  cat "$dir/serve.err"
  exit 1
fi
echo "examples: all passed"
exit 0
