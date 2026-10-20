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

# Passphrase-protected private key files against ssh-keygen, with real
# bcrypt-pbkdf (the application's half, here python3's bcrypt module):
# foxtrot reads what ssh-keygen wrote, with each cipher it supports and each
# kind of key, and ssh-keygen reads what foxtrot writes.  Needs ssh-keygen and
# python3 with the bcrypt module; skips itself (exit 77) without them, and when
# GF_NO_INTEROP is set.

srcdir=${srcdir:-.}
builddir=${builddir:-.}

[ -n "$GF_NO_INTEROP" ] && exit 77
SSH_KEYGEN=${SSH_KEYGEN:-ssh-keygen}
command -v "$SSH_KEYGEN" >/dev/null 2>&1 || exit 77
command -v python3 >/dev/null 2>&1 || exit 77
python3 -c 'import bcrypt' >/dev/null 2>&1 || exit 77

KEY=$builddir/interop-key
dir=$(mktemp -d "${TMPDIR:-/tmp}/foxtrot-keyfiles.XXXXXX") || exit 99
trap 'rm -rf "$dir"' EXIT HUP INT TERM

fails=0
fail ()
{
  echo "FAIL: $*"
  fails=$((fails + 1))
}

pass='correct horse battery'
for t in ed25519 ecdsa rsa; do
  b=; [ $t = rsa ] && b="-b 2048"
  for c in aes256-ctr aes128-ctr aes192-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com; do
    f=$dir/k_${t}_$c
    $SSH_KEYGEN -q -t $t $b -N "$pass" -Z $c -a 4 -C '' -f "$f" || exit 99
    want=$(cut -d' ' -f1,2 "$f.pub")
    # foxtrot reads what ssh-keygen wrote.
    got=$("$KEY" decrypt "$f" "$pass" 2>"$dir/err" | sed -n 's/^PUB //p')
    [ "$got" = "$want" ] || { fail "decrypt $t $c"; cat "$dir/err"; }
    # A wrong passphrase is told apart (exit 3).
    "$KEY" decrypt "$f" "not the passphrase" >/dev/null 2>&1
    [ $? -eq 3 ] || fail "wrong passphrase for $t $c is not reported as such"
  done
done

# ssh-keygen reads what foxtrot writes (aes256-gcm), and what it says of it is
# the key we started from.
for t in ed25519 ecdsa rsa; do
  b=; [ $t = rsa ] && b="-b 2048"
  f=$dir/p_$t
  $SSH_KEYGEN -q -t $t $b -N '' -C '' -f "$f" || exit 99
  want=$(cut -d' ' -f1,2 "$f.pub")
  "$KEY" encrypt "$f" "$pass" "$dir/e_$t" 2>"$dir/err" || { fail "encrypt $t"; cat "$dir/err"; }
  chmod 600 "$dir/e_$t"
  got=$($SSH_KEYGEN -y -P "$pass" -f "$dir/e_$t" 2>"$dir/err" | cut -d' ' -f1,2)
  [ "$got" = "$want" ] || { fail "ssh-keygen cannot read foxtrot's $t file"; cat "$dir/err"; }
  $SSH_KEYGEN -y -P "wrong" -f "$dir/e_$t" >/dev/null 2>&1 && fail "ssh-keygen read foxtrot's $t file with a wrong passphrase"
  # And back through foxtrot.
  got=$("$KEY" roundtrip "$dir/e_$t" "$pass" 2>/dev/null | sed -n 's/^PUB //p')
  [ "$got" = "$want" ] || fail "foxtrot round trip $t"
done

if [ $fails -ne 0 ]; then
  echo "$fails key file failures"
  exit 1
fi
echo "Encrypted private key files: all passed"
exit 0
