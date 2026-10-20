##
## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of foxtrot.
##
## foxtrot is free software: you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published
## by the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## foxtrot is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public
## License along with this program.  If not, see
## <https://www.gnu.org/licenses/>.

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS)
LDADD = $(top_builddir)/src/libfoxtrot.la

UNIT_TESTS = test-wire test-packet test-ident test-key test-kex test-kexinit test-policy test-conn test-conn-attack test-auth

TESTS = $(UNIT_TESTS)
check_PROGRAMS = $(UNIT_TESTS)

EXTRA_DIST = tst-util.h tst-pair.h vectors-packet.h gen-packet-vectors.py \
  vectors-key.h gen-key-vectors.py \
  vectors-kex.h gen-kex-vectors.py

# Calls libgcrypt's KEM interface directly to check the hybrid methods'
# composition from outside.
test_kex_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_kex_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
