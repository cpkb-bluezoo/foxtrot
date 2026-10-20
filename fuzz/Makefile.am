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

## Fuzz targets.  Each is a libFuzzer target (LLVMFuzzerTestOneInput) linked
## here with a small driver, so that "make check" runs it over its corpus:
## what fuzzing once found stays fixed.  To fuzz, build with the sanitizers
## and run a target with mutation (see HACKING):
##
##   ./fuzz-key -runs=1000000 corpus/key
##
## or, with clang, link a target with -fsanitize=fuzzer instead of driver.c.
## The corpus (corpus/) is made from the vectors of ../tests by gen-seeds.py,
## and grows with the inputs that found something.

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir) -I$(top_srcdir)/tests
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS)
LDADD = $(top_builddir)/src/libfoxtrot.la

FUZZ_TARGETS = fuzz-wire fuzz-ident fuzz-packet fuzz-kexinit fuzz-key \
  fuzz-keytext fuzz-keyfile fuzz-knownhosts fuzz-x509 fuzz-auth \
  fuzz-chans fuzz-sftp fuzz-conn fuzz-authkeys

check_PROGRAMS = $(FUZZ_TARGETS)
TESTS = $(FUZZ_TARGETS)
LOG_COMPILER = $(SHELL) $(srcdir)/run-corpus.sh

fuzz_wire_SOURCES = fuzz-wire.c driver.c fuzz-common.h
fuzz_ident_SOURCES = fuzz-ident.c driver.c fuzz-common.h
fuzz_packet_SOURCES = fuzz-packet.c driver.c fuzz-common.h
fuzz_kexinit_SOURCES = fuzz-kexinit.c driver.c fuzz-common.h
fuzz_key_SOURCES = fuzz-key.c driver.c fuzz-common.h
fuzz_keytext_SOURCES = fuzz-keytext.c driver.c fuzz-common.h
fuzz_keyfile_SOURCES = fuzz-keyfile.c driver.c fuzz-common.h
fuzz_keyfile_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
fuzz_keyfile_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
fuzz_knownhosts_SOURCES = fuzz-knownhosts.c driver.c fuzz-common.h
fuzz_x509_SOURCES = fuzz-x509.c driver.c fuzz-common.h
fuzz_auth_SOURCES = fuzz-auth.c driver.c fuzz-common.h
fuzz_chans_SOURCES = fuzz-chans.c driver.c fuzz-common.h
fuzz_sftp_SOURCES = fuzz-sftp.c driver.c fuzz-common.h
fuzz_conn_SOURCES = fuzz-conn.c driver.c fuzz-common.h
fuzz_authkeys_SOURCES = fuzz-authkeys.c driver.c fuzz-common.h

EXTRA_DIST = run-corpus.sh gen-seeds.py lsan.supp corpus
