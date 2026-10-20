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

## The integration suite: tests that use real I/O (sockets, processes, files,
## the host's own programs) or the real clock, and so can be slow, depend
## on what the host has installed, and fail for reasons outside the
## library.  The unit tests are in ../tests and are what "make check"
## runs; this directory is not part of "make", "make check" or "make
## install", only of "make check-integration" at the top level (or "make
## check" here).  Each test skips itself (exit 77) when what it needs is not
## there.

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS)
LDADD = $(top_builddir)/src/libfoxtrot.la

INTEGRATION_PROGS = interop-server interop-client interop-key interop-sign
INTEGRATION_TESTS = interop-openssh.sh interop-keyfiles.sh interop-certsign.sh

interop_server_SOURCES = interop-server.c interop-util.h
interop_client_SOURCES = interop-client.c interop-util.h
interop_key_SOURCES = interop-key.c
interop_sign_SOURCES = interop-sign.c

check_PROGRAMS = $(INTEGRATION_PROGS)
TESTS = $(INTEGRATION_TESTS)

EXTRA_DIST = interop-openssh.sh interop-keyfiles.sh interop-certsign.sh

## The test scripts find the programs next to them.
TESTS_ENVIRONMENT = srcdir=$(srcdir) builddir=$(builddir)
