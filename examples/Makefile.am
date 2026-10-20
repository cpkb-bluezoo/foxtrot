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

## Example programs.  They are built with everything else so that they stay
## true to the headers, run by "make check" (test-examples.sh), and installed
## as source with the documentation, not as programs: they are models to copy
## from.  example.h is what an application supplies that the library leaves
## out (sockets, a clock, an event loop); the rest is about the library.

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS)
LDADD = $(top_builddir)/src/libfoxtrot.la

noinst_PROGRAMS = ssh-run sftp-get ssh-serve keyinfo krl-check cert-sign

TESTS = test-examples.sh
TESTS_ENVIRONMENT = srcdir=$(srcdir) builddir=$(builddir)

examplesdir = $(docdir)/examples
dist_examples_DATA = example.h ssh-run.c sftp-get.c ssh-serve.c keyinfo.c \
  krl-check.c cert-sign.c
EXTRA_DIST = test-examples.sh
