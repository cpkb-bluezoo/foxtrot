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

lib_LTLIBRARIES = libfoxtrot.la

libfoxtrot_la_SOURCES = \
  auth.c \
  chan.c \
  conn.c \
  crypto.c \
  gettext.h \
  internal.h \
  ident.c \
  kex.c \
  kexinit.c \
  key.c \
  packet.c \
  policy.c \
  sftp.c \
  status.c \
  wire.c

libfoxtrot_la_CPPFLAGS = -I$(top_srcdir)/include \
  -DLOCALEDIR=\"$(localedir)\"
libfoxtrot_la_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS) $(LIBGCRYPT_CFLAGS) $(GNUTLS_CFLAGS)
libfoxtrot_la_LIBADD = $(LIBGCRYPT_LIBS) $(GNUTLS_LIBS) $(LTLIBINTL)
libfoxtrot_la_LDFLAGS = -version-info $(LIBFOXTROT_LTVERSION) \
  -export-symbols-regex '^gf_'

foxtrotincludedir = $(includedir)/foxtrot
foxtrotinclude_HEADERS = \
  $(top_srcdir)/include/foxtrot/auth.h \
  $(top_srcdir)/include/foxtrot/chan.h \
  $(top_srcdir)/include/foxtrot/conn.h \
  $(top_srcdir)/include/foxtrot/crypto.h \
  $(top_srcdir)/include/foxtrot/ident.h \
  $(top_srcdir)/include/foxtrot/kex.h \
  $(top_srcdir)/include/foxtrot/kexinit.h \
  $(top_srcdir)/include/foxtrot/key.h \
  $(top_srcdir)/include/foxtrot/packet.h \
  $(top_srcdir)/include/foxtrot/policy.h \
  $(top_srcdir)/include/foxtrot/sftp.h \
  $(top_srcdir)/include/foxtrot/status.h \
  $(top_srcdir)/include/foxtrot/wire.h
