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

info_TEXINFOS = foxtrot.texi
foxtrot_TEXINFOS = fdl.texi

## The reference pages: section 3 pages made from the public headers by
## gen-man.py (checked in, so that building needs no python), and the overview
## in foxtrot.7.  "make check" says if the headers have changed under them.
include $(srcdir)/man.am

EXTRA_DIST = gen-man.py man.am $(man3_MANS) $(man7_MANS)

check-local:
	@if command -v python3 >/dev/null 2>&1; then \
	  python3 $(srcdir)/gen-man.py --check; \
	fi
