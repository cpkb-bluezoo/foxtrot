/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of foxtrot.

   foxtrot is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   foxtrot is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */

/* Message translation.  Every user-visible string in the library is
   marked with _() and looked up in the "foxtrot" domain.  Without NLS the
   macros vanish.  */

#ifndef GF_GETTEXT_H
#define GF_GETTEXT_H

#ifdef ENABLE_NLS
# include <libintl.h>
# define GF_TEXTDOMAIN "foxtrot"
# define _(msgid) dgettext (GF_TEXTDOMAIN, msgid)
#else
# define _(msgid) (msgid)
#endif

/* Mark a string for extraction without translating it here.  */
#define N_(msgid) (msgid)

/* Bind the message domain to the installed catalogues.  Idempotent; called
   from gf_crypto_init.  */
void gfi_i18n_init (void);

#endif /* GF_GETTEXT_H */
