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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <foxtrot/status.h>

#include "gettext.h"

const char *
gf_strerror (int status)
{
  switch (status)
    {
    case GF_OK:			return _("success");
    case GF_NEED_MORE:		return _("more input needed");
    case GF_ERR_INVAL:		return _("invalid argument");
    case GF_ERR_NOMEM:		return _("out of memory");
    case GF_ERR_ENCODING:	return _("malformed wire data");
    case GF_ERR_RANGE:		return _("value out of range");
    case GF_ERR_BUFSIZE:	return _("output buffer too small");
    case GF_ERR_CRYPTO:		return _("cryptographic operation failed");
    case GF_ERR_UNSUPPORTED:	return _("algorithm not permitted by policy");
    case GF_ERR_HANDLER:	return _("handler aborted processing");
    case GF_ERR_HOSTKEY:	return _("host key or signature rejected");
    case GF_ERR_UNAVAILABLE:	return _("feature not compiled in");
    case GF_ERR_PROTOCOL:	return _("protocol violation");
    case GF_ERR_TIMEOUT:	return _("deadline passed");
    case GF_ERR_STATE:		return _("not allowed in the current state");
    case GF_ERR_CLOSED:		return _("connection closed");
    case GF_ERR_AUTH:		return _("authentication failed");
    case GF_ERR_AGAIN:		return _("try again after the next event");
    case GF_ERR_PASSPHRASE:	return _("wrong passphrase");
    default:			return _("unknown status");
    }
}

void
gfi_i18n_init (void)
{
#ifdef ENABLE_NLS
  static int done;

  if (!done)
    {
      bindtextdomain (GF_TEXTDOMAIN, LOCALEDIR);
      bind_textdomain_codeset (GF_TEXTDOMAIN, "UTF-8");
      done = 1;
    }
#endif
}
