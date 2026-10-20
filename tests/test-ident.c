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
#include <foxtrot/ident.h>

#include "tst-util.h"

/* Feed S (LEN bytes) in chunks of CHUNK; return the final status and the
   number of bytes left over after the line.  */
static int
run (int prefix, const char *s, size_t len, size_t chunk, gf_ident *id,
     size_t *left)
{
  const uint8_t *p = (const uint8_t *) s;
  size_t n = len, off = 0;
  int rc = GF_NEED_MORE;

  gf_ident_init (id, prefix);
  while (off < len)
    {
      size_t take = len - off < chunk ? len - off : chunk;

      p = (const uint8_t *) s + off;
      n = take;
      rc = gf_ident_parse (id, &p, &n);
      off += take - n;
      if (rc != GF_NEED_MORE)
        {
          /* The rest of this chunk is the next layer's.  */
          *left = n + (len - (off + n));
          return rc;
        }
      off += n;
    }
  *left = 0;
  return rc;
}

static void
good (int prefix, const char *s, size_t slen, const char *line,
      const char *software, size_t trailing)
{
  size_t chunk;

  for (chunk = 1; chunk <= slen; chunk++)
    {
      gf_ident id;
      size_t left;
      gf_slice l, sw;

      CHECK_EQ (run (prefix, s, slen, chunk, &id, &left), GF_OK);
      CHECK_EQ (left, trailing);
      l = gf_ident_string (&id);
      sw = gf_ident_software (&id);
      CHECK (gf_slice_equals (l, line));
      CHECK (gf_slice_equals (sw, software));
    }
}

static void
bad (int prefix, const char *s, size_t slen, int rc)
{
  size_t chunk;

  for (chunk = 1; chunk <= slen && chunk <= 40; chunk++)
    {
      gf_ident id;
      size_t left;

      CHECK_EQ (run (prefix, s, slen, chunk, &id, &left), rc);
      /* An error is permanent.  */
      {
        const uint8_t *p = (const uint8_t *) "SSH-2.0-x\r\n";
        size_t n = 11;

        CHECK (gf_ident_parse (&id, &p, &n) != GF_OK);
      }
    }
}

#define GOOD(prefix, s, line, sw, trailing) \
  good (prefix, s, sizeof s - 1, line, sw, trailing)
#define BAD(prefix, s, rc) bad (prefix, s, sizeof s - 1, rc)

static void
test_parse (void)
{
  GOOD (0, "SSH-2.0-foxtrot_0.0.1\r\n", "SSH-2.0-foxtrot_0.0.1",
        "foxtrot_0.0.1", 0);
  GOOD (0, "SSH-2.0-OpenSSH_9.6 Ubuntu-3\r\n", "SSH-2.0-OpenSSH_9.6 Ubuntu-3",
        "OpenSSH_9.6 Ubuntu-3", 0);
  /* Bytes after the line belong to the next layer.  */
  GOOD (0, "SSH-2.0-x\r\n\0\0\0\x14", "SSH-2.0-x", "x", 4);

  /* A client skips text before the server's line.  */
  GOOD (1, "Welcome to the machine\r\nSSH-2.0-srv\r\n", "SSH-2.0-srv",
        "srv", 0);
  GOOD (1, "\r\nbare lf\nab\nSSH-2.0-srv\r\nrest", "SSH-2.0-srv", "srv", 4);
  GOOD (1, "SSH-2.0-srv\r\n", "SSH-2.0-srv", "srv", 0);
  GOOD (1, "SSHx text\r\nSSH-2.0-srv\r\n", "SSH-2.0-srv", "srv", 0);
  /* A server does not.  */
  BAD (0, "hello\r\nSSH-2.0-cli\r\n", GF_ERR_ENCODING);
  BAD (0, "\r\nSSH-2.0-cli\r\n", GF_ERR_ENCODING);
}

static void
test_refusals (void)
{
  /* SSH-1 and its compatibility versions.  */
  BAD (0, "SSH-1.99-old\r\n", GF_ERR_UNSUPPORTED);
  BAD (0, "SSH-1.5-old\r\n", GF_ERR_UNSUPPORTED);
  BAD (0, "SSH-2.1-future\r\n", GF_ERR_UNSUPPORTED);
  BAD (0, "SSH-3.0-future\r\n", GF_ERR_UNSUPPORTED);
  BAD (0, "SSH-2.00-x\r\n", GF_ERR_UNSUPPORTED);
  /* Malformed.  */
  BAD (0, "SSH-2.0\r\n", GF_ERR_ENCODING);
  BAD (0, "SSH-2.0-\r\n", GF_ERR_ENCODING);
  BAD (0, "SSH-2.0- x\r\n", GF_ERR_ENCODING);
  BAD (0, "SSH--x\r\n", GF_ERR_ENCODING);
  BAD (0, "SSH-2.0-x\n", GF_ERR_ENCODING);	/* Bare LF.  */
  BAD (0, "SSH-2.0-x\r\r\n", GF_ERR_ENCODING);
  BAD (0, "SSH-2.0-a\0b\r\n", GF_ERR_ENCODING);
  BAD (0, "SSH-2.0-caf\xc3\xa9\r\n", GF_ERR_ENCODING);
  BAD (1, "SSH-2.0-x\n", GF_ERR_ENCODING);

  /* Too long: 255 including CR LF is the most.  */
  {
    char s[400];
    gf_ident id;
    size_t left;
    int n;

    memset (s, 'a', sizeof s);
    memcpy (s, "SSH-2.0-", 8);
    s[253] = '\r';
    s[254] = '\n';
    CHECK_EQ (run (0, s, 255, 255, &id, &left), GF_OK);
    CHECK_EQ (gf_ident_string (&id).len, 253);
    s[254] = 'a';
    s[255] = '\r';
    s[256] = '\n';
    CHECK_EQ (run (0, s, 257, 257, &id, &left), GF_ERR_ENCODING);
    /* Nor may a line never end.  */
    for (n = 0; n < 2; n++)
      CHECK_EQ (run (n, s, 300, 7, &id, &left), GF_ERR_ENCODING);
  }

  /* Text before the line is limited too.  */
  {
    static char big[GF_IDENT_MAX_PREFIX + 200];
    gf_ident id;
    size_t left, i;

    for (i = 0; i < sizeof big; i += 2)
      {
        big[i] = 'x';
        big[i + 1] = '\n';
      }
    CHECK_EQ (run (1, big, sizeof big, 1000, &id, &left), GF_ERR_ENCODING);
  }
}

static void
test_format (void)
{
  uint8_t out[300];
  size_t n;

  CHECK_EQ (gf_ident_format ("foxtrot_0.0.1", NULL, out, sizeof out, &n),
            GF_OK);
  CHECK (n == 23 && memcmp (out, "SSH-2.0-foxtrot_0.0.1\r\n", 23) == 0);
  CHECK_EQ (gf_ident_format ("foxtrot_0.0.1", "a comment", out, sizeof out,
                             &n), GF_OK);
  CHECK (n == 33 && memcmp (out, "SSH-2.0-foxtrot_0.0.1 a comment\r\n", 33) == 0);
  CHECK_EQ (gf_ident_format ("fox-trot", NULL, out, sizeof out, &n),
            GF_ERR_INVAL);
  CHECK_EQ (gf_ident_format ("fox trot", NULL, out, sizeof out, &n),
            GF_ERR_INVAL);
  CHECK_EQ (gf_ident_format ("", NULL, out, sizeof out, &n), GF_ERR_INVAL);
  CHECK_EQ (gf_ident_format ("x", "bad\ncomment", out, sizeof out, &n),
            GF_ERR_INVAL);
  CHECK_EQ (gf_ident_format ("foxtrot", NULL, out, 10, &n), GF_ERR_BUFSIZE);
  {
    char big[300];

    memset (big, 'a', sizeof big);
    big[250] = 0;
    CHECK_EQ (gf_ident_format (big, NULL, out, sizeof out, &n), GF_ERR_RANGE);
  }
}

int
main (void)
{
  test_parse ();
  test_refusals ();
  test_format ();
  TST_DONE ();
}
