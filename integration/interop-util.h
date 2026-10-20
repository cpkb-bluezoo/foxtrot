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

/* Helpers shared by the interoperability programs: a socket driver for a
   gf_conn, which is the part of a real application the library leaves
   out.  */

#ifndef GF_INTEROP_UTIL_H
#define GF_INTEROP_UTIL_H

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <foxtrot/session.h>
#include <foxtrot/status.h>

static uint64_t
now_us (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

/* The test pattern for bulk transfers: byte I of the stream.  */
static uint8_t
pattern_at (uint64_t i)
{
  return (uint8_t) (i * 7 + i / 251);
}

static int
sock_write (int fd, const uint8_t *data, size_t len)
{
  while (len > 0)
    {
      ssize_t n = write (fd, data, len);

      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      data += n;
      len -= (size_t) n;
    }
  return 0;
}

/* Run S over FD until it closes or DONE (called after each wakeup)
   returns nonzero.  Returns 0 if the session ended cleanly, else a negative
   status or -1 for a socket error, -2 for the overall timeout.  This is the
   part of a real application the library leaves out.  */
static int
drive (gf_session *s, int fd, int (*done) (void *), void *user, int timeout_ms)
{
  uint64_t deadline = now_us () + (uint64_t) timeout_ms * 1000;

  for (;;)
    {
      struct pollfd pfd = { fd, POLLIN, 0 };
      uint64_t t = gf_session_timeout (s), n = now_us ();
      int wait, r;
      uint8_t buf[16384];
      ssize_t got;

      if (gf_session_phase (s) == GF_PHASE_CLOSED || (done && done (user)))
        return 0;
      if (n >= deadline)
        return -2;
      wait = (int) ((deadline - n) / 1000) + 1;
      if (t != UINT64_MAX)
        {
          int tw = t > n ? (int) ((t - n) / 1000) + 1 : 0;

          if (tw < wait)
            wait = tw;
        }
      r = poll (&pfd, 1, wait);
      if (r < 0 && errno != EINTR)
        return -1;
      if (r > 0)
        {
          got = read (fd, buf, sizeof buf);
          if (got <= 0)
            return gf_session_phase (s) == GF_PHASE_CLOSED ? 0 : -1;
          r = gf_session_receive (s, now_us (), buf, (size_t) got);
          if (r < 0 && gf_session_phase (s) != GF_PHASE_CLOSED)
            return r;
        }
      else
        {
          r = gf_session_on_timeout (s, now_us ());
          if (r < 0 && gf_session_phase (s) != GF_PHASE_CLOSED)
            return r;
        }
    }
}

/* A public key (or certificate) from a file in the text form of ssh-keygen's
   .pub files.  */
static gf_key *
read_pub (const char *file)
{
  char text[16384];
  FILE *f = fopen (file, "r");
  size_t n;
  gf_key *key = NULL;

  if (f == NULL)
    return NULL;
  n = fread (text, 1, sizeof text, f);
  fclose (f);
  if (gf_key_from_text (&key, text, n, NULL) != GF_OK)
    return NULL;
  return key;
}

#endif /* GF_INTEROP_UTIL_H */
