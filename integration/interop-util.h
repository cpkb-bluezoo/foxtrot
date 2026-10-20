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

#include <foxtrot/conn.h>
#include <foxtrot/status.h>

static uint64_t
now_us (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
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

/* Run CONN over FD until it closes or DONE (called after each wakeup)
   returns nonzero.  Returns 0 if the connection ended cleanly, else a
   negative status or -1 for a socket error.  */
static int
drive (gf_conn *c, int fd, int (*done) (void *), void *user, int timeout_ms)
{
  uint64_t deadline = now_us () + (uint64_t) timeout_ms * 1000;

  for (;;)
    {
      struct pollfd pfd = { fd, POLLIN, 0 };
      uint64_t t = gf_conn_timeout (c), n = now_us ();
      int wait, r;
      uint8_t buf[16384];
      ssize_t got;

      if (gf_conn_is_closed (c) || (done && done (user)))
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
            return gf_conn_is_closed (c) ? 0 : -1;
          r = gf_conn_receive (c, now_us (), buf, (size_t) got);
          if (r < 0 && !gf_conn_is_closed (c))
            return r;
        }
      else
        {
          r = gf_conn_on_timeout (c, now_us ());
          if (r < 0 && !gf_conn_is_closed (c))
            return r;
        }
    }
}

#endif /* GF_INTEROP_UTIL_H */
