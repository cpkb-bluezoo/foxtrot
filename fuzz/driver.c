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

/* A driver for the fuzz targets, for when libFuzzer is not at hand.

     driver [-runs=N] [-seed=N] [-max_len=N] [-max_total_time=S]
            [-out=DIR] [-save=FILE] FILE-OR-DIRECTORY...

   Each target is a libFuzzer one (LLVMFuzzerTestOneInput), so with clang
   it can be linked with -fsanitize=fuzzer instead of this file.  Here, each
   file named, and each file directly inside a directory named, is run once:
   that is what "make check" does with the corpus, so that what fuzzing once
   found stays fixed.  With -runs, the inputs are then mutated (bit flips,
   byte changes, insertions, deletions, repetitions, boundary values,
   splices between inputs) from a fixed seed, so a run can be repeated, and
   run too; a sanitizer, or an abort, reports a failure.

   If the target and the library were compiled with
   -fsanitize-coverage=trace-pc (gcc and clang have it), the driver sees
   which code each input reaches and keeps the ones that reach new code
   (-out=DIR also writes those to files), so that mutation builds on what has
   got somewhere; without it the mutation is blind.  When the run is
   killed by an abort, a fault or an illegal instruction (run the sanitizers
   with abort_on_error=1) the input that did it is written to the file
   named by -save (default fuzz-crash.bin).  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fuzz-common.h"

struct input
{
  uint8_t *data;
  size_t len;
};

static struct input *corpus;
static size_t ncorpus, capcorpus;
static const char *save_path = "fuzz-crash.bin";
static const char *out_dir;
static const uint8_t *current;
static size_t current_len;

/* ---- coverage ---- */

#define MAP_SIZE 65536
static uint8_t cov_map[MAP_SIZE], cov_virgin[MAP_SIZE];
static uintptr_t cov_prev;

void __sanitizer_cov_trace_pc (void);

/* Called by instrumented code on entering each basic block.  Not itself
   instrumented.  The edge from the previous block to this one is hashed
   into the map.  */
__attribute__ ((no_sanitize_coverage)) void
__sanitizer_cov_trace_pc (void)
{
  uintptr_t pc = (uintptr_t) __builtin_return_address (0) >> 1;

  cov_map[(pc ^ (cov_prev * 0x9e3779b1u)) & (MAP_SIZE - 1)] = 1;
  cov_prev = pc;
}

/* Does the last run's map have an edge no earlier run had?  */
static int
cov_new (void)
{
  size_t i;
  int fresh = 0;

  for (i = 0; i < MAP_SIZE; i++)
    if (cov_map[i] && !cov_virgin[i])
      {
        cov_virgin[i] = 1;
        fresh = 1;
      }
  return fresh;
}

static void
crash (int sig)
{
  int fd = open (save_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

  if (fd >= 0)
    {
      if (current_len)
        (void) !write (fd, current, current_len);
      close (fd);
    }
  signal (sig, SIG_DFL);
  raise (sig);
}

static void
install_handlers (void)
{
  static const int sigs[] = { SIGABRT, SIGILL, SIGFPE, SIGSEGV, SIGBUS };
  size_t i;

  for (i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
    {
      struct sigaction old;

      /* A sanitizer's own handler for a fault reports it, and then aborts:
         leave it.  */
      if (sigaction (sigs[i], NULL, &old) == 0 && old.sa_handler == SIG_DFL)
        signal (sigs[i], crash);
    }
}

static uint64_t rng = 0x9e3779b97f4a7c15ull;

static uint32_t
rnd (void)
{
  rng ^= rng >> 12;
  rng ^= rng << 25;
  rng ^= rng >> 27;
  return (uint32_t) ((rng * 0x2545f4914f6cdd1dull) >> 32);
}

static void
add (const uint8_t *data, size_t len)
{
  if (ncorpus == capcorpus)
    {
      capcorpus = capcorpus ? capcorpus * 2 : 64;
      corpus = realloc (corpus, capcorpus * sizeof *corpus);
      if (corpus == NULL)
        exit (2);
    }
  corpus[ncorpus].data = malloc (len ? len : 1);
  if (corpus[ncorpus].data == NULL)
    exit (2);
  memcpy (corpus[ncorpus].data, data, len);
  corpus[ncorpus].len = len;
  ncorpus++;
}

static void
load_file (const char *path)
{
  FILE *f = fopen (path, "rb");
  uint8_t *buf;
  size_t n, cap = 1 << 16;

  if (f == NULL)
    return;
  buf = malloc (cap);
  if (buf == NULL)
    exit (2);
  n = fread (buf, 1, cap, f);
  fclose (f);
  add (buf, n);
  free (buf);
}

static void
load (const char *path)
{
  DIR *d = opendir (path);

  if (d == NULL)
    {
      load_file (path);
      return;
    }
  for (;;)
    {
      struct dirent *e = readdir (d);
      char full[4096];

      if (e == NULL)
        break;
      if (e->d_name[0] == '.')
        continue;
      snprintf (full, sizeof full, "%s/%s", path, e->d_name);
      load_file (full);
    }
  closedir (d);
}

/* Run one input; returns 1 if it reached code no input has.  */
static int
run (const uint8_t *data, size_t len)
{
  current = data;
  current_len = len;
  memset (cov_map, 0, sizeof cov_map);
  cov_prev = 0;
  LLVMFuzzerTestOneInput (data, len);
  return cov_new ();
}

/* Remember an input that found new code, and write it if asked.  */
static void
keep (const uint8_t *data, size_t len)
{
  add (data, len);
  if (out_dir)
    {
      char path[4096];
      uint64_t h = 1469598103934665603ull;
      size_t i;
      FILE *f;

      for (i = 0; i < len; i++)
        h = (h ^ data[i]) * 1099511628211ull;
      snprintf (path, sizeof path, "%s/%016llx", out_dir, (unsigned long long) h);
      f = fopen (path, "wb");
      if (f)
        {
          fwrite (data, 1, len, f);
          fclose (f);
        }
    }
}

static const uint32_t interesting[] = {
  0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255,
  256, 257, 511, 512, 1023, 1024, 4096, 32767, 32768, 32769, 65535, 65536,
  0x7fffffffu, 0x80000000u, 0x80000001u, 0xfffffffeu, 0xffffffffu
};

static size_t
mutate (uint8_t *buf, size_t len, size_t cap)
{
  unsigned rounds = 1 + rnd () % 4;

  while (rounds--)
    switch (rnd () % 11)
      {
      case 0:			/* Flip a bit.  */
        if (len)
          buf[rnd () % len] ^= (uint8_t) (1u << (rnd () % 8));
        break;
      case 1:			/* A new byte.  */
        if (len)
          buf[rnd () % len] = (uint8_t) rnd ();
        break;
      case 2:			/* A small change.  */
        if (len)
          buf[rnd () % len] += (uint8_t) ((int) (rnd () % 9) - 4);
        break;
      case 3:			/* Insert bytes.  */
        {
          size_t n = 1 + rnd () % 8, at = len ? rnd () % (len + 1) : 0, i;

          if (len + n <= cap)
            {
              memmove (buf + at + n, buf + at, len - at);
              for (i = 0; i < n; i++)
                buf[at + i] = (uint8_t) rnd ();
              len += n;
            }
          break;
        }
      case 4:			/* Delete a range.  */
        if (len > 1)
          {
            size_t n = 1 + rnd () % (len < 16 ? len : 16), at = rnd () % (len - n + 1);

            memmove (buf + at, buf + at + n, len - at - n);
            len -= n;
          }
        break;
      case 5:			/* Repeat a range.  */
        if (len > 1)
          {
            size_t n = 1 + rnd () % (len < 32 ? len : 32), at = rnd () % (len - n + 1);

            if (len + n <= cap)
              {
                memmove (buf + at + n, buf + at, len - at);
                memcpy (buf + at + n, buf + at, n);
                len += n;
              }
          }
        break;
      case 6:			/* A boundary value, big-endian.  */
        if (len >= 4)
          {
            uint32_t v = interesting[rnd () % (sizeof interesting / sizeof interesting[0])];
            size_t at = rnd () % (len - 3);

            buf[at] = (uint8_t) (v >> 24);
            buf[at + 1] = (uint8_t) (v >> 16);
            buf[at + 2] = (uint8_t) (v >> 8);
            buf[at + 3] = (uint8_t) v;
          }
        break;
      case 7:			/* A piece of another input.  */
        if (ncorpus > 1)
          {
            const struct input *o = &corpus[rnd () % ncorpus];

            if (o->len)
              {
                size_t n = 1 + rnd () % (o->len < 64 ? o->len : 64);
                size_t from = rnd () % (o->len - n + 1), at = len ? rnd () % len : 0;

                if (at + n <= cap)
                  {
                    memcpy (buf + at, o->data + from, n);
                    if (at + n > len)
                      len = at + n;
                  }
              }
          }
        break;
      case 8:			/* Swap two bytes.  */
        if (len > 1)
          {
            size_t a = rnd () % len, b = rnd () % len;
            uint8_t t = buf[a];

            buf[a] = buf[b];
            buf[b] = t;
          }
        break;
      case 9:			/* Cut it short.  */
        if (len > 1)
          len = 1 + rnd () % len;
        break;
      default:			/* A length field for a string: keep it near
				   what is there.  */
        if (len >= 4)
          {
            size_t at = rnd () % (len - 3);
            uint32_t v = (uint32_t) (len - at - 4 + (rnd () % 3) - 1);

            buf[at] = (uint8_t) (v >> 24);
            buf[at + 1] = (uint8_t) (v >> 16);
            buf[at + 2] = (uint8_t) (v >> 8);
            buf[at + 3] = (uint8_t) v;
          }
        break;
      }
  return len;
}

int
main (int argc, char **argv)
{
  unsigned long long runs = 0, total = 0, ncorpus0;
  size_t max_len = 16384, i;
  long max_time = 0;
  time_t start = time (NULL);
  uint8_t *buf;

  for (i = 1; i < (size_t) argc; i++)
    {
      if (strncmp (argv[i], "-runs=", 6) == 0)
        runs = strtoull (argv[i] + 6, NULL, 10);
      else if (strncmp (argv[i], "-seed=", 6) == 0)
        rng ^= strtoull (argv[i] + 6, NULL, 10) * 0x9e3779b97f4a7c15ull;
      else if (strncmp (argv[i], "-max_len=", 9) == 0)
        max_len = (size_t) strtoull (argv[i] + 9, NULL, 10);
      else if (strncmp (argv[i], "-max_total_time=", 16) == 0)
        max_time = atol (argv[i] + 16);
      else if (strncmp (argv[i], "-save=", 6) == 0)
        save_path = argv[i] + 6;
      else if (strncmp (argv[i], "-out=", 5) == 0)
        out_dir = argv[i] + 5;
      else if (argv[i][0] == '-')
        {
          fprintf (stderr, "unknown option %s\n", argv[i]);
          return 2;
        }
      else
        load (argv[i]);
    }
  install_handlers ();
  LLVMFuzzerInitialize (&argc, &argv);
  for (i = 0; i < ncorpus; i++)
    run (corpus[i].data, corpus[i].len);
  total = ncorpus;
  ncorpus0 = ncorpus;
  {
    size_t edges = 0;

    for (i = 0; i < MAP_SIZE; i++)
      edges += cov_virgin[i];
    if (runs)
      fprintf (stderr, "%zu inputs, %zu edges\n", ncorpus, edges);
  }
  buf = malloc (max_len + 64);
  if (buf == NULL)
    return 2;
  if (ncorpus == 0)
    {
      uint8_t zero = 0;

      add (&zero, 1);
    }
  for (; total < runs + ncorpus0; total++)
    {
      /* Half the time start from one of the most recent finds.  */
      size_t pick = (rnd () & 1) && ncorpus > 8 ? ncorpus - 1 - rnd () % 8
                                                 : rnd () % ncorpus;
      const struct input *base = &corpus[pick];
      size_t len = base->len > max_len ? max_len : base->len;

      memcpy (buf, base->data, len);
      len = mutate (buf, len, max_len);
      if (run (buf, len))
        keep (buf, len);
      if (max_time && (total & 255) == 0 && time (NULL) - start >= max_time)
        break;
    }
  fprintf (stderr, "%llu runs, %zu inputs\n", total, ncorpus);
  free (buf);
  return 0;
}
