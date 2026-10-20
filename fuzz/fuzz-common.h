/* Helpers shared by the fuzz targets (see driver.c).  */

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* The libFuzzer entry points of a target.  */
int LLVMFuzzerInitialize (int *argc, char ***argv);
int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

/* A fuzz input of several messages is a series of frames: a 16-bit
   big-endian length, then that many bytes.  Returns 1 and the frame (a
   short last frame is cut off at the end of the input), or 0 when nothing is
   left.  */
static inline int
fuzz_frame (const uint8_t **p, size_t *n, const uint8_t **frame, size_t *flen)
{
  size_t l;

  if (*n < 2)
    return 0;
  l = (size_t) (*p)[0] << 8 | (*p)[1];
  *p += 2;
  *n -= 2;
  if (l > *n)
    l = *n;
  *frame = *p;
  *flen = l;
  *p += l;
  *n -= l;
  return 1;
}

/* Hex text to bytes (for the constants of the test vectors); returns the
   length.  */
static inline size_t
fuzz_unhex (const char *hex, uint8_t *out, size_t cap)
{
  size_t n = 0;

  while (hex[0] && hex[1] && n < cap)
    {
      unsigned v;
      char t[3] = { hex[0], hex[1], 0 };

      v = (unsigned) strtoul (t, NULL, 16);
      out[n++] = (uint8_t) v;
      hex += 2;
    }
  return n;
}

#endif
