#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/ident.h>

#include "fuzz-common.h"

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  return 0;
}

/* The identification line, in pieces of any size.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  gf_ident id;
  size_t chunk, pos = 0;
  int rc = GF_NEED_MORE;

  if (size < 2)
    return 0;
  gf_ident_init (&id, data[0] & 1);
  chunk = 1 + (data[1] % 64);
  data += 2;
  size -= 2;
  while (pos < size && rc == GF_NEED_MORE)
    {
      const uint8_t *p = data + pos;
      size_t n = size - pos < chunk ? size - pos : chunk;

      rc = gf_ident_parse (&id, &p, &n);
      pos = (size_t) (p - data);
      if (rc == GF_NEED_MORE && n != 0)
        abort ();		/* It takes everything it is given.  */
    }
  if (rc == GF_OK)
    {
      gf_slice line = gf_ident_string (&id), sw = gf_ident_software (&id);

      if (line.len > GF_IDENT_MAX || sw.len > line.len)
        abort ();
      if (line.len < 8 || memcmp (line.data, "SSH-2.0-", 8) != 0)
        abort ();
    }
  return 0;
}
