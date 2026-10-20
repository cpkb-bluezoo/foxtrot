#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/wire.h>

#include "fuzz-common.h"

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  return 0;
}

/* The first byte of each step says what to read next.  What is read is
   written again and read back, and has to be the same.  */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  gf_reader r;
  uint8_t out[8192], ops[256];
  size_t nops, i;

  if (size < 1)
    return 0;
  nops = data[0] < size - 1 ? data[0] : size - 1;
  memcpy (ops, data + 1, nops);
  gf_reader_init (&r, data + 1 + nops, size - 1 - nops);
  for (i = 0; i < nops; i++)
    {
      gf_slice s;
      uint8_t u8;
      uint32_t u32;
      uint64_t u64;
      int b;
      gf_writer w;
      gf_reader again;

      switch (ops[i] % 11)
        {
        case 0:
          (void) gf_rd_u8 (&r, &u8);
          break;
        case 1:
          (void) gf_rd_u32 (&r, &u32);
          break;
        case 2:
          (void) gf_rd_u64 (&r, &u64);
          break;
        case 3:
          (void) gf_rd_bool (&r, &b);
          break;
        case 4:
          (void) gf_rd_bytes (&r, ops[i], &s);
          break;
        case 5:
          if (gf_rd_string (&r, &s) == GF_OK && s.len < sizeof out - 8)
            {
              gf_slice t;

              gf_writer_init (&w, out, sizeof out);
              gf_wr_string (&w, s.data, s.len);
              gf_reader_init (&again, out, w.len);
              if (gf_wr_status (&w) != GF_OK || gf_rd_string (&again, &t) != GF_OK
                  || t.len != s.len || (s.len && memcmp (t.data, s.data, s.len)))
                abort ();
            }
          break;
        case 6:
          (void) gf_rd_text (&r, &s);
          break;
        case 7:
          (void) gf_rd_utf8 (&r, &s);
          break;
        case 8:
          if (gf_rd_mpint (&r, &s) == GF_OK && s.len < sizeof out - 8)
            {
              gf_slice t;

              gf_writer_init (&w, out, sizeof out);
              gf_wr_mpint (&w, s.data, s.len);
              gf_reader_init (&again, out, w.len);
              if (gf_wr_status (&w) != GF_OK || gf_rd_mpint (&again, &t) != GF_OK
                  || t.len != s.len || (s.len && memcmp (t.data, s.data, s.len)))
                abort ();
            }
          break;
        case 9:
          if (gf_rd_namelist (&r, &s) == GF_OK)
            {
              gf_slice rest = s, name;
              size_t count = 0;

              while (gf_namelist_next (&rest, &name))
                {
                  if (!gf_namelist_has (s, name))
                    abort ();
                  if (++count > s.len + 1)
                    abort ();
                }
              (void) gf_namelist_contains (s, "ssh-ed25519");
            }
          break;
        default:
          (void) gf_rd_remaining (&r);
          (void) gf_rd_finish (&r);
          break;
        }
    }
  return 0;
}
