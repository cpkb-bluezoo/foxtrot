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

/* A key revocation list, whole.  Loaded after a good list, it can only add
   to what that revokes, and loading it twice changes no answer.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <foxtrot/status.h>
#include <foxtrot/crypto.h>
#include <foxtrot/policy.h>
#include <foxtrot/key.h>
#include <foxtrot/krl.h>

#include "fuzz-common.h"
#include "vectors-krl.h"

#define NQ (sizeof vec_krl_queries / sizeof vec_krl_queries[0])

static gf_key *keys[NQ];
static int base[NQ];
static gf_krl *good;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  static uint8_t b[8192];
  size_t i, n;

  (void) argc;
  (void) argv;
  gf_crypto_init ();
  if (gf_krl_new (&good) != GF_OK)
    abort ();
  n = fuzz_unhex (vec_krl_main, b, sizeof b);
  if (gf_krl_load (good, b, n) != GF_OK)
    abort ();
  for (i = 0; i < NQ; i++)
    {
      static uint8_t kb[4096];

      n = fuzz_unhex (vec_krl_queries[i].blob, kb, sizeof kb);
      if (gf_key_from_blob (&keys[i], kb, n) != GF_OK)
        abort ();
      base[i] = gf_krl_check (good, keys[i]);
    }
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  gf_krl *k = NULL, *two = NULL;
  size_t i, before;
  int rc;

  if (gf_krl_new (&k) != GF_OK)
    return 0;
  rc = gf_krl_load (k, data, size);
  if (rc != GF_OK && gf_krl_count (k) != 0)
    {
      fprintf (stderr, "a refused list left %zu entries\n", gf_krl_count (k));
      abort ();
    }
  if (rc == GF_OK)
    {
      int ans[NQ];

      for (i = 0; i < NQ; i++)
        ans[i] = gf_krl_check (k, keys[i]);
      before = gf_krl_count (k);
      /* Twice is once.  */
      if (gf_krl_load (k, data, size) != GF_OK || gf_krl_count (k) != 2 * before)
        {
          fprintf (stderr, "a list loaded once and not twice\n");
          abort ();
        }
      for (i = 0; i < NQ; i++)
        if (gf_krl_check (k, keys[i]) != ans[i])
          {
            fprintf (stderr, "%s: twice is not once\n", vec_krl_queries[i].name);
            abort ();
          }
      /* After a good list: nothing is un-revoked.  */
      if (gf_krl_new (&two) == GF_OK)
        {
          static uint8_t b[8192];
          size_t n = fuzz_unhex (vec_krl_main, b, sizeof b);

          if (gf_krl_load (two, b, n) != GF_OK || gf_krl_load (two, data, size) != GF_OK)
            abort ();
          for (i = 0; i < NQ; i++)
            if (base[i] == 1 && gf_krl_check (two, keys[i]) != 1)
              {
                fprintf (stderr, "%s: revoked, then not\n", vec_krl_queries[i].name);
                abort ();
              }
        }
    }
  gf_krl_free (k);
  gf_krl_free (two);
  return 0;
}
