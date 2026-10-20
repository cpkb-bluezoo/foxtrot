#!/bin/sh
# Run a fuzz target over its corpus once: run-corpus.sh ./fuzz-NAME
# (corpus/NAME).  Used by "make check".
name=$(basename "$1" | sed 's/^fuzz-//')
exec "$@" "${srcdir:-.}/corpus/$name"
