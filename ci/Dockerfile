# syntax=docker/dockerfile:1
#
# The build the CI workflow (.github/workflows/ci.yml) runs: foxtrot built
# with gcc, warnings as errors, and its unit tests.  Build from the
# repository root, so that the sources are in the context:
#
#   docker build --target check -f ci/Dockerfile .

# ---- Build: foxtrot, with gcc ----------------------------------------------
FROM ubuntu:24.04 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         autoconf autopoint automake build-essential ca-certificates curl \
         bzip2 gettext libgnutls28-dev libtool pkg-config texinfo \
    && rm -rf /var/lib/apt/lists/*

# foxtrot needs libgcrypt 1.12 or newer (the final ML-KEM), and that needs a
# newer libgpg-error than Ubuntu 24.04 has: both are built here.  The
# versions and checksums are quickstep's.
ARG GPGERROR_VERSION=1.61
ARG GPGERROR_SHA256=7a85413f2bc354f4f8aa832b718af122e48965e9e0eb9012ee659c13c6385c93
ARG LIBGCRYPT_VERSION=1.12.4
ARG LIBGCRYPT_SHA256=d77f68f48879510e79a2f65977ccc68981781ea0923e5bdffac2a193ea3d660e
RUN curl -fsSL -o gpgrt.tar.bz2 \
         https://gnupg.org/ftp/gcrypt/gpgrt/libgpg-error-${GPGERROR_VERSION}.tar.bz2 \
    && echo "${GPGERROR_SHA256}  gpgrt.tar.bz2" | sha256sum -c - \
    && tar xjf gpgrt.tar.bz2 \
    && cd libgpg-error-${GPGERROR_VERSION} \
    && ./configure --prefix=/usr/local --disable-static --disable-doc \
         --disable-tests \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf gpgrt.tar.bz2 libgpg-error-${GPGERROR_VERSION} \
    && ldconfig
# The linker must find these, not an older libgpg-error that Ubuntu's own
# packages pull in.
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN curl -fsSL -o libgcrypt.tar.bz2 \
         https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${LIBGCRYPT_VERSION}.tar.bz2 \
    && echo "${LIBGCRYPT_SHA256}  libgcrypt.tar.bz2" | sha256sum -c - \
    && tar xjf libgcrypt.tar.bz2 \
    && cd libgcrypt-${LIBGCRYPT_VERSION} \
    && ./configure --prefix=/usr/local --disable-static --disable-doc \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf libgcrypt.tar.bz2 libgcrypt-${LIBGCRYPT_VERSION} \
    && ldconfig

WORKDIR /src
COPY . .

# Warnings are errors: the tree is expected to build cleanly with gcc.
ENV CC=gcc PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
RUN ./autogen.sh \
    && ./configure --without-gnutls \
    && make -j"$(nproc)" CFLAGS="-g -O2 -Werror"

# ---- Check: the unit tests --------------------------------------------------
# "docker build --target check" runs them; a failing test fails the build.
FROM build AS check
RUN make check -j"$(nproc)" CFLAGS="-g -O2 -Werror" \
    || (cat tests/test-suite.log; exit 1)

# ---- Sanitize: the unit tests and the fuzz corpora, with ASan and UBSan -----
# Also runs each fuzz target with mutation for a short time.  The build is
# separate from the one above because the sanitizers need their own flags.
FROM build AS sanitize
ENV SAN="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
ENV ASAN_OPTIONS=abort_on_error=1 LSAN_OPTIONS=suppressions=/src/fuzz/lsan.supp:print_suppressions=0
RUN make distclean >/dev/null 2>&1; \
    ./configure --without-gnutls CFLAGS="$SAN" LDFLAGS="-fsanitize=address,undefined" \
    && make -j"$(nproc)" check CFLAGS="$SAN" \
       || (cat tests/test-suite.log fuzz/test-suite.log; exit 1)
# Coverage (for the mutation below) is for the library and the fuzz targets
# only: a library built with it needs the callback that fuzz/driver.c
# defines, which the unit tests do not link.
RUN make -C src clean \
    && make -j"$(nproc)" -C src CFLAGS="$SAN -fsanitize-coverage=trace-pc" \
    && make -C fuzz clean \
    && make -j"$(nproc)" -C fuzz check TESTS= CFLAGS="$SAN -fsanitize-coverage=trace-pc"
RUN cd fuzz && for t in $(ls corpus); do \
      ./fuzz-$t -runs=100000000 -max_total_time=30 -seed=1 -save=/tmp/crash-$t.bin \
        corpus/$t || exit 1; \
    done
