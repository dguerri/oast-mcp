FROM alpine:3.21 AS builder

ARG MBEDTLS_VERSION=2.28.8

RUN apk add --no-cache gcc musl-dev cmake make wget upx

# Build mbedTLS from source (static libs only, minimal config)
COPY loader.c mbedtls_config.h /

RUN wget -q "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v${MBEDTLS_VERSION}.tar.gz" \
        -O /tmp/mbedtls.tgz && \
    tar xf /tmp/mbedtls.tgz -C /tmp && \
    rm /tmp/mbedtls.tgz && \
    cp /mbedtls_config.h /tmp/mbedtls-${MBEDTLS_VERSION}/include/mbedtls/config.h && \
    cmake -S /tmp/mbedtls-${MBEDTLS_VERSION} -B /tmp/mbedtls-build \
          -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
          -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
          -DENABLE_PROGRAMS=OFF \
          -DENABLE_TESTING=OFF \
          -DCMAKE_BUILD_TYPE=MinSizeRel \
          -DCMAKE_C_FLAGS="-Os -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables" \
          > /dev/null && \
    cmake --build /tmp/mbedtls-build --parallel $(nproc) > /dev/null

RUN gcc -Os -static -s \
        -ffunction-sections -fdata-sections \
        -fno-asynchronous-unwind-tables -fno-stack-protector \
        -o /loader /loader.c \
        -I /tmp/mbedtls-${MBEDTLS_VERSION}/include \
        /tmp/mbedtls-build/library/libmbedtls.a \
        /tmp/mbedtls-build/library/libmbedx509.a \
        /tmp/mbedtls-build/library/libmbedcrypto.a \
        -Wl,--gc-sections,--build-id=none && \
    upx --best --lzma /loader > /dev/null 2>&1

FROM scratch
COPY --from=builder /loader /loader
