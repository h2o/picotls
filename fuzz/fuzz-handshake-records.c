/*
 * fuzz-handshake-records.c - stateful TLS 1.3 session fuzzer for picotls.
 *
 * Threat model: a TLS endpoint receives attacker-controlled bytes on the wire:
 * post-handshake records (arbitrary ciphertext), PSK identities offered on
 * resumption, and application data. The existing hello fuzzers feed attacker
 * bytes into a handshake whose ephemeral key exchange is mutation-hostile, so
 * they abort before the traffic key schedule exists and the record
 * encryption/decryption machinery, ticket handling and post-handshake message
 * processing stay dark (production report 2026-11-17: lib/picotls.c 2440 dark
 * lines, lib/openssl.c 1033 dark).
 *
 * This harness removes that gate legitimately: it completes a genuine TLS 1.3
 * handshake between an in-process client and server and only then hands
 * attacker-controlled bytes to the boundaries an attacker really has:
 *   - ptls_receive() on both endpoints: record framing, AEAD decryption,
 *     alert emission, NewSessionTicket/KeyUpdate processing;
 *   - the resumption ticket identity: pass-through ticket callbacks let a
 *     corrupted stored ticket reach the server ticket parser before binder
 *     verification aborts;
 *   - ptls_send(): payloads encrypted with the live traffic keys and delivered.
 *
 * Backend: picotls-minicrypto (in-tree, no OpenSSL) with the upstream test
 * SECP256R1 certificate and key (t/test.h), so the real record AEAD, key
 * schedule and certificate handling all run without any external dependency.
 * Compiled WITHOUT -DPTLS_FUZZ_HANDSHAKE so the real AEAD paths run.
 *
 * Input framing (stateful sequence, flags in byte 0):
 *   bit0: offer the stored ticket on resumption (genuine PSK resumption)
 *   bit1: replace the stored ticket with attacker bytes (up to 128)
 *   bit2: inject attacker records into the resuming client
 *   bit3: inject attacker records into the resuming server
 *   bit4: ptls_send() attacker appdata from client, deliver to server
 * bytes 1..: [attacker ticket identity (first <=128 bytes when bit1)] [rest:
 * attacker records / appdata payload]
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "picotls.h"
#include "picotls/minicrypto.h"
#include "test.h"

#define MAX_TICKET 512
#define MAX_DRAIN_ROUNDS 16

static ptls_context_t ctx_client, ctx_server;

struct st_fuzz_ticket_store {
    ptls_save_ticket_t super;
    uint8_t buf[MAX_TICKET];
    size_t len;
};

static struct st_fuzz_ticket_store ticket_store;

static void deterministic_random_bytes(void *buf, size_t len)
{
    /* deterministic but non-degenerate: an all-zero "random" stream would
     * produce invalid EC private keys, so use a stable byte pattern instead */
    for (size_t i = 0; i < len; ++i)
        ((uint8_t *)buf)[i] = (uint8_t)(0x41 + (i % 26));
}

static int encrypt_ticket_cb(ptls_encrypt_ticket_t *_self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
    /* pass-through: the server decrypts exactly what the client offered, so a
     * genuine ticket resumes, while attacker-supplied identities reach the
     * ticket parser verbatim before binder verification aborts */
    static const char identity[] = "picotls-fuzz-resumption-identity-01";
    int ret;

    (void)tls;
    if (is_encrypt) {
        if ((ret = ptls_buffer_reserve(dst, sizeof(identity) - 1)) != 0)
            return ret;
        memcpy(dst->base + dst->off, identity, sizeof(identity) - 1);
        dst->off += sizeof(identity) - 1;
    } else {
        if ((ret = ptls_buffer_reserve(dst, src.len)) != 0)
            return ret;
        memcpy(dst->base + dst->off, src.base, src.len);
        dst->off += src.len;
    }
    return 0;
}

static int save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src, const ptls_save_ticket_properties_t *properties)
{
    struct st_fuzz_ticket_store *store = (struct st_fuzz_ticket_store *)_self;

    (void)tls;
    (void)properties;
    store->len = src.len < sizeof(store->buf) ? src.len : sizeof(store->buf);
    memcpy(store->buf, src.base, store->len);
    return 0;
}

static int init_contexts_once(void)
{
    static int initialized;
    static ptls_minicrypto_secp256r1sha256_sign_certificate_t sign_certificate;
    static ptls_iovec_t cert_list[1];
    static ptls_encrypt_ticket_t et = {.cb = encrypt_ticket_cb};

    if (initialized)
        return 1;

    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, sizeof(SECP256R1_PRIVATE_KEY) - 1));
    cert_list[0] = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);

    memset(&ctx_client, 0, sizeof(ctx_client));
    ctx_client.random_bytes = deterministic_random_bytes;
    ctx_client.get_time = &ptls_get_time;
    ctx_client.key_exchanges = ptls_minicrypto_key_exchanges;
    ctx_client.cipher_suites = ptls_minicrypto_cipher_suites_all;
    ctx_client.certificates.list = cert_list;
    ctx_client.certificates.count = 1;
    ctx_client.sign_certificate = &sign_certificate.super;
    ticket_store.super.cb = save_ticket_cb;
    ctx_client.save_ticket = &ticket_store.super;

    memset(&ctx_server, 0, sizeof(ctx_server));
    ctx_server.random_bytes = deterministic_random_bytes;
    ctx_server.get_time = &ptls_get_time;
    ctx_server.key_exchanges = ptls_minicrypto_key_exchanges;
    ctx_server.cipher_suites = ptls_minicrypto_cipher_suites_all;
    ctx_server.certificates.list = cert_list;
    ctx_server.certificates.count = 1;
    ctx_server.sign_certificate = &sign_certificate.super;
    ctx_server.encrypt_ticket = &et;
    ctx_server.ticket_lifetime = 86400;

    initialized = 1;
    return 1;
}

/* feed a byte stream to an endpoint one record per call, as an attacker or a
 * peer would; processes post-handshake records such as tickets or alerts */
static void drain(ptls_t *tls, const uint8_t *in, size_t inlen)
{
    ptls_buffer_t plain;
    size_t off = 0;

    ptls_buffer_init(&plain, "", 0);
    for (int i = 0; i < MAX_DRAIN_ROUNDS && off < inlen; ++i) {
        size_t consumed = inlen - off;
        if (ptls_receive(tls, &plain, in + off, &consumed) != 0)
            break;
        off += consumed;
    }
    ptls_buffer_dispose(&plain);
}

/* drive a handshake between the two endpoints, routing each flight to the
 * side that can still consume it; leftovers (e.g. NewSessionTicket after the
 * Finished) are drained through the post-handshake path */
static void pump_handshake(ptls_t *client, ptls_t *server, ptls_handshake_properties_t *client_props)
{
    ptls_buffer_t cbuf, sbuf;

    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(&sbuf, "", 0);

    ptls_handshake(client, &cbuf, NULL, NULL, client_props);

    for (int round = 0; round < 8; ++round) {
        int progress = 0;

        if (cbuf.off != 0) {
            if (!ptls_handshake_is_complete(server)) {
                size_t consumed = cbuf.off;
                ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
            } else {
                drain(server, cbuf.base, cbuf.off);
            }
            cbuf.off = 0;
            progress = 1;
        }
        if (sbuf.off != 0) {
            if (!ptls_handshake_is_complete(client)) {
                size_t consumed = sbuf.off;
                ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
                if (consumed < sbuf.off) {
                    memmove(sbuf.base, sbuf.base + consumed, sbuf.off - consumed);
                    sbuf.off -= consumed;
                } else {
                    sbuf.off = 0;
                }
            } else {
                drain(client, sbuf.base, sbuf.off);
                sbuf.off = 0;
            }
            progress = 1;
        }

        if (!progress || (ptls_handshake_is_complete(client) && ptls_handshake_is_complete(server)))
            break;
    }

    if (sbuf.off != 0)
        drain(client, sbuf.base, sbuf.off);

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ptls_t *client, *server;
    const uint8_t *ident, *records, *payload;
    size_t ident_len = 0, records_len, payload_len;
    uint8_t flags;

    if (!init_contexts_once())
        return 0;
    if (size == 0)
        return 0;

    flags = data[0];
    payload = data + 1;
    payload_len = size - 1;

    if ((flags & 2) != 0 && payload_len != 0)
        ident_len = payload_len < 128 ? payload_len : 128;
    ident = payload;
    records = payload + ident_len;
    records_len = payload_len - ident_len;

    ticket_store.len = 0;

    /* handshake #1: genuine full handshake; the server mints a ticket */
    client = ptls_new(&ctx_client, 0);
    server = ptls_new(&ctx_server, 1);
    if (client != NULL && server != NULL)
        pump_handshake(client, server, NULL);
    if (client != NULL)
        ptls_free(client);
    if (server != NULL)
        ptls_free(server);
    if (ticket_store.len == 0)
        return 0;

    /* the attacker may corrupt the stored ticket before resumption */
    if ((flags & 2) != 0 && ident_len != 0) {
        size_t n = ident_len < sizeof(ticket_store.buf) ? ident_len : sizeof(ticket_store.buf);
        memcpy(ticket_store.buf, ident, n);
        ticket_store.len = n;
    }

    /* handshake #2: resumption (genuine or attacker identity), then attacker
     * records and application data over the live traffic keys */
    client = ptls_new(&ctx_client, 0);
    server = ptls_new(&ctx_server, 1);
    if (client != NULL && server != NULL) {
        ptls_handshake_properties_t props;

        memset(&props, 0, sizeof(props));
        if ((flags & 3) != 0)
            props.client.session_ticket = ptls_iovec_init(ticket_store.buf, ticket_store.len);
        pump_handshake(client, server, &props);

        if ((flags & 8) != 0)
            drain(server, records, records_len);
        if ((flags & 4) != 0)
            drain(client, records, records_len);
        if ((flags & 16) != 0 && records_len != 0) {
            ptls_buffer_t out;
            ptls_buffer_init(&out, "", 0);
            if (ptls_send(client, &out, records, records_len) == 0)
                drain(server, out.base, out.off);
            ptls_buffer_dispose(&out);
        }
    }
    if (client != NULL)
        ptls_free(client);
    if (server != NULL)
        ptls_free(server);

    return 0;
}
