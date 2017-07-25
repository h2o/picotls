/* picotlsvs: test program for the TLS 1.3 library. */
#include <stdio.h>
#include <openssl/pem.h>
#include "../picotls/wincompat.h"
#include "../../include/picotls.h"
#include "../../include/picotls/openssl.h"
#include "../../include/picotls/minicrypto.h"

int ptls_export_secret(ptls_t *tls, void *output, size_t outlen, const char *label, ptls_iovec_t context_value);

/*
 * Testing the Base64 and ASN1 verifiers
 */
int openPemTest(char const * filename)
{
	ptls_iovec_t buf = { 0 };
	ptls_iovec_t * list = &buf;
	size_t count = 1;
#if 1
	int ret = ptls_pem_get_private_key(filename, &buf, stderr);
#else
	int ret = ptls_pem_get_objects(filename, "PRIVATE KEY",
		&list, 1, &count, stderr);
#endif
	if (buf.base != NULL)
	{
		free(buf.base);
	}

	return ret;
}

/*
 * Using the open ssl library to load the test certificate
 */

X509* openPemFile(char* filename)
{

    X509* cert = X509_new();
    BIO* bio_cert = BIO_new_file(filename, "rb");
    PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
    return cert;
}

int get_certificates(char * pem_fname, ptls_iovec_t ** list, int * nb_certs)
{
    int ret = 0;
    size_t count = 0;
    X509 *cert;
    static ptls_iovec_t certs[16];

    *nb_certs = 0;
    *list = NULL;

    cert = openPemFile(pem_fname);

    if (cert == NULL)
    {
        fprintf(stderr, "Could not read cert in %s\n", pem_fname);
        ret = -1;
    }
    else
    {
        ptls_iovec_t *dst = certs + count++;
        dst->len = i2d_X509(cert, &dst->base);
    }
    
    *nb_certs = count;
    *list = certs;

    return ret;
}

void SetSignCertificate(char * keypem, ptls_context_t * ctx)
{
    static ptls_openssl_sign_certificate_t signer;

    EVP_PKEY *pkey = EVP_PKEY_new();
    BIO* bio_key = BIO_new_file(keypem, "rb");
    PEM_read_bio_PrivateKey(bio_key, &pkey, NULL, NULL);
    ptls_openssl_init_sign_certificate(&signer, pkey);
    EVP_PKEY_free(pkey);
    ctx->sign_certificate = &signer.super;
}


int handshake_init(ptls_t * tls, ptls_buffer_t * sendbuf)
{
    size_t inlen = 0, roff = 0;

    ptls_buffer_init(sendbuf, "", 0);
    int ret = ptls_handshake(tls, sendbuf, NULL, NULL, NULL);

    return ret;
}


int handshake_progress(ptls_t * tls, ptls_buffer_t * sendbuf, ptls_buffer_t * recvbuf)
{
    size_t inlen = 0, roff = 0;
    int ret = 0;

    ptls_buffer_init(sendbuf, "", 0);

    /* Provide the data */
    while (roff < recvbuf->off && (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
    {
        inlen = recvbuf->off - roff;
        ret = ptls_handshake(tls, sendbuf, recvbuf->base + roff, &inlen, NULL);
        roff += inlen;
    }

    if (roff < recvbuf->off)
    {
        // Could not consume all the data. This is bad.
        fprintf(stderr, "Could only process %d bytes out of %d\n", roff, recvbuf->off);
    }
    ptls_buffer_dispose(recvbuf);

    return ret;
}

/*
 Verify the secret extraction functionality
 at the end of the handshake.
 */

int extract_1rtt_secret( 
    ptls_t *tls, const char *label, 
    ptls_cipher_suite_t ** cipher,
    uint8_t * secret, size_t secret_max)
{
    int ret = 0;
    *cipher = ptls_get_cipher(tls);

    if (*cipher == NULL)
    {
        ret = -1;
    }
    else if ((*cipher)->hash->digest_size > secret_max)
    {
        ret = -1;
    }
    else
    {
        ret = ptls_export_secret(tls, secret, (*cipher)->hash->digest_size,
            label, ptls_iovec_init(NULL, 0));
    }

    return 0;
}

int verify_1rtt_secret_extraction(ptls_t *tls_client, ptls_t *tls_server)
{
    int ret = 0;
    ptls_cipher_suite_t * cipher_client;
    ptls_cipher_suite_t * cipher_server;
    uint8_t secret_client[64];
    uint8_t secret_server[64];
    char const * label = "This is just a test";

    ret = extract_1rtt_secret(tls_client, label, &cipher_client, 
        secret_client, sizeof(secret_client));

    if (ret != 0)
    {
        fprintf(stderr, "Cannot extract client 1RTT secret, ret=%d\n", ret);
    }
    else
    {
        ret = extract_1rtt_secret(tls_server, label, &cipher_server,
            secret_server, sizeof(secret_server));
        if (ret != 0)
        {
            fprintf(stderr, "Cannot extract client 1RTT secret, ret=%d\n", ret);
        }
    }

    if (ret == 0)
    {
        if (strcmp(cipher_client->aead->name, cipher_server->aead->name) != 0)
        {
            fprintf(stderr, "AEAD differ, client:%s, server:%s\n",
                cipher_client->aead->name, cipher_server->aead->name);
            ret = -1;
        }
        else if (cipher_client->hash->digest_size != cipher_server->hash->digest_size)
        {
            fprintf(stderr, "Key length differ, client:%d, server:%d\n",
                cipher_client->hash->digest_size, cipher_server->hash->digest_size);
            ret = -1;
        }
        else if (memcmp(secret_client, secret_server, cipher_client->hash->digest_size) != 0)
        {
            fprintf(stderr, "Key of client and server differ!\n");
            ret = -1;
        }
    }

    return ret;
}

int openssl_init_test_client(ptls_context_t *ctx_client)
{
	int ret = 0;
	static ptls_openssl_verify_certificate_t verifier;

	/* Initialize the client context */
	memset(ctx_client, 0, sizeof(ptls_context_t));
	ctx_client->random_bytes = ptls_openssl_random_bytes;
	ctx_client->key_exchanges = ptls_openssl_key_exchanges;
	ctx_client->cipher_suites = ptls_openssl_cipher_suites;
	ptls_openssl_init_verify_certificate(&verifier, NULL);
	ctx_client->verify_certificate = &verifier.super;

	return ret;
}

int openssl_init_test_server(ptls_context_t *ctx_server, char * key_file, char * cert_file)
{
	int ret = 0;
	/* Initialize the server context */
	memset(ctx_server, 0, sizeof(ptls_context_t));
	ctx_server->random_bytes = ptls_openssl_random_bytes;
	ctx_server->key_exchanges = ptls_openssl_key_exchanges;
	ctx_server->cipher_suites = ptls_openssl_cipher_suites;

	ret = ptls_set_context_certificates(ctx_server, cert_file, stdout);
	if (ret != 0)
	{
		fprintf(stderr, "Could not read the server certificates\n");
	}
	else
	{
		SetSignCertificate(key_file, ctx_server);
	}

	return ret;
}

int minicrypto_init_test_client(ptls_context_t *ctx_client)
{
	int ret = 0;
	// static ptls_openssl_verify_certificate_t verifier;

	/* Initialize the client context */
	memset(ctx_client, 0, sizeof(ptls_context_t));
	ctx_client->random_bytes = ptls_minicrypto_random_bytes; 
	ctx_client->key_exchanges = ptls_minicrypto_key_exchanges;
	ctx_client->cipher_suites = ptls_minicrypto_cipher_suites;
	// ptls_openssl_init_verify_certificate(&verifier, NULL);
	ctx_client->verify_certificate = NULL; // &verifier.super;

	return ret;
}

int minicrypto_init_test_server(ptls_context_t *ctx_server, char * key_file, char * cert_file)
{
	int ret = 0;

	/* Initialize the server context */
	memset(ctx_server, 0, sizeof(ptls_context_t));
	ctx_server->random_bytes = ptls_minicrypto_random_bytes;
	ctx_server->key_exchanges = ptls_minicrypto_key_exchanges;
	ctx_server->cipher_suites = ptls_minicrypto_cipher_suites;

	ret = ptls_set_context_certificates(ctx_server, cert_file, stdout);
	if (ret != 0)
	{
		fprintf(stderr, "Could not read the server certificates\n");
	}
	else
	{
		SetSignCertificate(key_file, ctx_server);
	}

	return ret;
}

int ptls_memory_loopback_test(int openssl_client, int openssl_server, char * key_file, char * cert_file)
{
	ptls_context_t ctx_client, ctx_server;
	ptls_t *tls_client = NULL, *tls_server = NULL;
	int ret = 0;
	ptls_buffer_t client_buf, server_buf;

	/* init the contexts */
	if (ret == 0 && openssl_client)
	{
		ret = openssl_init_test_client(&ctx_client);
	}
	else
	{
		ret = minicrypto_init_test_client(&ctx_client);
	}

	if (ret == 0 && openssl_server)
	{
		ret = openssl_init_test_server(&ctx_server, key_file, cert_file);
	}
	else
	{
		ret = minicrypto_init_test_server(&ctx_server, key_file, cert_file);
	}

	/* Create the connections */
	if (ret == 0)
	{
		tls_client = ptls_new(&ctx_client, 0);
		tls_server = ptls_new(&ctx_server, 1);

		if (tls_server == NULL || tls_client == NULL)
		{
			fprintf(stderr, "Could not create the TLS connection objects\n");
			ret = -1;
		}
	}

	/* Perform the handshake */
	if (ret == 0)
	{
		int nb_rounds = 0;
		ret = handshake_init(tls_client, &client_buf);
		printf("First message from client, ret = %d, %d bytes.\n", ret, client_buf.off);

		while ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && client_buf.off > 0 && nb_rounds < 12)
		{
			nb_rounds++;

			ret = handshake_progress(tls_server, &server_buf, &client_buf);
			printf("Message from server, ret = %d, %d bytes.\n", ret, server_buf.off);

			if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && server_buf.off > 0)
			{
				ret = handshake_progress(tls_client, &client_buf, &server_buf);
				printf("Message from client, ret = %d, %d bytes.\n", ret, client_buf.off);
			}
		}

		printf("Exit handshake after %d rounds, ret = %d.\n", nb_rounds, ret);

		if (ret == 0)
		{
			ret = verify_1rtt_secret_extraction(tls_client, tls_server);

			if (ret == 0)
			{
				printf("Key extracted and matches!\n");
			}
		}
	}

	return ret;
}

static char const * test_keys[] = {
	"key.pem",
	"key-test-1.pem",
	"key-test-2.pem",
	"key-test-4.pem"
};

static const size_t nb_test_keys = sizeof(test_keys) / sizeof(char const *);

int main()
{
	int ret = 0;

#if 1
	/* TODO: move to ASN.1 unit test*/

	for (size_t i = 0; ret == 0 && i < nb_test_keys; i++)
	{
		ret = openPemTest(test_keys[i]);
	}
#endif

	if (ret == 0)
	{
		ret = ptls_memory_loopback_test(1, 1, "key.pem", "cert.pem");
	}

	if (ret == 0)
	{
		ret = ptls_memory_loopback_test(1, 1, "ec_key.pem", "ec_cert.pem");
	}


    return ret;
}

