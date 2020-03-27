#ifndef picotcpls_h
#define picotcpls_h

#include "picotypes.h"

#define NBR_SUPPORTED_TCPLS_OPTIONS 5

/** TCP options we would support in the TLS context */
typedef enum ptls_tcpls_options_t {
  USER_TIMEOUT,
  FAILOVER,
} ptls_tcpls_options_t;

struct st_tcpls_t {
  ptls_tcpls_options_t type;
  ptls_iovec_t *data;
};

struct st_ptls_record_t;

/** API exposed to the application */
int ptls_set_user_timeout(ptls_t *ctx, uint16_t value, uint16_t sec_or_min);


/** Internal to picotls */
int handle_tcpls_extension_option(ptls_t *ctx, ptls_tcpls_options_t type,
    const uint8_t *input, size_t len);

int handle_tcpls_record(ptls_t *tls, struct st_ptls_record_t *rec);

void ptls_tcpls_options_free(ptls_t *ptls);

#endif
