#ifndef picotcpls_h
#define picotcpls_h

#include "picotypes.h"

#define NBR_SUPPORTED_TCPLS_OPTIONS 3

/** TCP options we would support in the TLS context */
typedef enum ptls_tcpls_options_t {
  USER_TIMEOUT,
  FAILOVER,
} ptls_tcpls_options_t;

struct st_tcpls_t {
  ptls_tcpls_options_t type;
  size_t len;
  uint8_t *data;
};


/** API exposed to the application */
int ptls_set_user_timeout(ptls_context_t *ctx, uint16_t value, uint16_t sec_or_min);


/** Internal to picotls */
int handle_tcpls_extension_option(ptls_context_t *ctx, ptls_tcpls_options_t type, uint16_t val);

int handle_tcpls_record(void);

#endif
