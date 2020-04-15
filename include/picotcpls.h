#ifndef picotcpls_h
#define picotcpls_h

#include "picotypes.h"

#define NBR_SUPPORTED_TCPLS_OPTIONS 5
#define VARSIZE_OPTION_MAX_CHUNK_SIZE 4*16384 /* should be able to hold 4 record before needing to be extended */



/** TCP options we would support in the TLS context */
typedef enum ptls_tcpls_options_t {
  USER_TIMEOUT,
  FAILOVER,
  BPF_CC,
} ptls_tcpls_options_t;

struct st_tcpls_t {
  ptls_tcpls_options_t type;
  unsigned setlocal : 1; /** Whether or not we also apply the option locally */
  unsigned settopeer : 1; /** Whether or not this option might be sent to the peer */
  unsigned is_varlen : 1; /** Tell whether this option is of variable length */
  ptls_iovec_t *data;
};

struct st_ptls_record_t;

/*=====================================API====================================*/

/** API exposed to the application */
int ptls_set_user_timeout(ptls_t *ctx, uint16_t value, uint16_t sec_or_min,
    uint8_t setlocal, uint8_t settopeer);

int ptls_set_failover(ptls_t *ptls, char *address);

int ptls_set_bpf_scheduler(ptls_t *ptls, const uint8_t *bpf_prog_bytecode,
    size_t bytecodelen, int setlocal, int settopeer);

int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_tcpls_options_t type);

/*============================================================================*/
/** Internal to picotls */
int handle_tcpls_extension_option(ptls_t *ctx, ptls_tcpls_options_t type,
    const uint8_t *input, size_t len);

int handle_tcpls_record(ptls_t *tls, struct st_ptls_record_t *rec);

void ptls_tcpls_options_free(ptls_t *ptls);

#endif
