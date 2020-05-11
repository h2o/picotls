#ifndef picotcpls_h
#define picotcpls_h

#include "picotypes.h"
#include "containers.h"
#include <netinet/in.h>
#define NBR_SUPPORTED_TCPLS_OPTIONS 5
#define VARSIZE_OPTION_MAX_CHUNK_SIZE 4*16384 /* should be able to hold 4 records before needing to be extended */

/*
 * When adding a new stream, we increase the low IV part by 4096 to avoid any
 * chance of collision. Note, when deriving server_write_iv and client_write_iv; we also
 * require to check whether the distance between them is at least
 * 4096*nbr_max_streams
 */
#define MIN_LOWIV_STREAM_INCREASE 4096

#define TCPLS_SIGNAL_SIZE 12

/** TCP options we would support in the TLS context */
typedef enum tcpls_enum_t {
  USER_TIMEOUT,
  MULTIHOMING_v4,
  MULTIHOMING_v6,
  FAILOVER,
  BPF_CC,
} tcpls_enum_t;

typedef enum tcpls_tcp_state_t {
  CONNECTING,
  CONNECTED,
  CLOSED
} tcpls_tcp_state_t;

struct st_tcpls_options_t {
  tcpls_enum_t type;
  unsigned setlocal : 1; /** Whether or not we also apply the option locally */
  unsigned settopeer : 1; /** Whether or not this option might be sent to the peer */
  unsigned is_varlen : 1; /** Tell whether this option is of variable length */
  ptls_iovec_t *data;
};

typedef struct st_tcpls_v4_addr_t {
  struct sockaddr_in addr;
  unsigned is_primary : 1;
  tcpls_tcp_state_t state;
  struct timeval connect_time;
  int socket;
  struct st_tcpls_v4_addr_t *next;
} tcpls_v4_addr_t;

typedef struct st_tcpls_v6_addr_t {
  struct sockaddr_in6 addr;
  unsigned is_primary : 1;
  tcpls_tcp_state_t state;
  struct timeval connect_time;
  int socket;
  struct st_tcpls_v6_addr_t *next;
} tcpls_v6_addr_t;

typedef struct st_tcpls_stream {
  /** Buffer for potentially lost records in case of failover, loss of
   * connection. Also potentially used for fair usage of the link w.r.t multiple
   * streams  
   **/
  tcpls_record_fifo_t *send_queue;
  streamid_t streamid;
  /** Note: The following contexts use the same key; but a different counter and
   * IV
   */
  /* Context for encryption */
  ptls_aead_context_t *aead_enc;
  /* Context for decryption */
  ptls_aead_context_t *aead_dec;
  /** Attached to v4_addr or a v6_addr; */
  tcpls_v4_addr_t *v4_addr;
  tcpls_v6_addr_t *v6_addr;
} tcpls_stream_t;


struct st_tcpls_t {
  ptls_t *tls;
  /* Sending buffer */
  ptls_buffer_t *sendbuf;
  /* Receiving buffer */
  ptls_buffer_t *recvbuf;
  /** Linked List of address to be used for happy eyeball 
   * and for failover 
   */

  tcpls_v4_addr_t *v4_addr_llist;
  tcpls_v6_addr_t *v6_addr_llist;
  
  /** Should contain all streams */
  list_t *streams;

  /** socket of the primary address - must be update at each primary change*/
  int *socket_ptr;
};

struct st_ptls_record_t;

/*=====================================API====================================*/

/** API exposed to the application */

void *tcpls_new();

int tcpls_connect(ptls_t *tls);

int tcpls_add_v4(ptls_t *tls, struct sockaddr_in *addr, int is_primary, int settopeer);

int tcpls_add_v6(ptls_t *tls, struct sockaddr_in6 *addr, int is_primary, int settopeer);

uint32_t tcpls_stream_new(ptls_t *tls, struct sockaddr *addr);

ssize_t tcpls_send(ptls_t *tls, streamid_t streamid, const void *input, size_t nbytes);

ssize_t tcpls_receive(ptls_t *tls, const void *input, size_t nbytes);

int ptls_set_user_timeout(ptls_t *ctx, uint16_t value, uint16_t sec_or_min,
    uint8_t setlocal, uint8_t settopeer);

int ptls_set_failover(ptls_t *ptls, char *address);

int ptls_set_bpf_scheduler(ptls_t *ptls, const uint8_t *bpf_prog_bytecode,
    size_t bytecodelen, int setlocal, int settopeer);

int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, tcpls_enum_t type);

void tcpls_free(tcpls_t *tcpls);

/*============================================================================*/
/** Internal to picotls */
int handle_tcpls_extension_option(ptls_t *ctx, tcpls_enum_t type,
    const uint8_t *input, size_t len);

int handle_tcpls_record(ptls_t *tls, struct st_ptls_record_t *rec);

int tcpls_failover_signal(tcpls_t *tcpls, ptls_buffer_t *sendbuf);

void ptls_tcpls_options_free(ptls_t *ptls);

#endif
