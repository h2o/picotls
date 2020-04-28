#ifndef picotcpls_h
#define picotcpls_h

#include "picotypes.h"
#include <netinet/in.h>
#define NBR_SUPPORTED_TCPLS_OPTIONS 5
#define VARSIZE_OPTION_MAX_CHUNK_SIZE 4*16384 /* should be able to hold 4 record before needing to be extended */


#define TCPLS_SIGNAL_SIZE 12

/** TCP options we would support in the TLS context */
typedef enum tcpls_enum_t {
  USER_TIMEOUT,
  FAILOVER_ADDR4,
  FAILOVER_ADDR6,
  FAILOVER_SIGNAL,
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

  /** socket of the primary address - must be update at each primary change*/
  int *socket_ptr;
};

struct st_ptls_record_t;

/*=====================================API====================================*/

/** API exposed to the application */

void *tcpls_new();

int tcpls_connect(void *tls_info);

int tcpls_add_v4(void *tls_info, struct sockaddr_in *addr, int is_primary);

int tcpls_add_v6(void *tls_info, struct sockaddr_in6 *addr, int is_primary);

ssize_t tcpls_send(void *tls_info, const void *input, size_t nbytes);

ssize_t tcpls_receive(void *tls_info, const void *input, size_t nbytes);

int ptls_set_user_timeout(ptls_t *ctx, uint16_t value, uint16_t sec_or_min,
    uint8_t setlocal, uint8_t settopeer);

int ptls_set_failover(ptls_t *ptls, char *address);

int ptls_set_bpf_scheduler(ptls_t *ptls, const uint8_t *bpf_prog_bytecode,
    size_t bytecodelen, int setlocal, int settopeer);

int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, tcpls_enum_t type);

/*============================================================================*/
/** Internal to picotls */
int handle_tcpls_extension_option(ptls_t *ctx, tcpls_enum_t type,
    const uint8_t *input, size_t len);

int handle_tcpls_record(ptls_t *tls, struct st_ptls_record_t *rec);

int tcpls_failover_signal(tcpls_t *tcpls, ptls_buffer_t *sendbuf);

void ptls_tcpls_options_free(ptls_t *ptls);

#endif
