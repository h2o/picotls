#ifndef picotcpls_h
#define picotcpls_h

#include "picotypes.h"
#include "picotls.h"
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
#define STREAM_SENDER_NEW_STREAM_SIZE 4
#define STREAM_CLOSE_SIZE 4

/** TCP options we would support in the TLS context */
typedef enum tcpls_enum_t {
  USER_TIMEOUT,
  MULTIHOMING_v4,
  MULTIHOMING_v6,
  FAILOVER,
  BPF_CC,
  STREAM_ATTACH,
  STREAM_CLOSE
} tcpls_enum_t;

typedef enum tcpls_tcp_state_t {
  CONNECTING,
  CONNECTED,
  CLOSED
} tcpls_tcp_state_t;

struct st_tcpls_options_t {
  tcpls_enum_t type;
  uint8_t setlocal; /** Whether or not we also apply the option locally */
  uint8_t settopeer; /** Whether or not this option might be sent to the peer */
  uint8_t is_varlen; /** Tell whether this option is of variable length */
  ptls_iovec_t *data;
};

typedef struct st_tcpls_v4_addr_t {
  struct sockaddr_in addr;
  unsigned is_primary : 1; /* whether this is our primary address */
  unsigned is_ours : 1;  /* is this our address? */
  struct st_tcpls_v4_addr_t *next;
} tcpls_v4_addr_t;

typedef struct st_tcpls_v6_addr_t {
  struct sockaddr_in6 addr;
  unsigned is_primary : 1;
  unsigned is_ours : 1;
  struct st_tcpls_v6_addr_t *next;
} tcpls_v6_addr_t;

typedef struct st_connect_info_t {
  tcpls_tcp_state_t state; /* Connection state */
  int socket;
  unsigned is_primary : 1;
  struct timeval connect_time;
  /** Only one is used */
  tcpls_v4_addr_t *src;
  tcpls_v6_addr_t *src6;
  /** only one is used */
  tcpls_v4_addr_t *dest;
  tcpls_v6_addr_t *dest6;

} connect_info_t;

typedef struct st_tcpls_stream {
  /** Buffer for potentially lost records in case of failover, loss of
   * connection. Also potentially used for fair usage of the link w.r.t multiple
   * streams
   **/
  tcpls_record_fifo_t *send_queue;
  streamid_t streamid;
  /** when this stream should first send an attach event before
   * sending any packet */
  unsigned need_sending_attach_event  : 1;
  
  /**
   * As soon as we have sent a stream attach event to the other peer, this
   * stream is usable
   */
  unsigned stream_usable : 1;
  
  /** end positio of the stream control event message in the current sending
   * buffer*/
  int send_stream_attach_in_sendbuf_pos;

  /**
   * Whether we still have to initialize the aead context for this stream.
   * That may happen if this stream is created before the handshake took place.
   */
  unsigned aead_initialized : 1;
  /** Note: The following contexts use the same key; but a different counter and
   * IV
   */
  /* Context for encryption */
  ptls_aead_context_t *aead_enc;
  /* Context for decryption */
  ptls_aead_context_t *aead_dec;
  /** Attached connection */
  connect_info_t *con;
} tcpls_stream_t;


struct st_tcpls_t {
  ptls_t *tls;
  /* Sending buffer */
  ptls_buffer_t *sendbuf;
  
  /** If we did not manage to empty sendbuf in one send call */
  int send_start;

  /* Receiving buffer */
  ptls_buffer_t *recvbuf;
  /** Linked List of address to be used for happy eyeball
   * and for failover 
   */
  /** Destination addresses */
  tcpls_v4_addr_t *v4_addr_llist;
  tcpls_v6_addr_t *v6_addr_llist;
  /** Our addresses */
  tcpls_v4_addr_t *ours_v4_addr_llist;
  tcpls_v6_addr_t *ours_v6_addr_llist;

  /** carry a list of tcpls_option_t */
  list_t *tcpls_options;
  /** Should contain all streams */
  list_t *streams;
  /** We have stream control event to check */
  unsigned check_stream_attach_sent : 1;
  /** Contains the state of connected src and dest addresses */
  list_t *connect_infos;
 
  /** value of the next stream id :) */
  uint32_t next_stream_id;
  /** count the number of times we attached a stream from the peer*/
  uint32_t nbr_of_peer_streams_attached;
  
  /** nbr of tcp connection */
  uint32_t nbr_tcp_streams;

  /** socket of the primary address - must be update at each primary change*/
  int socket_primary;
  /** remember on which socket we pulled out bytes */
  int socket_rcv;
};

struct st_ptls_record_t;

/*=====================================API====================================*/

/** API exposed to the application */

void *tcpls_new();

int tcpls_connect(ptls_t *tls, struct sockaddr *src, struct sockaddr *dest,
    struct timeval *timeout);

int tcpls_add_v4(ptls_t *tls, struct sockaddr_in *addr, int is_primary, int
    settopeer, int is_ours);

int tcpls_add_v6(ptls_t *tls, struct sockaddr_in6 *addr, int is_primary, int
    settopeer, int is_ours);

uint32_t tcpls_stream_new(ptls_t *tls, struct sockaddr *src, struct sockaddr *addr);

int tcpls_streams_attach(ptls_t *tls, int sendnow);

int tcpls_stream_close(ptls_t *tls, streamid_t streamid);

/**
 * tcpls_send can be called whether or not tcpls_stream_new has been called before
 * by the application; but it must send a stream_attach record first to attach a
 * stream.
 */

ssize_t tcpls_send(ptls_t *tls, streamid_t streamid, const void *input, size_t nbytes);

ssize_t tcpls_receive(ptls_t *tls, void *input, size_t nbytes, struct timeval *tv);

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

void ptls_tcpls_options_free(tcpls_t *tcpls);

#endif
