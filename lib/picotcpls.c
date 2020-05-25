/**
 * \file picotcpls.c
 *
 * \brief Implement logic for setting, sending, receiving and processing TCP
 * options through the TLS layer, as well as offering a wrapper for the
 * transport protocol and expose only one interface to the application layer
 *
 * This file defines an API exposed to the application
 * <ul>
 *   <li> tcpls_new </li>
 *   <li> tcpls_add_v4 </li>
 *   <li> tcpls_add_v6 </li>
 *   <li> tcpls_connect </li>
 *   <li> tcpls_send </li>
 *   <li> tcpls_receive </li>
 *   <li> tcpls_stream_new </li>
 *   <li> tcpls_stream_close </li>
 *   <li> tcpls_free </li>
 * </ul>
 *
 * We also offer an API to set localy and/or to the
 * peer some TCP options. We currently support the following options:
 *
 * <ul>
 *    <li> User Timeout RFC5482 </li>
 *    <li> Failover </li>
 *    <li> BPF injection of a Congestion Control scheme (kernel >= 5.6)  </li>
 * </ul>
 * 
 * To set up a TCP option, the application layer should first turns on 
 * ctx->support_tcpls_options = 1; which will advertise to the peer the
 * capability of handling TCPLS. Then, we may set locally or remotly TCP options
 * by doing: 
 *
 * ptls_set_[OPTION]
 * and then
 *
 * ptls_send_tcpotion(...)
 *
 */

#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include "picotypes.h"
#include "containers.h"
#include "picotls.h"
#include "picotcpls.h"

/** Forward declarations */
static int tcpls_init_context(ptls_t *ptls, const void *data, size_t datalen,
    tcpls_enum_t type, uint8_t setlocal, uint8_t settopeer);
static int is_varlen(tcpls_enum_t type);
static int setlocal_usertimeout(ptls_t *ptls, int val);
static int setlocal_bpf_cc(ptls_t *ptls, const uint8_t *bpf_prog, size_t proglen);
static void _set_primary(tcpls_t *tcpls);
static tcpls_stream_t *stream_new(ptls_t *tcpls, streamid_t streamid, tcpls_v4_addr_t *addr,
    tcpls_v6_addr_t *addr6, int is_ours);
static void stream_free(tcpls_stream_t *stream);
static int stream_send_control_message(tcpls_t *tcpls, tcpls_stream_t *stream,
    const void *inputinfo, tcpls_enum_t message, uint32_t message_len);
static tcpls_v4_addr_t *get_v4_primary_addr(tcpls_t *tcpls);
static tcpls_v4_addr_t *get_v4_addr(tcpls_t *tcpls, int socket);
static tcpls_v6_addr_t *get_v6_primary_addr(tcpls_t *tcpls);
static tcpls_v6_addr_t *get_v6_addr(tcpls_t *tcpls, int socket);
static tcpls_stream_t *stream_get(tcpls_t *tcpls, streamid_t streamid);

void *tcpls_new(void *ctx, int is_server) {
  ptls_context_t *ptls_ctx = (ptls_context_t *) ctx;
  ptls_t *tls;
  tcpls_t *tcpls  = malloc(sizeof(*tcpls));
  if (tcpls == NULL)
    return NULL;
  if (is_server) {
    tls = ptls_server_new(ptls_ctx);
    tcpls->next_stream_id = 2147483648;  // 2**31
  }
  else {
    tls = ptls_client_new(ptls_ctx);
    tcpls->next_stream_id = 0;
  }
  // init tcpls stuffs
  tcpls->sendbuf = malloc(sizeof(*tcpls->sendbuf));
  tcpls->recvbuf = malloc(sizeof(*tcpls->recvbuf));
  tcpls->tls = tls;
  ptls_buffer_init(tcpls->sendbuf, "", 0);
  ptls_buffer_init(tcpls->recvbuf, "", 0);
  ptls_ctx->output_decrypted_tcpls_data = 1;
  tcpls->socket_primary = 0;
  tcpls->socket_rcv = 0;
  tcpls->v4_addr_llist = NULL;
  tcpls->v6_addr_llist = NULL;
  tcpls->nbr_of_peer_streams_attached = 0;
  tcpls->nbr_tcp_streams = 0;
  tcpls->tcpls_options = new_list(sizeof(tcpls_options_t), NBR_SUPPORTED_TCPLS_OPTIONS);
  tcpls->streams = new_list(sizeof(tcpls_stream_t), 3);
  tls->tcpls = tcpls;
  return tcpls;
}


int static add_v4_to_options(tcpls_t *tcpls, uint8_t n) {
  /** Contains the number of IPs in [0], and then the 32 bits of IPs */
  uint8_t *addresses = malloc(sizeof(struct in_addr)+1);
  if (!addresses)
    return PTLS_ERROR_NO_MEMORY;
  tcpls_v4_addr_t *current = tcpls->v4_addr_llist;
  int i = 1;
  while (current && i < sizeof(struct in_addr)+1) {
    memcpy(&addresses[i], &current->addr.sin_addr, sizeof(struct in_addr));
    i+=sizeof(struct in_addr);
    current = current->next;
  }
  /** TODO, check what bit ordering to do here */
  addresses[0] = n;
  return tcpls_init_context(tcpls->tls, addresses, sizeof(struct in_addr)+1, MULTIHOMING_v4, 0, 1);
}

int static add_v6_to_options(tcpls_t *tcpls, uint8_t n) {
  uint8_t *addresses = malloc(sizeof(struct in6_addr)+1);
  if (!addresses)
    return PTLS_ERROR_NO_MEMORY;
  tcpls_v6_addr_t *current = tcpls->v6_addr_llist;
  int i = 1;
  while (current &&i < 16*n+1) {
    memcpy(&addresses[i], &current->addr.sin6_addr.s6_addr, sizeof(struct in6_addr));
    i+=sizeof(struct in6_addr);
    current = current->next;
  }
  addresses[0] = n;
  return tcpls_init_context(tcpls->tls, addresses, sizeof(struct in6_addr),
      MULTIHOMING_v6, 0, 1);
}

/** 
 * Copy Sockaddr_in into our structures. If is_primary is set, flip that bit
 * from any other v4 address if set.
 *
 * if settopeer is enabled, it means that this address is actually ours and meant to
 * be sent to the peer
 * 
 * if settopeer is 0, then this address is the peer's one
 */

int tcpls_add_v4(ptls_t *tls, struct sockaddr_in *addr, int is_primary, int settopeer) {
  tcpls_t *tcpls = tls->tcpls;
  /* enable failover */
  if (!settopeer)
    tls->ctx->failover = 1;
  tcpls_v4_addr_t *new_v4 = malloc(sizeof(tcpls_v4_addr_t));
  if (new_v4 == NULL)
    return PTLS_ERROR_NO_MEMORY;
  new_v4->is_primary = is_primary;
  new_v4->state = CLOSED;
  new_v4->socket = 0;
  memcpy(&new_v4->addr, addr, sizeof(*addr));
  new_v4->next = NULL;

  tcpls_v4_addr_t *current = tcpls->v4_addr_llist;
  if (!current) {
    tcpls->v4_addr_llist = new_v4;
    if (settopeer)
      return add_v4_to_options(tcpls, 1);
    return 0;
  }
  int n = 0;
  while (current->next) {
    if (current->is_primary && is_primary) {
      current->is_primary = 0;
    }
    /** we already added this address */
    if (!memcmp(&current->addr, addr, sizeof(*addr))) {
      free(new_v4);
      return -1;
    }
    current = current->next;
    n++;
  }
  /** look into the last item */
  if (!memcmp(&current->addr, addr, sizeof(*addr))) {
    free(new_v4);
    return -1;
  }
  current->next = new_v4;
  if (settopeer)
    return add_v4_to_options(tcpls, n);
  return 0;
}

int tcpls_add_v6(ptls_t *tls, struct sockaddr_in6 *addr, int is_primary, int settopeer) {
  tcpls_t *tcpls = tls->tcpls;
  tcpls_v6_addr_t *new_v6 = malloc(sizeof(*new_v6));
  if (new_v6 == NULL)
    return PTLS_ERROR_NO_MEMORY;
  new_v6->is_primary = is_primary;
  new_v6->state = CLOSED;
  new_v6->socket = 0;
  memcpy(&new_v6->addr, addr, sizeof(*addr));
  new_v6->next = NULL;

  tcpls_v6_addr_t *current = tcpls->v6_addr_llist;
  if (!current) {
    tcpls->v6_addr_llist = new_v6;
    if (settopeer)
      return add_v6_to_options(tcpls, 1);
    return 0;
  }
  int n = 0;
  while(current->next) {
    if (current->is_primary && is_primary) {
      current->is_primary = 0;
    }
    if (!memcmp(&current->addr, addr, sizeof(*addr))) {
      free(new_v6);
      return -1;
    }
    current = current->next;
    n++;
  }
  if (!memcmp(&current->addr, addr, sizeof(*addr))) {
    free(new_v6);
    return -1;
  }
  current->next = new_v6;
  if (settopeer)
    return add_v6_to_options(tcpls, n);
  return 0;
}
/** For connect-by-name sparing 2-RTT logic! Much much further work */
int tcpls_add_domain(ptls_t *tls, char* domain) {
  return 0;
}

/**
 * Makes TCP connections to registered IPs that are in CLOSED state.
 *
 * Returns -1 upon error
 *         -2 upon timeout experiration without any addresses connected
 *         1 if the timeout fired but some address(es) connected
 *         0 if all addresses connected
 */
int tcpls_connect(ptls_t *tls) {
  tcpls_t *tcpls = tls->tcpls;
  int maxfds = 0;
  int nfds = 0;
  fd_set wset;
  FD_ZERO(&wset);
#define HANDLE_CONNECTS(current, afinet) do {                                               \
  while (current) {                                                                 \
    if (current->state == CLOSED){                                                  \
      if (!current->socket) {                                                       \
        if ((current->socket = socket(afinet, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0) {\
          current = current->next;                                                  \
          continue;                                                                 \
        }                                                                           \
        FD_SET(current->socket, &wset);                                             \
        nfds++;                                                                     \
        if (current->socket > maxfds)                                               \
          maxfds = current->socket;                                                 \
      }                                                                             \
      if (connect(current->socket, (struct sockaddr*) &current->addr, sizeof(current->addr)) < 0 && errno != EINPROGRESS) {\
        close(current->socket);                                                     \
        current = current->next;                                                    \
        continue;                                                                   \
      }                                                                             \
      current->state = CONNECTING;                                                  \
    }                                                                               \
    else if (current->state == CONNECTING) {                                        \
      FD_SET(current->socket, &wset);                                               \
      nfds++;                                                                       \
      if (current->socket > maxfds)                                                 \
        maxfds = current->socket;                                                   \
    }                                                                               \
    current = current->next;                                                        \
  }                                                                                 \
} while (0)

  // Connect with v4 addresses first
  tcpls_v4_addr_t *current_v4 = tcpls->v4_addr_llist;
  HANDLE_CONNECTS(current_v4, AF_INET);
  tcpls_v6_addr_t *current_v6 = tcpls->v6_addr_llist;
  // Connect with v6 addresses
  HANDLE_CONNECTS(current_v6, AF_INET6);
#undef HANDLE_CONNECTS

  /* wait until all connected or the timeout fired */
  int ret;
  int remaining_nfds = nfds;
  current_v4 = tcpls->v4_addr_llist;
  current_v6 = tcpls->v6_addr_llist;
  struct timeval t_initial, timeout, t_previous, t_current;
  gettimeofday(&t_initial, NULL);
  memcpy(&t_previous, &t_initial, sizeof(t_previous));
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  tcpls->nbr_tcp_streams = nfds;

#define CHECK_WHICH_CONNECTED(current) do {                                         \
  while (current) {                                                                 \
    if (current->state == CONNECTING && FD_ISSET(current->socket,                   \
          &wset)) {                                                                 \
      current->connect_time.tv_sec = sec;                                           \
      current->connect_time.tv_usec = rtt - sec*(uint64_t)1000000;                  \
      current->state = CONNECTED;                                                   \
      int flags = fcntl(current->socket, F_GETFL);                                  \
      flags &= ~O_NONBLOCK;                                                         \
      fcntl(current->socket, F_SETFL, flags);                                       \
    }                                                                               \
    current = current->next;                                                        \
  }                                                                                 \
} while(0) 
 
  while (remaining_nfds) {
    if ((ret = select(maxfds+1, NULL, &wset, NULL, &timeout)) < 0) {
      return -1;
    }
    else if (!ret) {
      /* the timeout fired! */
      if (remaining_nfds == nfds) {
        /* None of the addresses connected */
        return -2;
      }
      return 1;
    }
    else {
      gettimeofday(&t_current, NULL);
      
      int new_val =
        timeout.tv_sec*(uint64_t)1000000+timeout.tv_usec
          - (t_current.tv_sec*(uint64_t)1000000+t_current.tv_usec
              - t_previous.tv_sec*(uint64_t)1000000-t_previous.tv_usec);

      memcpy(&t_previous, &t_current, sizeof(t_previous));
     
      int rtt = t_current.tv_sec*(uint64_t)1000000+t_current.tv_usec
        - t_initial.tv_sec*(uint64_t)1000000-t_initial.tv_usec;

      int sec = new_val / 1000000;
      timeout.tv_sec = sec;
      timeout.tv_usec = new_val - timeout.tv_sec*(uint64_t)1000000;

      sec = rtt / 1000000;

      CHECK_WHICH_CONNECTED(current_v4);
      CHECK_WHICH_CONNECTED(current_v6);
      remaining_nfds--;
    }
  }
#undef CHECK_WHICH_CONNECTED
  _set_primary(tcpls);
  return 0;
}


/**
 * Create and attach locallty a new stream to the main address if no addr
 * is provided; else attach to addr if we have a connection open to it
 *
 * returns -1 if a stream is alreay attached for addr
 */

streamid_t tcpls_stream_new(ptls_t *tls, struct sockaddr *addr) {
  /** Check first whether a stream isn't already attach to this addr */
  tcpls_t *tcpls = tls->tcpls;
  assert(tcpls);
  tcpls_stream_t *stream = NULL;
  for (int i = 0; i < tcpls->streams->size; i++) {
    stream = list_get(tcpls->streams, i);
    if (addr->sa_family == AF_INET && stream->v4_addr && !memcmp(&stream->v4_addr->addr,
          addr, sizeof(*addr)))
    {
      return -1;
    }
    else if (addr->sa_family == AF_INET6  && stream->v6_addr &&
        !memcpy(&stream->v6_addr->addr, addr, sizeof(struct sockaddr_in6))) {
      return -1;
    }
  }
  if (addr->sa_family == AF_INET) {
    tcpls_v4_addr_t *current = tcpls->v4_addr_llist;
    if (!current) {
      return -1;
    }
    int found = 0;
    while (current) {
      if (!memcmp(&current->addr, (struct sockaddr_in*) addr, sizeof(struct sockaddr_in))) {
        found = 1;
        break;
      }
      current = current->next;
    }
    if (!found)
      return -1;
    stream = stream_new(tls, tcpls->next_stream_id++, current, NULL, 1);
  }
  else {
    tcpls_v6_addr_t *current = tcpls->v6_addr_llist;
    if (!current)
      return -1;
    int found = 0;
    while (current) {
      if (!memcmp(&current->addr, (struct sockaddr_in6 *) addr, sizeof(struct sockaddr_in6))) {
        found = 1;
        break;
      }
      current = current->next;
    }
    if (!found)
      return -1;
    stream = stream_new(tls, tcpls->next_stream_id++, NULL, current, 1);
  }
  if (!stream)
    return -1;
  list_add(tcpls->streams, stream);
  return stream->streamid;
}

/**
* Encrypts and sends input towards the primary path if available; else sends
* towards the fallback path if the option is activated.
*
* Only send if the socket is within a connected state 
*
* Send through streamid; or to the primary one if streamid = 0
* Send through the primary; or switch the primary if some problem occurs
*/


ssize_t tcpls_send(ptls_t *tls, streamid_t streamid, const void *input, size_t nbytes) {
  tcpls_t *tcpls = tls->tcpls;
  int ret;
  tcpls_stream_t *stream;
  /*int is_failover_enabled = 0;*/
  /** Check the state of connections first do we have our primary connected tcp? */
  if (!streamid && !tcpls->socket_primary) {
    return -1;
  }
  /** Check whether we already have a stream open; if not, build a stream
   * with the default context */
  //TODO
  if (!tcpls->streams->size) {
    // Create a stream with the default context, attached to primary IP
    tcpls_v4_addr_t *addr = get_v4_primary_addr(tcpls);
    tcpls_v6_addr_t *addr6 = get_v6_primary_addr(tcpls);
    assert(addr || addr6);
    stream = stream_new(tls, tcpls->next_stream_id++, addr, addr6, 1);

    stream->aead_enc =  tcpls->tls->traffic_protection.enc.aead;
    stream->aead_dec =  tcpls->tls->traffic_protection.dec.aead;
    list_add(tcpls->streams, stream);

    uint8_t input[4];
    /** send the stream id to the peer */
    memcpy(input, &stream->streamid, 4);
    /** Add a stream message creation to the sending buffer ! */
    stream_send_control_message(tcpls, stream, input, STREAM_ATTACH, 0);
  }
  else {
    stream = stream_get(tcpls, streamid);
  }
  if (!stream)
    return -1;

  // For compatibility with picotcpls; set the traffic_protection context
  // of the stream we want to use
  ptls_aead_context_t *remember_aead = tcpls->tls->traffic_protection.enc.aead;
  // get the right  aead context matching the stream id
  // This is done for compabitility with original PTLS's unit tests
  tcpls->tls->traffic_protection.enc.aead = stream->aead_enc;
  ret = ptls_send(tcpls->tls, tcpls->sendbuf, input, nbytes);
  tcpls->tls->traffic_protection.enc.aead = remember_aead;
  switch (ret) {
    /** Error in encryption -- TODO document the possibilties */
    default: return ret;
  }
  /** Send over the socket's stream */
  int sock_to_use;
  if (stream->v4_addr) {
    sock_to_use = stream->v4_addr->socket;
  }
  else if (stream->v6_addr) {
    sock_to_use = stream->v6_addr->socket;
  }
  /** Get the primary address */
  ret = send(sock_to_use, tcpls->sendbuf->base, tcpls->sendbuf->off, 0);
  if (ret < 0) {
    /** The peer reset the connection */
    if (errno == ECONNRESET) {
      /** We might still have data in the socket, and we don't how much the
       * server read */
      //TODO send the last unacked records from streamid x the buffer
      //over the secondary path
    
      errno = 0; // reset after the problem is resolved =)
    }
    else if (errno == EPIPE) {
      /** Normal close (FIN) then RST */
    }
  }
  return 0;
}

/**
 * Wait at most tv time over all stream sockets to be available for reading
 *
 * // TODO adding configurable callbacks for TCPLS events
 */

ssize_t tcpls_receive(ptls_t *tls, void *buf, size_t nbytes, struct timeval *tv) {
  fd_set rset;
  int ret;
  tcpls_t *tcpls = tls->tcpls;
  list_t *socklist = new_list(sizeof(int), tcpls->nbr_tcp_streams);
  FD_ZERO(&rset);
#define ADD_TO_RSET(current) do {                                     \
  while (current) {                                                   \
    FD_SET(current->socket, &rset);                                   \
    list_add(socklist, &current->socket);                             \
    current = current->next;                                          \
  }                                                                   \
} while(0);
  tcpls_v4_addr_t *current = tcpls->v4_addr_llist;
  ADD_TO_RSET(current);
  tcpls_v6_addr_t *current_v6 = tcpls->v6_addr_llist;
  ADD_TO_RSET(current_v6);
#undef ADD_TO_RSET
  ret = select(socklist->size+1, &rset, NULL, NULL, tv);
  if (ret == -1) {
    list_free(socklist);
    return -1;
  }
  int *socket;
  ret = 0;
  uint8_t input[nbytes];
  for (int i =  0; i < socklist->size; i++) {
     socket = list_get(socklist, i);
     if (FD_ISSET(*socket, &rset)) {
       ret = read(*socket, input, nbytes);
       if (ret == -1) {
         //things TODO ?
         list_free(socklist);
         return ret;
       }
       break;
     }
  }
  tcpls->socket_rcv = *socket;
  /* We have stuff to decrypts */
  if (ret > 0) {
    ptls_buffer_t decryptbuf;
    ptls_buffer_init(&decryptbuf, "", ret);
    //TODO put the right decryption context
    if ((ptls_receive(tls, &decryptbuf, input, (size_t*)&ret) != 0)) {
      ptls_buffer_dispose(&decryptbuf);
      list_free(socklist);
      return ret;
    }
    memcpy(buf, decryptbuf.base, decryptbuf.off);
    ret = decryptbuf.off;
    ptls_buffer_dispose(&decryptbuf);
  }
  return ret;
}

/**
 * Sends a tcp option which has previously been registered with ptls_set...
 *
 * This function should be called after the handshake is complete for both party
 * */
int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, tcpls_enum_t type)
{
  tcpls_t *tcpls = tls->tcpls;
  if(tls->traffic_protection.enc.aead == NULL)
    return -1;
  
  if (tls->traffic_protection.enc.aead->seq >= 16777216)
    tls->needs_key_update = 1;

  if (tls->needs_key_update) {
        int ret;
        if ((ret = update_send_key(tls, sendbuf, tls->key_update_send_request)) != 0)
            return ret;
        tls->needs_key_update = 0;
        tls->key_update_send_request = 0;
  }
  /** Get the option */
  tcpls_options_t *option;
  int found = 0;
  for (int i = 0; i < tcpls->tcpls_options->size && !found; i++) {
    option = list_get(tcpls->tcpls_options, i);
    if (option->type == type && option->data->base && option->settopeer) {
      found = 1;
      break;
    }
  }
  if (!found)
    return -1;

  if (option->is_varlen) {
    /** We need to send the size of the option, which we might need to buffer */
    /** 4 bytes for the variable length, 2 bytes for the option value */
    uint8_t input[option->data->len + sizeof(option->type) + 4];
    memcpy(input, &option->type, sizeof(option->type));
    memcpy(input+sizeof(option->type), &option->data->len, 4);
    memcpy(input+sizeof(option->type)+4, option->data->base, option->data->len);
    return buffer_push_encrypted_records(sendbuf,
        PTLS_CONTENT_TYPE_TCPLS_OPTION, input,
        option->data->len+sizeof(option->type)+4, tls->traffic_protection.enc.aead);
  }
  else {
    uint8_t input[option->data->len + sizeof(option->type)];
    memcpy(input, &option->type, sizeof(option->type));
    memcpy(input+sizeof(option->type), option->data->base, option->data->len);

    return buffer_push_encrypted_records(sendbuf,
        PTLS_CONTENT_TYPE_TCPLS_OPTION, input,
        option->data->len+sizeof(option->type), tls->traffic_protection.enc.aead);
  }
}

/**=====================================================================================*/
/**
 * ptls_set_[TCPOPTION] needs to have been called first to initialize an option 
 */

/**
 * Set a timeout option (i.e., RFC5482) to transport within the TLS connection
 */
int ptls_set_user_timeout(ptls_t *ptls, uint16_t value, uint16_t sec_or_min,
    uint8_t setlocal, uint8_t settopeer) {
  int ret = 0;
  uint16_t *val = malloc(sizeof(uint16_t));
  if (val == NULL)
    return PTLS_ERROR_NO_MEMORY;
  *val = value | sec_or_min << 15;
  ret = tcpls_init_context(ptls, val, 2, USER_TIMEOUT, setlocal, settopeer);
  if (ret)
    return ret;
  if (setlocal) {
    ret = setlocal_usertimeout(ptls, *val);
  }
  return ret;
}

/**
 *  Notes
 *
 *  Need to use poll() or select() to the set of fds to read back pong messages
 *  added IPs path to probe)
 *
 */

int ptls_set_happy_eyeball(ptls_t *ptls) {
  return 0;
}

int ptls_set_faileover(ptls_t *ptls, char *address) {
  return 0;
}
/**
 * Copy bpf_prog_bytecode inside ptls->tcpls_options
 *
 */
int ptls_set_bpf_cc(ptls_t *ptls, const uint8_t *bpf_prog_bytecode, size_t bytecodelen,
    int setlocal, int settopeer) {
  int ret = 0;
  uint8_t* bpf_cc = NULL;
  if ((bpf_cc =  malloc(bytecodelen)) == NULL)
    return PTLS_ERROR_NO_MEMORY;
  memcpy(bpf_cc, bpf_prog_bytecode, bytecodelen);
  ret = tcpls_init_context(ptls, bpf_cc, bytecodelen, BPF_CC, setlocal, settopeer);
  if (ret)
    return -1;
  if (setlocal){
    ret = setlocal_bpf_cc(ptls, bpf_prog_bytecode, bytecodelen);
  }
  return ret;
}

/*===================================Internal========================================*/

/**
 * Send a message to the peer to 
 *    - initiate a new stream
 *    - close a new stream
 *    - send a acknowledgment
 *
 * Note, currently we implement 1 stream per TCP connection
 */

static int stream_send_control_message(tcpls_t *tcpls, tcpls_stream_t *stream,
    const void *inputinfo, tcpls_enum_t tcpls_message, uint32_t message_len) {
  uint8_t input[message_len];
  memcpy(input, &tcpls_message, sizeof(tcpls_message));
  memcpy(input+sizeof(tcpls_message), inputinfo, message_len);
  return buffer_push_encrypted_records(tcpls->sendbuf,
      PTLS_CONTENT_TYPE_TCPLS_OPTION, input,
      message_len+sizeof(tcpls_message), stream->aead_enc);
}

static int  tcpls_init_context(ptls_t *ptls, const void *data, size_t datalen,
    tcpls_enum_t type, uint8_t setlocal, uint8_t settopeer) {
  tcpls_t *tcpls = ptls->tcpls;
  ptls->ctx->support_tcpls_options = 1;
  /** Picking up the right slot in the list, i.e;, the first unused should have
   * a len of 0
   * */
  tcpls_options_t *option = NULL;
  int found_one = 0;
  for (int i = 0; i < tcpls->tcpls_options->size; i++) {
    /** already set or Not yet set */
    option = list_get(tcpls->tcpls_options, i);
    if (option->type == type && option->data->base) {
      found_one = 1;
      break;
    }
  }
  /** let's create it and add it to the list */
  if (!found_one) {
    option = malloc(sizeof(tcpls_options_t));
    option->data = malloc(sizeof(ptls_iovec_t));
    memset(option->data, 0, sizeof(ptls_iovec_t));
    option->type = type;
    option->is_varlen = 0;
  }

  option->setlocal = setlocal;
  option->settopeer = settopeer;

  switch (type) {
    case USER_TIMEOUT:
      if (found_one) {
        free(option->data->base);
      }
      option->is_varlen = 0;
      *option->data = ptls_iovec_init(data, sizeof(uint16_t));
      option->type = USER_TIMEOUT;
      if (!found_one) {
        /** copy the option, free this one */
        list_add(tcpls->tcpls_options, option);
        free(option);
      }
      return 0;
    case MULTIHOMING_v4:
    case MULTIHOMING_v6:
      if (option->data->len) {
        free(option->data->base);
      }
      *option->data = ptls_iovec_init(data, datalen);
      option->type = type;
      if (!found_one) {
        /** copy the option, free this one */
        list_add(tcpls->tcpls_options, option);
        free(option);
      }
      return 0;
    case BPF_CC:
      if (option->data->len) {
      /** We already had one bpf cc, free it */
        free(option->data->base);
      }
      option->is_varlen = 1;
      *option->data = ptls_iovec_init(data, datalen);
      option->type = BPF_CC;
      if (!found_one) {
        /** copy the option, free this one */
        list_add(tcpls->tcpls_options, option);
        free(option);
      }
      return 0;
    default:
        break;
  }
  return -1;
}

/**
 * Handle TCPLS extension
 *
 * Note: the implementation currently does not handle malformed options (we
 * should check our parsing and send alert messages upon inapropriate data)
 */

int handle_tcpls_extension_option(ptls_t *ptls, tcpls_enum_t type,
    const uint8_t *input, size_t inputlen) {
  if (!ptls->ctx->tcpls_options_confirmed)
    return -1;
  switch (type) {
    case USER_TIMEOUT:
      {
        uint16_t *nval = malloc(inputlen);
        *nval = (uint16_t) *input;
        int ret;
        /**nval = ntoh16(input);*/
        ret= tcpls_init_context(ptls, nval, 2, USER_TIMEOUT, 1, 0);
        if (ret)
          return -1; /** Should define an appropriate error code */
        return setlocal_usertimeout(ptls, *nval);
      }
      break;
    case MULTIHOMING_v4:
      {
        /** input should contain a list of v4 IP addresses */
        printf("Receiving MULTIHOMING extension\n");
        int ret = 0;
        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(443); /** Not great; but it's fine for a POC; else we also need
                                        to reference the port somewhere */
        uint8_t nbr = *input;
        int offset = 0;
        while(nbr && !ret) {
          memcpy(&addr.sin_addr, input+1+offset, sizeof(struct in_addr));
          offset+=sizeof(struct in_addr);
          ret = tcpls_add_v4(ptls, &addr, 0, 0);
          nbr--;
        }
        return ret;
      }
      break;
    case MULTIHOMING_v6:
      {
      /** input should contain a list of v6 IP addresses */
        int ret = 0;
        struct sockaddr_in6 addr;
        bzero(&addr, sizeof(addr));
        addr.sin6_family = AF_INET6;
        uint8_t nbr = *input;
        int offset = 0;
        while (nbr && !ret) {
          memcpy(&addr.sin6_addr, input+1+offset, sizeof(struct in6_addr));
          offset+=sizeof(struct in6_addr);
          ret = tcpls_add_v6(ptls, &addr, 0, 0);
          nbr--;
        }
        return ret;
      }
      break;
    case STREAM_CLOSE:
      {
       streamid_t streamid = (streamid_t) *input;
       tcpls_stream_t *stream = stream_get(ptls->tcpls, streamid);
       if (!stream) {
         /** What to do? this should not happen - Close the connection*/
         return -1;
       }
       /** Note, we current assume only one stream per address */
       close(ptls->tcpls->socket_rcv);
       list_remove(ptls->tcpls->streams, stream);
       stream_free(stream);
       return 0;
      }
      break;
    case STREAM_ATTACH:
      {
        //TODO fix this with sending with network order and receiving with host
        //order
        streamid_t streamid = (streamid_t) *input;
        tcpls_v4_addr_t *addr = get_v4_addr(ptls->tcpls, ptls->tcpls->socket_rcv);
        tcpls_v6_addr_t *addr6 = NULL;
        if (!addr) {
          addr6 = get_v6_addr(ptls->tcpls, ptls->tcpls->socket_rcv);
        }
        tcpls_stream_t *stream = stream_new(ptls, streamid, addr, addr6, 0);
        if (!stream) {
          return PTLS_ERROR_NO_MEMORY;
        }
        list_add(ptls->tcpls->streams, stream);
        return 0;
      }
      break;
    case FAILOVER:
      break;
    case BPF_CC:
      {
        int ret;
        /** save the cc; will be freed at tcpls_free */
        uint8_t *bpf_prog = malloc(inputlen);
        memcpy(bpf_prog, input, inputlen);
        ret = tcpls_init_context(ptls, bpf_prog, inputlen, BPF_CC, 1, 0);
        if (ret)
          return -1;
        return setlocal_bpf_cc(ptls, bpf_prog, inputlen);
      }
      break;
    default:
      printf("Unsuported option?");
      return -1;
  }
 return 0;
}

/**
 * Handle single record and varlen options with possibly many records
 *
 * varlen records must be sent over the same stream for appropriate buffering
 * //TODO make the buffering per-stream!
 */

int handle_tcpls_record(ptls_t *tls, struct st_ptls_record_t *rec)
{
  int ret = 0;
  tcpls_enum_t type;
  uint8_t *init_buf = NULL;
  /** Assumes a TCPLS option holds within 1 record ; else we need to buffer the
   * option to deliver it to handle_tcpls_extension_option 
   * */
  if (!tls->tcpls_buf) {
    if ((tls->tcpls_buf = malloc(sizeof(*tls->tcpls_buf))) == NULL) {
      ret = PTLS_ERROR_NO_MEMORY;
      goto Exit;
    }
    memset(tls->tcpls_buf, 0, sizeof(*tls->tcpls_buf));
  }
  
  type = (tcpls_enum_t) *rec->fragment;
  /** Check whether type is a variable len option */
  if (is_varlen(type)){
    /*size_t optsize = ntoh32(rec->fragment+sizeof(type));*/
    uint32_t optsize = (uint32_t) *(rec->fragment+sizeof(type));
    if (optsize > PTLS_MAX_PLAINTEXT_RECORD_SIZE-sizeof(type)-4) {
      /** We need to buffer it */
      /** Check first if the buffer has been initialized */
      if (!tls->tcpls_buf->base) {
        if ((init_buf = malloc(VARSIZE_OPTION_MAX_CHUNK_SIZE)) == NULL) {
          ret = PTLS_ERROR_NO_MEMORY;
          goto Exit;
        }
        ptls_buffer_init(tls->tcpls_buf, init_buf, VARSIZE_OPTION_MAX_CHUNK_SIZE);
      }
      /** always reserve memory (won't if enough left) */
      if ((ret = ptls_buffer_reserve(tls->tcpls_buf, rec->length-sizeof(type)-4)) != 0)
        goto Exit;
      memcpy(tls->tcpls_buf->base+tls->tcpls_buf->off, rec->fragment+sizeof(type)+4, rec->length-sizeof(type)-4);
      tls->tcpls_buf->off += rec->length - sizeof(type)-4;
      
      if (ret)
        goto Exit;
      if (tls->tcpls_buf->off == optsize) {
        /** We have all of it */
        ret = handle_tcpls_extension_option(tls, type, tls->tcpls_buf->base, optsize);
        ptls_buffer_dispose(tls->tcpls_buf);
      }
      return ret;
    }
    else {
      return handle_tcpls_extension_option(tls, type, rec->fragment+sizeof(type)+4, optsize);
    }
  }
  /** We assume that only Variable size options won't hold into 1 record */
  return handle_tcpls_extension_option(tls, type, rec->fragment+sizeof(type), rec->length-sizeof(type));

Exit:
  ptls_buffer_dispose(tls->tcpls_buf);
  /*free(tls->tcpls_buf);*/
  return ret;
}

static int setlocal_usertimeout(ptls_t *ptls, int val) {
  return 0;
}


static int setlocal_bpf_cc(ptls_t *ptls, const uint8_t *prog, size_t proglen) {
  return 0;
}


/*=====================================utilities======================================*/

/**
 * Compute the value IV to use for the next stream.
 *
 * It allows the counter to start at 0, and MIN_LOWIV_STREAM_INCREASE prevent
 * the AES counter to have a chance to overlap between calls. However, we must
 * have |sever_iv - client_iv| < max_nbr_streams * MIN_LOWIV_STREAM_INCREASE
 * that should be verified during the handshake (TODO)
 **/

static void stream_derive_new_aead_iv(ptls_t *tls, uint8_t *iv, int iv_size, int is_ours) {
  int mult;
  if (is_ours) {
    /** server next_stream_id starts at 2**31 */
    if (tls->is_server)
      mult = tls->tcpls->next_stream_id-2147483648;
    else
      mult = tls->tcpls->next_stream_id;
  }
  else {
    mult = tls->tcpls->nbr_of_peer_streams_attached;
  }
  if (iv_size == 96) {
    uint32_t low_iv = (uint32_t) iv[8];
    /** if over uin32 MAX; it should properly wrap arround */
    low_iv += mult * MIN_LOWIV_STREAM_INCREASE;
    memcpy(&iv[8], &low_iv, 4);
  }
  else if (iv_size == 128) {
    uint64_t low_iv = (uint64_t) iv[8];
    low_iv += mult * MIN_LOWIV_STREAM_INCREASE;
    memcpy(&iv[8], &low_iv, 8);
  }
}

/**
 * Create a new stream and attach it to a local addr.
 * if addr is set, addr6 must be NULL;
 * if addr6 is set, addr must be NULL;
 * 
 * is_ours tells whether this stream has been initiated by us (is_our = 1), or
 * initiated by the peer (STREAM_ATTACH event, is_ours = 0)
 */

static tcpls_stream_t *stream_new(ptls_t *tls, streamid_t streamid,
    tcpls_v4_addr_t *addr, tcpls_v6_addr_t *addr6, int is_ours) {
  tcpls_stream_t *stream = malloc(sizeof(*stream));
  stream->streamid = streamid;
  stream->list_id = streamid;

  /** TODO figure out a good default size for the control flow */
  stream->send_queue = tcpls_record_queue_new(500);
  if (addr) {
    stream->v4_addr = addr;
  }
  else if (addr6) {
    stream->v6_addr = addr6;
  }
  /** Now derive a correct aead context for this stream */
  stream->aead_enc = (ptls_aead_context_t *) malloc(tls->cipher_suite->aead->context_size);
  if (!stream->aead_enc)
    return NULL;
  memcpy(stream->aead_enc, &tls->traffic_protection.enc, sizeof(tls->traffic_protection.enc));
  /** restart the counter */
  stream->aead_enc->seq = 0;
  /** now change the lower half bits of the IV to avoid collisions */
  stream_derive_new_aead_iv(tls, stream->aead_enc->static_iv,
      tls->cipher_suite->aead->iv_size, is_ours);
  stream->aead_dec = (ptls_aead_context_t *) malloc(tls->cipher_suite->aead->context_size);
  if (stream->aead_dec)
    return NULL;
  memcpy(stream->aead_dec, &tls->traffic_protection.dec, sizeof(tls->traffic_protection.dec));
  stream->aead_dec->seq = 0;
  stream_derive_new_aead_iv(tls, stream->aead_dec->static_iv,
      tls->cipher_suite->aead->iv_size, is_ours);
  return stream;
}

tcpls_stream_t *stream_get(tcpls_t *tcpls, streamid_t streamid) {
  if (!tcpls->streams)
    return NULL;
  tcpls_stream_t *stream;
  for (int i = 0; i < tcpls->streams->size; i++) {
    stream = list_get(tcpls->streams, i);
    if (stream->streamid == streamid)
      return stream;
  }
  return NULL;
}

static void stream_free(tcpls_stream_t *stream) {
  if (!stream)
    return;
  ptls_aead_free(stream->aead_enc);
  ptls_aead_free(stream->aead_dec);
  free(stream);
}

tcpls_v4_addr_t *get_v4_primary_addr(tcpls_t *tcpls) {
  tcpls_v4_addr_t *current = tcpls->v4_addr_llist;
  int has_primary = 0;
  while (current && !has_primary) {
    if (current->is_primary) {
      has_primary = 1;
      continue;
    }
    current = current->next;
  }
  if (has_primary)
    return current;
  return NULL;
}

/** could do some code cleanup here */

static tcpls_v4_addr_t *get_v4_addr(tcpls_t *tcpls, int socket) {
  tcpls_v4_addr_t *current = tcpls->v4_addr_llist;
  while (current) {
    if (current->socket == socket)
      return current;
    current = current->next;
  }
  return NULL;
}

static tcpls_v6_addr_t *get_v6_addr(tcpls_t *tcpls, int socket) {
  tcpls_v6_addr_t *current = tcpls->v6_addr_llist;
  while (current) {
    if (current->socket == socket)
      return current;
    current = current->next;
  }
  return NULL;
}

tcpls_v6_addr_t *get_v6_primary_addr(tcpls_t *tcpls) {
  tcpls_v6_addr_t *current = tcpls->v6_addr_llist;
  int has_primary = 0;
  while (current && !has_primary) {
    if (current->is_primary) {
      has_primary = 1;
      continue;
    }
    current = current->next;
  }
  if (has_primary)
    return current;
  return NULL;
}

/**
 * ret < 0 : t1 < t2
 * ret == 0: t1 == t2
 * ret > 0 : t1 > t2
 */
static int cmp_times(struct timeval *t1, struct timeval *t2) {
  int64_t val = t1->tv_sec*1000000 + t1->tv_usec - t2->tv_sec*1000000-t2->tv_usec;
  if (val < 0)
    return -1;
  else if (val == 0)
    return 0;
  else
    return 1;
}

/**
 * If a a primary address has not been set by the application, set the
 * address for which we connected the fastest as primary
 */

static void _set_primary(tcpls_t *tcpls) {
  tcpls_v4_addr_t *current_v4 = tcpls->v4_addr_llist;
  tcpls_v6_addr_t *current_v6 = tcpls->v6_addr_llist;
  tcpls_v4_addr_t *primary_v4 = current_v4;
  tcpls_v6_addr_t *primary_v6 = current_v6;
  int has_primary = 0;
#define CHECK_PRIMARY(current, primary) do {                                            \
  while (current) {                                                                     \
    if (current->is_primary) {                                                          \
      has_primary = 1;                                                                  \
      break;                                                                            \
    }                                                                                   \
    if (cmp_times(&primary->connect_time, &current->connect_time) < 0)                  \
      primary = current;                                                                \
                                                                                        \
    current = current->next;                                                            \
  }                                                                                     \
} while(0)

  CHECK_PRIMARY(current_v4, primary_v4);
  if (has_primary)
    return;
  CHECK_PRIMARY(current_v6, primary_v6);
  if (has_primary)
    return;
  assert(primary_v4 || primary_v6);
  /* if we hav a v4 and a v6, compare them */
  if (primary_v4 && primary_v6) {
    switch (cmp_times(&primary_v4->connect_time, &primary_v6->connect_time)) {
      case -1: primary_v4->is_primary = 1;
               tcpls->socket_primary = primary_v4->socket; break;
      case 0:
      case 1: primary_v6->is_primary = 1;
              tcpls->socket_primary = primary_v6->socket; break;
      default: primary_v6->is_primary = 1;
               tcpls->socket_primary = primary_v6->socket; break;
    }
  } else if (primary_v4) {
    primary_v4->is_primary = 1;
  } else if (primary_v6) {
    primary_v6->is_primary = 1;
  }
#undef CHEK_PRIMARY
}

static int is_varlen(tcpls_enum_t type) {
  return (type == BPF_CC);
}

void ptls_tcpls_options_free(tcpls_t *tcpls) {
  if (!tcpls)
    return;
  tcpls_options_t *option = NULL;
  for (int i = 0; i < tcpls->tcpls_options->size; i++) {
    option = list_get(tcpls->tcpls_options, i);
    if (option->data->base) {
      free(option->data->base);
    }
    free(option->data);
  }
  list_free(tcpls->tcpls_options);
  tcpls->tcpls_options = NULL;
}

void tcpls_free(tcpls_t *tcpls) {
  if (!tcpls)
    return;
  ptls_buffer_dispose(tcpls->recvbuf);
  ptls_buffer_dispose(tcpls->sendbuf);
  free(tcpls->sendbuf);
  free(tcpls->recvbuf);
  list_free(tcpls->streams);
  ptls_tcpls_options_free(tcpls);
#define FREE_ADDR_LLIST(current, next) do {              \
  if (!next) {                                           \
    free(current);                                       \
  }                                                      \
  else {                                                 \
    while (next) {                                       \
      free(current);                                     \
      current = next;                                    \
      next = next->next;                                 \
    }                                                    \
  }                                                      \
} while(0);
  if (tcpls->v4_addr_llist) {
    tcpls_v4_addr_t *current = tcpls->v4_addr_llist;
    tcpls_v4_addr_t *next = current->next;
    FREE_ADDR_LLIST(current, next);
  }
  if (tcpls->v6_addr_llist) {
    tcpls_v6_addr_t *current = tcpls->v6_addr_llist;
    tcpls_v6_addr_t *next = current->next;
    FREE_ADDR_LLIST(current, next);
  }
#undef FREE_ADDR_LLIST
  ptls_free(tcpls->tls);
  free(tcpls);
}
