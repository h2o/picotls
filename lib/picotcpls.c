/**
 * \file picotcpls.c
 *
 * \brief Implement logic for setting, sending, receiving and processing TCP
 * options through the TLS layer
 *
 * This file defines an API exposed to the application to set localy and/or to the
 * peer some TCP options. We currently support the following options:
 *
 * <ul>
 *    <li> User Timeout RFC5482 </li>
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
 * On the receiver side, the application should loop over ptls_receive until the
 * TLS layer has eventually processed the option. For most of the cases, one
 * call of ptls_receive is enough, but we expect to support option with variable
 * lengths which could spawn over multiple TLS records
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
#include "picotls.h"
#include "picotcpls.h"

/** Forward declarations */
static tcpls_options_t* tcpls_init_context(ptls_t *ptls, const void *data, size_t datalen,
    tcpls_enum_t type, uint8_t setlocal, uint8_t settopeer);

static int is_varlen(tcpls_enum_t type);

static int setlocal_usertimeout(ptls_t *ptls, tcpls_options_t *option);

static int setlocal_bpf_sched(ptls_t *ptls, tcpls_options_t *option);

static void _set_primary(tcpls_t *tcpls);

void *tcpls_new(void *ctx, int is_server) {
  ptls_context_t *ptls_ctx = (ptls_context_t *) ctx;
  return is_server? ptls_server_new(ptls_ctx) : ptls_client_new(ptls_ctx);
}


/** 
 * Copy Sockaddr_in into our structures. If is_primary is set, flip that bit
 * from any other v4 address if set.
 */

int tcpls_add_v4(void *tls_info, struct sockaddr_in *addr, int is_primary) {
  tcpls_t *tcpls = (tcpls_t*) tls_info;
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
    return 0;
  }
  while (current->next) {
    if (current->is_primary && is_primary) {
      current->is_primary = 0;
    }
    current = current->next;
  }
  current->next = new_v4;
  return 0;
}
int tcpls_add_v6(void *tls_info, struct sockaddr_in6 *addr, int is_primary) {
  tcpls_t *tcpls = (tcpls_t*) tls_info;
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
    return 0;
  }
  while(current->next) {
    if (current->is_primary && is_primary) {
      current->is_primary = 0;
    }
    current = current->next;
  }
  current->next = new_v6;
  return 0;
}
/** For connect-by-name sparing 2-RTT logic! Much much further work */
int tcpls_add_domain(void *tls_info, char* domain) {
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
int tcpls_connect(void *tls_info) {
  tcpls_t *tcpls = (tcpls_t*) tls_info;
  int maxfds = 0;
  int nfds = 0;
  fd_set wset;
  FD_ZERO(&wset);
#define HANDLE_CONNECTS(current) do {                                               \
  while (current) {                                                                 \
    if (current->state == CLOSED){                                                  \
      if (!current->socket) {                                                       \
        if ((current->socket = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0) {\
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
  HANDLE_CONNECTS(current_v4);
  tcpls_v6_addr_t *current_v6 = tcpls->v6_addr_llist;
  // Connect with v6 addresses
  HANDLE_CONNECTS(current_v6);
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
 * Encrypts and sends input towards the primary path if available; else sends
 * towards the fallback path if the option is activated.
 *
 * Only send if the socket is within a connected state 
 *
 * Send through the primary; or switch the primary if some problem occurs
 * 
 */

ssize_t tcpls_send(void *tls_info, const void *input, size_t nbytes) {
  tcpls_t *tcpls = (tcpls_t *) tls_info;
  int ret;
  int is_failover_enabled = 0;
  /** Check the state of connections first */
  //TODO
  ret = ptls_send(tcpls->tls, tcpls->sendbuf, input, nbytes);
  
  if (is_failover_enabled) {
    //TODO
  }
  

  switch (ret) {
    /** Error in encryption -- TODO document the possibilties */
    default: return ret;
  }
  /** Get the primary address */
  ret = send(*tcpls->socket_ptr, tcpls->sendbuf->base, tcpls->sendbuf->off, 0);
  if (ret < 0) {
    /** The peer reset the connection */
    if (errno == ECONNRESET) {
      /** We might still have data in the socket, and we don't how much the
       * server read */
    }
    else if (errno == EPIPE) {
      /** Normal close (FIN) then RST */
    }
  }
  return 0;
}

ssize_t tcpls_receive(void *tls_info, const void *input, size_t nbytes) {
  return 0;
}

/**
 * Sends a tcp option which has previously been registered with ptls_set...
 *
 * This function should be called after the handshake is complete for both party
 * */
int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, tcpls_enum_t type)
{
  if(tls->traffic_protection.enc.aead == NULL)
    return -1;
  
  if ((!ptls_is_server(tls) && tls->traffic_protection.enc.seq >= 16777216))
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
  int i;
  int found = 0;
  for (i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS && !found; i++) {
    if (tls->tcpls_options[i].type == type && tls->tcpls_options[i].data->base &&
        tls->tcpls_options[i].settopeer) {
      option = &tls->tcpls_options[i];
      found = 1;
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
        option->data->len+sizeof(option->type)+4, &tls->traffic_protection.enc);
  }
  else {
    uint8_t input[option->data->len + sizeof(option->type)];
    memcpy(input, &option->type, sizeof(option->type));
    memcpy(input+sizeof(option->type), option->data->base, option->data->len);

    return buffer_push_encrypted_records(sendbuf,
        PTLS_CONTENT_TYPE_TCPLS_OPTION, input,
        option->data->len+sizeof(option->type), &tls->traffic_protection.enc);
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
  tcpls_options_t *option;
  uint16_t *val = malloc(sizeof(uint16_t));
  if (val == NULL)
    return PTLS_ERROR_NO_MEMORY;
  *val = value | sec_or_min << 15;
  option = tcpls_init_context(ptls, val, 2, USER_TIMEOUT, setlocal, settopeer);
  if (!option)
    return -1;
  if (option->setlocal) {
    ret = setlocal_usertimeout(ptls, option);
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
  tcpls_options_t *option;
  uint8_t* bpf_cc = NULL;
  if ((bpf_cc =  malloc(bytecodelen)) == NULL)
    return PTLS_ERROR_NO_MEMORY;
  memcpy(bpf_cc, bpf_prog_bytecode, bytecodelen);
  option = tcpls_init_context(ptls, bpf_cc, bytecodelen, BPF_CC, setlocal, settopeer);
  if (!option)
    return -1;
  if (option->setlocal){
    ret = setlocal_bpf_sched(ptls, option);
  }
  return ret;
}

/*===================================Internal========================================*/

static tcpls_options_t*  tcpls_init_context(ptls_t *ptls, const void *data, size_t datalen,
    tcpls_enum_t type, uint8_t setlocal, uint8_t settopeer) {
  ptls->ctx->support_tcpls_options = 1;
  if (!ptls->tcpls_options) {
    ptls->tcpls_options = malloc(sizeof(*ptls->tcpls_options)*NBR_SUPPORTED_TCPLS_OPTIONS);
    for (int i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS; i++) {
      ptls->tcpls_options[i].data = malloc(sizeof(ptls_iovec_t));
      memset(ptls->tcpls_options[i].data, 0, sizeof(ptls_iovec_t));
      ptls->tcpls_options[i].type = 0;
      ptls->tcpls_options[i].setlocal = 0;
      ptls->tcpls_options[i].settopeer = 0;
      ptls->tcpls_options[i].is_varlen = 0;
    }
  }
  /** Picking up the right slot in the list, i.e;, the first unused should have
   * a len of 0
   * */
  tcpls_options_t *option = NULL;
  for (int i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS; i++) {
    /** already set or Not yet set */
    if ((ptls->tcpls_options[i].type == type && ptls->tcpls_options[i].data->base)
        || !ptls->tcpls_options[i].data->base) {
      option = &ptls->tcpls_options[i];
      break;
    }
  }
  if (option == NULL)
    return NULL;

  option->setlocal = setlocal;
  option->settopeer = settopeer;

  switch (type) {
    case USER_TIMEOUT:
      if (option->data->len) {
        /** We already allocated one, free it before getting a new one */
        free(option->data->base);
      }
      option->is_varlen = 0;
      *option->data = ptls_iovec_init(data, sizeof(uint16_t));
      option->type = USER_TIMEOUT;
      return option;
    case FAILOVER_ADDR4:
    case FAILOVER_ADDR6: break;
    case BPF_CC:
      if (option->data->len) {
      /** We already had one bpf cc, free it */
        free(option->data->base);
      }
      option->is_varlen = 1;
      *option->data = ptls_iovec_init(data, datalen);
      option->type = BPF_CC;
      return option;
    default:
        break;
  }
  return NULL;
}

int handle_tcpls_extension_option(ptls_t *ptls, tcpls_enum_t type,
    const uint8_t *input, size_t inputlen) {
  if (!ptls->ctx->tcpls_options_confirmed)
    return -1;
  tcpls_options_t *option = NULL;
  switch (type) {
    case USER_TIMEOUT:
      {
        uint16_t *nval = malloc(inputlen);
        *nval = (uint16_t) *input;
        /**nval = ntoh16(input);*/
        option = tcpls_init_context(ptls, nval, 2, USER_TIMEOUT, 1, 0);
        if (!option)
          return -1; /** Should define an appropriate error code */
        return setlocal_usertimeout(ptls, option);
      }
      break;
    case FAILOVER_ADDR4:
    case FAILOVER_ADDR6:
      break;
    case BPF_CC:
      {
        uint8_t *bpf_prog = malloc(inputlen);
        memcpy(bpf_prog, input, inputlen);
        option = tcpls_init_context(ptls, bpf_prog, inputlen, BPF_CC, 1, 0);
        if (!option)
          return -1;
        return setlocal_bpf_sched(ptls, option);
      }
      break;
    default:
      printf("Unsuported option?");
      return -1;
  }
 return 0;
}


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
  return ret;
}


/**
 * In case of failover, the peer only switch TCP's connection upon reception of this signal
 *
 * Pick the faster non-primary and open TCP connection to send the signal
 * */

int tcpls_sends_failover_signal(tcpls_t *tcpls, ptls_buffer_t *sendbuf) {

  uint8_t input[TCPLS_SIGNAL_SIZE];
  tcpls_enum_t f_signal = FAILOVER_SIGNAL;
  memcpy(input, &f_signal, sizeof(f_signal));
  memcpy(input+sizeof(f_signal), &tcpls->tls->traffic_protection.enc.seq,
      sizeof(tcpls->tls->traffic_protection.enc.seq));
  /** Synchronization problem in sequence number ! */
  return buffer_push_encrypted_records(sendbuf,
      PTLS_CONTENT_TYPE_TCPLS_OPTION, input,
      TCPLS_SIGNAL_SIZE, &tcpls->tls->traffic_protection.enc);
}


static int setlocal_usertimeout(ptls_t *ptls, tcpls_options_t *option) {
  return 0;
}


static int setlocal_bpf_sched(ptls_t *ptls, tcpls_options_t *option) {
  return 0;
}


/*=====================================utilities======================================*/

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
               tcpls->socket_ptr = &primary_v4->socket; break;
      case 0:
      case 1: primary_v6->is_primary = 1;
              tcpls->socket_ptr = &primary_v6->socket; break;
      default: primary_v6->is_primary = 1; 
               tcpls->socket_ptr = &primary_v6->socket; break;
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

void ptls_tcpls_options_free(ptls_t *ptls) {
  if (ptls->tcpls_options == NULL)
    return;
  for (int i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS; i++) {
    if (ptls->tcpls_options[i].data->base) {
      free(ptls->tcpls_options[i].data->base);
    }
    free(ptls->tcpls_options[i].data);
  }
  free(ptls->tcpls_options);
  ptls->tcpls_options = NULL;
}
