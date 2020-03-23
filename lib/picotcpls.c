#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picotls.h"
#include "picotcpls.h"

static int tcpls_init_context(ptls_context_t *ctx, const void *data, ptls_tcpls_options_t type);

/** Temporary skeletton */
int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input,
    size_t inlen, int tcp_option_type)
{
  return 0;
}

/**
 * Set a timeout option 
 */
int ptls_set_user_timeout(ptls_context_t *ctx, int value, uint16_t sec_or_min) {
  ptls_tcpls_t user_timeout;
  user_timeout.data = malloc(sizeof(uint16_t));
  *user_timeout.data = ((uint16_t) value | (sec_or_min << 15));
  int ret = tcpls_init_context(ctx, user_timeout.data, USER_TIMEOUT);
  free(user_timeout.data);
  return ret;
}

int ptls_set_faileover(ptls_context_t *ctx, char *address) {
  return 0;
}

static int tcpls_init_context(ptls_context_t *ctx, const void *data, ptls_tcpls_options_t type) {
  if (!ctx->tcpls_options) {
    ctx->tcpls_options = malloc(sizeof(ptls_tcpls_t)*NBR_SUPPORTED_TCPLS_OPTIONS);
  }
  /** Picking up the right slot in the list, i.e;, the first unused should have
   * a len of 0
   * */
  ptls_tcpls_t **option; 
  for (option = ctx->tcpls_options; *option != NULL; ++option) {
    /** Not yet set */
    if (!(*option)->len)
      break;
  }
  if (*option == NULL)
    return -1;

  switch (type) {
    case USER_TIMEOUT:
      (*option)->len = sizeof(uint16_t);
      (*option)->data = malloc(sizeof(uint16_t));
      memcpy((*option)->data, data, (*option)->len);
      return 0;
      break;
    case FAILOVER: break;
    default:
        break;
  }
  return -1;
}

/** Temporaty skeletton */
int handle_tcpls_extension_option(ptls_context_t *ctx, ptls_tcpls_options_t type, uint16_t val) {
  if (!ctx->tcpls_options_confirmed)
    return -1;

  switch (type) {
    case USER_TIMEOUT:
      printf("Waouh, we just received a timeout value of %u", val);
      break;
    default:
      printf("Unsuported option?");
      return -1;
  }
 return 0;
}


/** TODO call from handle_input */
/** Temporary skeletton */

int handle_tcpls_record(void)
{
  return 0;
}
