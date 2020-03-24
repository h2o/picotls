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
int ptls_set_user_timeout(ptls_context_t *ctx, uint16_t value, uint16_t sec_or_min) {
  uint16_t val = value | sec_or_min << 15;
  int ret = tcpls_init_context(ctx, &val, USER_TIMEOUT);
  return ret;
}

int ptls_set_faileover(ptls_context_t *ctx, char *address) {
  return 0;
}

static int tcpls_init_context(ptls_context_t *ctx, const void *data, ptls_tcpls_options_t type) {
  if (!ctx->tcpls_options) {
    ctx->tcpls_options = malloc(sizeof(ptls_tcpls_t *)*NBR_SUPPORTED_TCPLS_OPTIONS);
    for (int i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS; i++) {
      ctx->tcpls_options[i] = malloc(sizeof(ptls_tcpls_t));
      memset(ctx->tcpls_options[i], 0, sizeof(ptls_tcpls_t));
    }
  }
  /** Picking up the right slot in the list, i.e;, the first unused should have
   * a len of 0
   * */
  ptls_tcpls_t **option; 
  for (option = ctx->tcpls_options; *option != NULL; option++) {
    /** already set or Not yet set */
    if ((*option)->type == type || !(*option)->len)
      break;
  }
  if (*option == NULL)
    return -1;

  switch (type) {
    case USER_TIMEOUT:
      if (!(*option)->len) {
        (*option)->data = malloc(sizeof(uint16_t));
        (*option)->len = sizeof(uint16_t);
        (*option)->type = USER_TIMEOUT;
      }
      memcpy((*option)->data, data, (*option)->len);
      return 0;
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
      tcpls_init_context(ctx, &val, USER_TIMEOUT);
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

void ptls_tcpls_options_free(ptls_context_t *ctx) {
  if (!ctx->tcpls_options)
    return;
  for (int i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS; i++) {
    /*if (ctx->tcpls_options[i]->data) {*/
      /*free(ctx->tcpls_options[i]->data);*/
    /*}*/
    free(ctx->tcpls_options[i]);
  }
  free(ctx->tcpls_options);
}
