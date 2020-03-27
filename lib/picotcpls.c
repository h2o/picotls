#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picotypes.h"
#include "picotls.h"
#include "picotcpls.h"

static int tcpls_init_context(ptls_t *ptls, const void *data, ptls_tcpls_options_t type);

/** Temporary skeletton */
int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input,
    size_t inlen, ptls_tcpls_options_t type)
{
  if(tls->traffic_protection.enc.aead == NULL)
    return -1;
  
  if (tls->traffic_protection.enc.seq >= 16777216)
    tls->needs_key_update = 1;

  if (tls->needs_key_update) {
        int ret;
        if ((ret = update_send_key(tls, sendbuf, tls->key_update_send_request)) != 0)
            return ret;
        tls->needs_key_update = 0;
        tls->key_update_send_request = 0;
  }
  /** Get the option */
  ptls_tcpls_t *option;
  int i;
  int found = 0;
  for (i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS && !found; i++) {
    if ((tls->tcpls_options[i].type == type && tls->tcpls_options[i].data->base)
        || !tls->tcpls_options[i].data->base) {
      option = &tls->tcpls_options[i];
      found = 1;
    }
  }
  if (!found)
    return -1;
  
  {
    uint8_t input[option->data->len + 2];
    memcpy(input, &option->type, 2);
    memcpy(input+2, option->data->base, option->data->len);
    
    return buffer_push_encrypted_records(sendbuf,
        PTLS_CONTENT_TYPE_TCPLS_OPTION, input, option->data->len+2, &tls->traffic_protection.enc);

  }
}

/**
 * Set a timeout option (i.e., RFC5482) to transport within the TLS connection
 */
int ptls_set_user_timeout(ptls_t *ptls, uint16_t value, uint16_t sec_or_min) {
  uint16_t *val = malloc(sizeof(uint16_t));
  *val = value | sec_or_min << 15;
  int ret = tcpls_init_context(ptls, val, USER_TIMEOUT);
  return ret;
}

int ptls_set_faileover(ptls_t *ptls, char *address) {
  return 0;
}

static int tcpls_init_context(ptls_t *ptls, const void *data, ptls_tcpls_options_t type) {
  ptls->ctx->support_tcpls_options = 1;
  if (!ptls->tcpls_options) {
    ptls->tcpls_options = malloc(sizeof(*ptls->tcpls_options)*NBR_SUPPORTED_TCPLS_OPTIONS);
    for (int i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS; i++) {
      ptls->tcpls_options[i].data = malloc(sizeof(ptls_iovec_t));
      memset(ptls->tcpls_options[i].data, 0, sizeof(ptls_iovec_t));
      ptls->tcpls_options[i].type = 0;
    }
  }
  /** Picking up the right slot in the list, i.e;, the first unused should have
   * a len of 0
   * */
  ptls_tcpls_t *option = NULL;
  for (int i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS; i++) {
    /** already set or Not yet set */
    if ((ptls->tcpls_options[i].type == type && ptls->tcpls_options[i].data->base)
        || !ptls->tcpls_options[i].data->base) {
      option = &ptls->tcpls_options[i];
      break;
    }
  }
  if (option == NULL)
    return -1;

  switch (type) {
    case USER_TIMEOUT:
      if (option->data->len) {
        /** We already allocated one, free it before getting a new one */
        free(option->data->base);
      }
      *option->data = ptls_iovec_init(data, sizeof(uint16_t));
      option->type = USER_TIMEOUT;
  
      return 0;
    case FAILOVER: break;
    default:
        break;
  }
  return -1;
}

/** Temporaty skeletton */
int handle_tcpls_extension_option(ptls_t *ptls, ptls_tcpls_options_t type,
    const uint8_t *input, size_t inputlen) {
  if (!ptls->ctx->tcpls_options_confirmed)
    return -1;

  switch (type) {
    case USER_TIMEOUT:
      {
        uint16_t *nval = malloc(inputlen);
        *nval = (uint16_t) *input;
        tcpls_init_context(ptls, nval, USER_TIMEOUT);
        /** TODO handle the extension! */
      }
      break;
    default:
      printf("Unsuported option?");
      return -1;
  }
 return 0;
}


/** TODO call from handle_input */
/** Temporary skeletton */
struct st_ptls_record_t;
int handle_tcpls_record(ptls_t *tls, struct st_ptls_record_t *rec)
{
  /** Assumes a TCPLS option holds within 1 record ; else we need to buffer the
   * option to deliver it to handle_tcpls_extension_option 
   * */
  return handle_tcpls_extension_option(tls, rec->type, rec->fragment, rec->length);
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
