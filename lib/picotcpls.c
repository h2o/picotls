#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picotypes.h"
#include "picotls.h"
#include "picotcpls.h"

static int tcpls_init_context(ptls_t *ptls, const void *data,
    ptls_tcpls_options_t type, uint8_t setlocal, uint8_t settopeer);

/**
 * ptls_set_[TCPOPTION] needs to have been called first to initialize an option 
 */
/** Temporary skeletton */
int ptls_send_tcpoption(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_tcpls_options_t type)
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
    uint8_t input[option->data->len + 6];
    memcpy(input, &option->type, 2);
    memcpy(input+2, &option->data->len, 4);
    memcpy(input+6, option->data->base, option->data->len);
    return buffer_push_encrypted_records(sendbuf,
        PTLS_CONTENT_TYPE_TCPLS_OPTION, input, option->data->len+6, &tls->traffic_protection.enc);
  }
  else {
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
int ptls_set_user_timeout(ptls_t *ptls, uint16_t value, uint16_t sec_or_min,
    uint8_t setlocal, uint8_t settopeer) {
  uint16_t *val = malloc(sizeof(uint16_t));
  *val = value | sec_or_min << 15;
  int ret = tcpls_init_context(ptls, val, USER_TIMEOUT, setlocal, settopeer);
  return ret;
}

int ptls_set_faileover(ptls_t *ptls, char *address) {
  return 0;
}

static int tcpls_init_context(ptls_t *ptls, const void *data,
    ptls_tcpls_options_t type, uint8_t setlocal, uint8_t settopeer) {
  ptls->ctx->support_tcpls_options = 1;
  if (!ptls->tcpls_options) {
    ptls->tcpls_options = malloc(sizeof(*ptls->tcpls_options)*NBR_SUPPORTED_TCPLS_OPTIONS);
    for (int i = 0; i < NBR_SUPPORTED_TCPLS_OPTIONS; i++) {
      ptls->tcpls_options[i].data = malloc(sizeof(ptls_iovec_t));
      memset(ptls->tcpls_options[i].data, 0, sizeof(ptls_iovec_t));
      ptls->tcpls_options[i].type = 0;
      ptls->tcpls_options[i].setlocal = 0;
      ptls->tcpls_options[i].settopeer = 0;
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

  option->setlocal = setlocal;
  option->settopeer = settopeer;

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
        *nval = ntoh16(input);
        tcpls_init_context(ptls, nval, USER_TIMEOUT, 1, 0);
        /** TODO handle the extension! */
      }
      break;
    case PROTOCOLPLUGIN:
      break;
    default:
      printf("Unsuported option?");
      return -1;
  }
 return 0;
}


/** TODO call from handle_input */
/** Temporary skeletton */
int handle_tcpls_record(ptls_t *tls, struct st_ptls_record_t *rec)
{
  int ret = 0;
  ptls_tcpls_options_t type;
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
  
  type = ntoh16(rec->fragment);
  /** Check whether type is a variable len option */
  if (type == PROTOCOLPLUGIN) {
    size_t optsize = ntoh32(rec->fragment+2);
    if (optsize > PTLS_MAX_PLAINTEXT_RECORD_SIZE-6) {
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
      ptls_buffer_reserve(tls->tcpls_buf, rec->length-6);
      memcpy(tls->tcpls_buf->base+tls->tcpls_buf->off, rec->fragment+6, rec->length-6);
      tls->tcpls_buf->off += rec->length - 6;
      
      if (ret)
        goto Exit;
      if (tls->tcpls_buf->off == optsize) {
        /** We have all of it */
        ret = handle_tcpls_extension_option(tls, type, tls->tcpls_buf->base, optsize);
        ptls_buffer_dispose(tls->tcpls_buf);
      }
      else {
        ret = PTLS_ERROR_IN_PROGRESS;
        return ret;
      }
    }
    else {
      return handle_tcpls_extension_option(tls, type, rec->fragment+6, optsize);
    }
  }
  /** We assume that only Variable size options won't hold into 1 record */
  return handle_tcpls_extension_option(tls, type, rec->fragment+2, rec->length-2);

Exit:
  ptls_buffer_dispose(tls->tcpls_buf);
  return ret;
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
