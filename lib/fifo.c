#include "fifo.h"
#include "picotls.h"
#include <stdlib.h>
#include <string.h>

tcpls_record_fifo_t *tcpls_recorc_queue_new(int max_record_num) {
  tcpls_record_fifo_t *fifo = malloc(sizeof(*fifo));
  if (fifo == NULL)
    return NULL;
  fifo->queue = malloc(max_record_num * sizeof(struct st_ptls_record_t));
  if (fifo->queue == NULL)
    goto Exit;
  fifo->front = fifo->queue;
  fifo->back = fifo->queue;
  return fifo;
Exit:
  free(fifo);
  return NULL;
}

queue_ret_t tcpls_record_queue_push(tcpls_record_fifo_t *fifo, struct st_ptls_record_t *rec) {
  if (fifo->size == fifo->max_record_num)
    return MEMORY_FULL;
  fifo->size++;
  memcpy(fifo->front, rec, sizeof(*rec));
  if (fifo->front - fifo->queue == sizeof(*rec)*(fifo->max_record_num-1)) {
    fifo->front = fifo->queue;
  }
  else {
    fifo->front++;
  }
  return OK;
}

queue_ret_t tcpls_record_queue_del(tcpls_record_fifo_t *fifo, int n) {
  while (n > 0) {
    if (fifo->size == 0)
      return EMPTY;
    fifo->size--;
    if (fifo->back - fifo->queue == sizeof(struct st_ptls_record_t)*(fifo->max_record_num-1)) {
      fifo->back = fifo->queue;
    }
    else {
      fifo->back++;
    }
    n--;
  }
  return OK;
}

void tcpls_record_fifo_free(tcpls_record_fifo_t *fifo) {
  if (!fifo)
    return;
  if (!fifo->queue){
    free(fifo);
    return;
  }
  free(fifo->queue);
  free(fifo);
}
