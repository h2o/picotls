#include "containers.h"
#include "picotls.h"
#include <stdlib.h>
#include <string.h>

/* ===========================FIFO======================================= */

/**
 * FIFO queue of max_record_num (cannot be extended). If the buffer is full,
 * no more records can be send with TCPLS, and we need to wait for
 * acknowledgments to arrive to free space
 */

tcpls_record_fifo_t *tcpls_record_queue_new(int max_record_num) {
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

/**
 * Push a record to the front of the queue
 *
 * return MEMORY_FULL, OK
 */
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

/* =================================================LIST===========================*/


/**
 * Create a new list_t containting room capacity items of size itemsize
 *
 * return NULL if an error occured
 */

list_t *new_list(int itemsize, int capacity) {
  list_t *list = malloc(sizeof(*list));
  if (!list)
    return NULL;
  list->items = malloc(sizeof(itemsize)*capacity);
  if (!list->items) {
    free(list);
    return NULL;
  }
  list->capacity = capacity;
  list->size = 0;
  list->itemsize = itemsize;
  return list;
}

/**
 * Add item to the end of the list. If the list's size has reached the capacity,
 * double its size and then add the item
 * return 0 if the item has been added, -1 if an error occured
 */

int list_add(list_t *list, void *item) {
  if (list->size == list->capacity) {
    list->items = reallocarray(list->items, list->capacity*2, list->itemsize);
    if (!list->items)
      return -1;
  }
  memcpy(&list->items[list->size*list->itemsize], item, list->itemsize);
  list->size++;
  return 0;
}


void *list_get(list_t *list, int itemid) {
  if (itemid > list->size-1)
    return NULL;
  return &list->items[list->itemsize*itemid];
}

/**
 * remove item from the list if this item is inside, then move the items to keep
 * the continuous
 * return -1 if an error occured or if the item isn't part of the list
 */

int list_remove(list_t *list, void *item) {
  if (list->size == 0)
    return -1;
  for (int i = 0; i < list->size; i++) {
    if (memcpy(&list->items[i*list->itemsize], item, list->itemsize) == 0) {
      if (i == list->size-1) {
        list->size--;
        return 0;
      }
      else {
        uint8_t *items_tmp = malloc((list->size-i-1)*list->itemsize);
        if (!items_tmp)
          return -1;
        /** Note: could do a memmove instead */
        memcpy(items_tmp, &list->items[(i+1)*list->itemsize], (list->size-i-1)*list->itemsize);
        memcpy(&list->items[i*list->itemsize], items_tmp, (list->size-i-1)*list->itemsize);
        free(items_tmp);
        list->size--;
        return 0;
      }
    }
  }
  return -1;
}
