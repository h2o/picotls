#ifndef picofifo_h
#define picofifo_h
#include "picotls.h"

typedef struct list_t {
  int capacity;
  int size;
  int itemsize;
  uint8_t *items;
} list_t;

typedef enum queue_ret {
  OK,
  MEMORY_FULL,
  EMPTY
} queue_ret_t;

struct st_tcpls_record_fifo_t {
  int max_record_num;
  int size;
  struct st_ptls_record_t *queue;
  struct st_ptls_record_t *front;
  struct st_ptls_record_t *back;
};

tcpls_record_fifo_t *tcpls_record_queue_new(int max_record_num);

queue_ret_t tcpls_record_queue_push(tcpls_record_fifo_t *fifo, struct
    st_ptls_record_t *record);

queue_ret_t tcpls_record_queue_del(tcpls_record_fifo_t *fifo, int n);


void tcpls_record_fifo_free(tcpls_record_fifo_t *fifo);

list_t *new_list(int itemsize, int capacity);

int list_add(list_t *list, void *item);

int list_remove(list_t *list, void *item);


#endif
