#ifndef QUEUE_H
#define QUEUE_H

typedef struct queue
{
	struct node *head;
	struct node *tail;
	int item_count;
} queue_t;

queue_t *queue_create(void);
void queue_free(queue_t *q);
int queue_enc(queue_t *q, void *value);
void *queue_deq(queue_t *q);
void queue_print(queue_t *q);

#endif
