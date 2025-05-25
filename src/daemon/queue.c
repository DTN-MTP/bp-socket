#include <stdlib.h>
#include <stdio.h>

#include "queue.h"

typedef struct node
{
	void *value;
	struct node *next;
} node_t;

queue_t *queue_create(void)
{
	queue_t *q;
	q = (queue_t *)malloc(sizeof(queue_t));
	if (q == NULL)
	{
		return NULL;
	}
	q->item_count = 0;
	q->head = NULL;
	q->tail = NULL;
	return q;
}

void queue_free(queue_t *q)
{
	node_t *cur;
	node_t *tmp;
	if (q == NULL)
	{
		return;
	}
	cur = q->head;
	while (cur != NULL)
	{
		tmp = cur;
		cur = cur->next;
		free(tmp);
	}
	free(q);
	return;
}

int queue_enc(queue_t *q, void *value)
{
	node_t *new_node;
	new_node = (node_t *)calloc(1, sizeof(node_t));
	if (new_node == NULL)
	{
		return 1;
	}
	new_node->value = value;

	if (q->head == NULL)
	{
		q->head = new_node;
		q->tail = new_node;
		q->item_count++;
		return 0;
	}

	q->tail->next = new_node;
	q->tail = new_node;
	q->item_count++;
	return 0;
}

void *queue_deq(queue_t *q)
{
	node_t *node;
	void *value;
	if (q->head == NULL)
	{
		return NULL;
	}
	node = q->head;
	value = node->value;
	q->head = node->next;

	if (q->head == NULL)
	{
		q->tail = NULL;
	}

	free(node);
	q->item_count--;
	return value;
}

void queue_print(queue_t *q)
{
	node_t *cur;
	printf("Queue contains:\n");
	cur = q->head;
	while (cur != NULL)
	{
		printf("\tNode with value %p\n", cur->value);
		cur = cur->next;
	}
	return;
}
