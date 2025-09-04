#ifndef ENDPOINT_REGISTRY_H
#define ENDPOINT_REGISTRY_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

struct endpoint_ctx {
    uint32_t node_id;
    uint32_t service_id;
    void *sap;

    _Atomic int running;
    pthread_t recv_thread;
    pthread_t send_thread;

    struct send_queue_item *send_queue_head;
    struct send_queue_item *send_queue_tail;
    pthread_mutex_t send_queue_mutex;
    pthread_cond_t send_queue_cond;
    int send_queue_size;

    struct endpoint_ctx *next;
};

struct send_queue_item {
    char *dest_eid;
    void *payload;
    size_t payload_size;
    uint32_t flags;
    struct send_queue_item *next;
};

int endpoint_registry_add(struct endpoint_ctx *ctx);
struct endpoint_ctx *endpoint_registry_get(uint32_t node_id, uint32_t service_id);
int endpoint_registry_remove(uint32_t node_id, uint32_t service_id);
bool endpoint_registry_exists(uint32_t node_id, uint32_t service_id);
int endpoint_registry_enqueue_send(uint32_t node_id, uint32_t service_id, const char *dest_eid,
                                   const void *payload, size_t payload_size, uint32_t flags);

#endif
