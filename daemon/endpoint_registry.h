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
    pthread_t thread;

    struct endpoint_ctx *next;
};

int endpoint_registry_add(struct endpoint_ctx *ctx);
struct endpoint_ctx *endpoint_registry_get(uint32_t node_id, uint32_t service_id);
int endpoint_registry_remove(uint32_t node_id, uint32_t service_id);
bool endpoint_registry_exists(uint32_t node_id, uint32_t service_id);

#endif
