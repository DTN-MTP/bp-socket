#include "endpoint_registry.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t endpoint_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct endpoint_ctx *endpoint_head = NULL;

int endpoint_registry_add(struct endpoint_ctx *ctx) {
    if (!ctx) {
        log_error("endpoint_registry_add: invalid context pointer");
        return -1;
    }

    if (pthread_mutex_lock(&endpoint_registry_mutex) != 0) {
        log_error("endpoint_registry_add: failed to lock registry mutex");
        return -1;
    }

    struct endpoint_ctx *current = endpoint_head;
    while (current != NULL) {
        if (current->node_id == ctx->node_id && current->service_id == ctx->service_id) {
            pthread_mutex_unlock(&endpoint_registry_mutex);
            log_error("endpoint_registry_add: endpoint ipn:%u.%u already exists", ctx->node_id,
                      ctx->service_id);
            return -1;
        }
        current = current->next;
    }

    ctx->next = endpoint_head;
    endpoint_head = ctx;
    pthread_mutex_unlock(&endpoint_registry_mutex);

    return 0;
}

struct endpoint_ctx *endpoint_registry_get(uint32_t node_id, uint32_t service_id) {
    struct endpoint_ctx *current;

    if (pthread_mutex_lock(&endpoint_registry_mutex) != 0) {
        log_error("endpoint_registry_get: failed to lock registry mutex");
        return NULL;
    }

    current = endpoint_head;
    while (current != NULL) {
        if (current->node_id == node_id && current->service_id == service_id) {
            pthread_mutex_unlock(&endpoint_registry_mutex);
            return current;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&endpoint_registry_mutex);
    return NULL;
}

int endpoint_registry_remove(uint32_t node_id, uint32_t service_id) {
    struct endpoint_ctx *current = endpoint_head;
    struct endpoint_ctx *prev = NULL;

    if (pthread_mutex_lock(&endpoint_registry_mutex) != 0) {
        log_error("endpoint_registry_remove: failed to lock registry mutex");
        return -1;
    }

    while (current != NULL) {
        if (current->node_id == node_id && current->service_id == service_id) {
            if (prev == NULL) {
                endpoint_head = current->next;
            } else {
                prev->next = current->next;
            }

            free(current);
            pthread_mutex_unlock(&endpoint_registry_mutex);

            return 0;
        }
        prev = current;
        current = current->next;
    }

    pthread_mutex_unlock(&endpoint_registry_mutex);
    log_error("endpoint_registry_remove: endpoint ipn:%u.%u not found", node_id, service_id);
    return -1;
}

bool endpoint_registry_exists(uint32_t node_id, uint32_t service_id) {
    struct endpoint_ctx *current;

    if (pthread_mutex_lock(&endpoint_registry_mutex) != 0) {
        log_error("endpoint_registry_exists: failed to lock registry mutex");
        return false;
    }

    current = endpoint_head;
    while (current != NULL) {
        if (current->node_id == node_id && current->service_id == service_id) {
            pthread_mutex_unlock(&endpoint_registry_mutex);
            return true;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&endpoint_registry_mutex);
    return false;
}
