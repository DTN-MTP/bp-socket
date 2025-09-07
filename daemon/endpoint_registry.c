#include "endpoint_registry.h"
#include "log.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    pthread_mutex_init(&ctx->send_queue_mutex, NULL);
    pthread_cond_init(&ctx->send_queue_cond, NULL);
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

            pthread_mutex_destroy(&current->send_queue_mutex);
            pthread_cond_destroy(&current->send_queue_cond);
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

int endpoint_registry_enqueue_send(uint32_t node_id, uint32_t service_id, const char *dest_eid,
                                   const void *payload, size_t payload_size, uint32_t flags) {
    struct endpoint_ctx *ctx = endpoint_registry_get(node_id, service_id);
    if (!ctx) {
        log_error("endpoint_registry_enqueue_send: no endpoint for ipn:%u.%u", node_id, service_id);
        return -ENODEV;
    }

    struct send_queue_item *item = malloc(sizeof(struct send_queue_item));
    if (!item) {
        log_error("endpoint_registry_enqueue_send: failed to allocate queue item");
        return -ENOMEM;
    }

    item->dest_eid = strdup(dest_eid);
    if (!item->dest_eid) {
        log_error("endpoint_registry_enqueue_send: failed to duplicate dest_eid");
        free(item);
        return -ENOMEM;
    }

    item->payload = malloc(payload_size);
    if (!item->payload) {
        log_error("endpoint_registry_enqueue_send: failed to allocate payload");
        free(item->dest_eid);
        free(item);
        return -ENOMEM;
    }

    memcpy(item->payload, payload, payload_size);
    item->payload_size = payload_size;
    item->flags = flags;
    item->next = NULL;

    pthread_mutex_lock(&ctx->send_queue_mutex);

    if (ctx->send_queue_size >= 5000) {
        pthread_mutex_unlock(&ctx->send_queue_mutex);
        log_warn("endpoint_registry_enqueue_send: queue full for ipn:%u.%u (size: %d)", node_id,
                 service_id, ctx->send_queue_size);
        free(item->dest_eid);
        free(item->payload);
        free(item);
        return -EAGAIN;
    }

    if (ctx->send_queue_tail) {
        ctx->send_queue_tail->next = item;
        ctx->send_queue_tail = item;
    } else {
        ctx->send_queue_head = item;
        ctx->send_queue_tail = item;
    }
    ctx->send_queue_size++;

    pthread_cond_signal(&ctx->send_queue_cond);
    pthread_mutex_unlock(&ctx->send_queue_mutex);

    return 0;
}