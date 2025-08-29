#include "adu_registry.h"
#include "log.h"
#include <pthread.h>
#include <stdlib.h>

static pthread_mutex_t adu_mutex = PTHREAD_MUTEX_INITIALIZER;
static adu_node_t *adu_head = NULL;

static adu_node_t *find_node(uint32_t node_id, uint32_t service_id, adu_node_t **prev) {
    adu_node_t *p = adu_head;
    adu_node_t *q = NULL;
    while (p) {
        if (p->key.node_id == node_id && p->key.service_id == service_id) {
            if (prev) *prev = q;
            return p;
        }
        q = p;
        p = p->next;
    }
    if (prev) *prev = NULL;
    return NULL;
}

bool adu_registry_contains(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&adu_mutex);
    bool exists = find_node(node_id, service_id, NULL) != NULL;
    pthread_mutex_unlock(&adu_mutex);
    return exists;
}

int adu_registry_add(Object adu, uint32_t dest_node_id, uint32_t dest_service_id,
                     uint32_t src_node_id, uint32_t src_service_id) {
    int ret = 0;
    adu_node_t *node;

    pthread_mutex_lock(&adu_mutex);
    if (find_node(dest_node_id, dest_service_id, NULL)) {
        pthread_mutex_unlock(&adu_mutex);
        return 0; // Already exists
    }
    pthread_mutex_unlock(&adu_mutex);

    node = (adu_node_t *)calloc(1, sizeof(adu_node_t));
    if (!node) {
        log_error("adu_registry_add: Failed to allocate memory for bundle reference");
        return -ENOMEM;
    }

    node->key.node_id = dest_node_id;
    node->key.service_id = dest_service_id;
    node->src_node_id = src_node_id;
    node->src_service_id = src_service_id;
    node->adu = adu;

    pthread_mutex_lock(&adu_mutex);
    node->next = adu_head;
    adu_head = node;
    pthread_mutex_unlock(&adu_mutex);

    return ret;
}

adu_node_t *adu_registry_get(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&adu_mutex);
    adu_node_t *node = find_node(node_id, service_id, NULL);
    pthread_mutex_unlock(&adu_mutex);
    return node;
}

Object adu_registry_remove(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&adu_mutex);
    adu_node_t *prev = NULL;
    adu_node_t *node = find_node(node_id, service_id, &prev);
    Object adu = 0;

    if (!node) {
        pthread_mutex_unlock(&adu_mutex);
        log_warn("adu_registry_remove: no bundle found (ipn:%u.%u)", node_id, service_id);
        return 0;
    }

    adu = node->adu;
    if (prev)
        prev->next = node->next;
    else
        adu_head = node->next;

    pthread_mutex_unlock(&adu_mutex);
    free(node);
    return adu;
}
