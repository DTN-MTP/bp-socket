#include "sap_registry.h"
#include <pthread.h>
#include <stdlib.h>

static pthread_mutex_t sap_mutex = PTHREAD_MUTEX_INITIALIZER;
static sap_node_t *sap_head = NULL;

static sap_node_t *find_node(uint32_t node_id, uint32_t service_id, sap_node_t **prev) {
    sap_node_t *p = sap_head;
    sap_node_t *q = NULL;
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

bool sap_registry_contains(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&sap_mutex);
    bool exists = find_node(node_id, service_id, NULL) != NULL;
    pthread_mutex_unlock(&sap_mutex);
    return exists;
}

int sap_registry_add(uint32_t node_id, uint32_t service_id, BpSAP sap) {
    int ret = 0;
    sap_node_t *node;
    pthread_mutex_lock(&sap_mutex);
    if (find_node(node_id, service_id, NULL)) {
        pthread_mutex_unlock(&sap_mutex);
        return 0;
    }
    pthread_mutex_unlock(&sap_mutex);

    node = (sap_node_t *)calloc(1, sizeof(sap_node_t));
    if (!node) return -ENOMEM;
    node->key.node_id = node_id;
    node->key.service_id = service_id;
    node->sap = sap;
    node->has_active_receive = false;

    pthread_mutex_lock(&sap_mutex);
    node->next = sap_head;
    sap_head = node;
    pthread_mutex_unlock(&sap_mutex);
    return ret;
}

BpSAP sap_registry_get(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&sap_mutex);
    sap_node_t *node = find_node(node_id, service_id, NULL);
    BpSAP sap = node ? node->sap : NULL;
    pthread_mutex_unlock(&sap_mutex);
    return sap;
}

int sap_registry_remove(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&sap_mutex);
    sap_node_t *prev = NULL;
    sap_node_t *node = find_node(node_id, service_id, &prev);
    if (!node) {
        pthread_mutex_unlock(&sap_mutex);
        return 0;
    }
    if (prev)
        prev->next = node->next;
    else
        sap_head = node->next;
    pthread_mutex_unlock(&sap_mutex);
    free(node);
    return 0;
}

// Helper functions for receive thread tracking
void sap_registry_mark_receive_active(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&sap_mutex);
    sap_node_t *node = find_node(node_id, service_id, NULL);
    if (node) {
        node->has_active_receive = true;
    }
    pthread_mutex_unlock(&sap_mutex);
}

void sap_registry_mark_receive_inactive(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&sap_mutex);
    sap_node_t *node = find_node(node_id, service_id, NULL);
    if (node) {
        node->has_active_receive = false;
    }
    pthread_mutex_unlock(&sap_mutex);
}

bool sap_registry_has_active_receive(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&sap_mutex);
    sap_node_t *node = find_node(node_id, service_id, NULL);
    bool has_active = node ? node->has_active_receive : false;
    pthread_mutex_unlock(&sap_mutex);
    return has_active;
}
