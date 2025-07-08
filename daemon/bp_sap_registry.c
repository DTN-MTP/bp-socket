#include "bp_sap_registry.h"
#include "log.h"
#include <bp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct SapNode {
    uint32_t node_id;
    uint32_t service_id;
    BpSAP sap;
    struct SapNode *next;
} SapNode;

static struct SapNode *head = NULL;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void bp_sap_registry_add(uint32_t node_id, uint32_t service_id, BpSAP sap) {
    SapNode *node = malloc(sizeof(SapNode));
    node->node_id = node_id;
    node->service_id = service_id;
    node->sap = sap;

    pthread_mutex_lock(&mutex);
    node->next = head;
    head = node;
    pthread_mutex_unlock(&mutex);
}

BpSAP bp_sap_registry_find(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&mutex);

    SapNode *current = head;
    while (current) {
        if (current->node_id == node_id && current->service_id == service_id) {
            pthread_mutex_unlock(&mutex);
            return current->sap;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&mutex);
    return NULL;
}

void bp_sap_registry_remove(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&mutex);

    SapNode **p = &head;
    while (*p) {
        if ((*p)->node_id == node_id && (*p)->service_id == service_id) {
            SapNode *to_delete = *p;
            *p = (*p)->next;
            free(to_delete);
            break;
        }
        p = &(*p)->next;
    }

    pthread_mutex_unlock(&mutex);
}

void bp_sap_registry_clear(void) {
    pthread_mutex_lock(&mutex);

    SapNode *current = head;
    while (current) {
        SapNode *to_delete = current;
        current = current->next;
        free(to_delete);
    }
    head = NULL;

    pthread_mutex_unlock(&mutex);
}
