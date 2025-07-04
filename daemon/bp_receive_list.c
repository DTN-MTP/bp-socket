#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <bp.h>
#include "bp_receive_list.h"
#include "log.h"

typedef struct bp_receive_list {
    uint32_t node_id;
    uint32_t service_id;
    BpSAP *sap;
    struct bp_receive_list *next;
} BpReceiveList;

static BpReceiveList *receive_list = NULL;
static pthread_mutex_t receive_list_lock = PTHREAD_MUTEX_INITIALIZER;

void bp_receive_list_add(uint32_t node_id, uint32_t service_id, BpSAP *sap) {
    BpReceiveList *node = calloc(1, sizeof(BpReceiveList));
    node->node_id = node_id;
    node->service_id = service_id;
    node->sap = sap;

    pthread_mutex_lock(&receive_list_lock);
    node->next = receive_list;
    receive_list = node;
    pthread_mutex_unlock(&receive_list_lock);
}

BpSAP *bp_receive_list_find(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&receive_list_lock);

    BpReceiveList *n = receive_list;
    while (n) {
        if (n->node_id == node_id && n->service_id == service_id) {
            pthread_mutex_unlock(&receive_list_lock);
            return n->sap;
        }
        n = n->next;
    }

    pthread_mutex_unlock(&receive_list_lock);
    return NULL;
}

void bp_receive_list_remove(uint32_t node_id, uint32_t service_id) {
    pthread_mutex_lock(&receive_list_lock);

    BpReceiveList **p = &receive_list;
    while (*p) {
        if ((*p)->node_id == node_id && (*p)->service_id == service_id) {
            BpReceiveList *to_delete = *p;
            *p = (*p)->next;
            free(to_delete);
            break;
        }
        p = &(*p)->next;
    }

    pthread_mutex_unlock(&receive_list_lock);
}

void bp_receive_list_clear(void) {
    pthread_mutex_lock(&receive_list_lock);

    BpReceiveList *n = receive_list;
    while (n) {
        BpReceiveList *to_delete = n;
        n = n->next;
        free(to_delete);
    }
    receive_list = NULL;

    pthread_mutex_unlock(&receive_list_lock);
}
