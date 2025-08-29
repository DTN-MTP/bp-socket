#include "adu_ref.h"
#include "log.h"
#include "sdr.h"
#include <bp.h>
#include <pthread.h>

static struct adu_reference *adu_refs = NULL;
static pthread_mutex_t adu_refs_mutex = PTHREAD_MUTEX_INITIALIZER;

int add_adu(Object adu, u_int32_t dest_node_id, u_int32_t dest_service_id,
            u_int32_t src_node_id, u_int32_t src_service_id) {
    struct adu_reference *ref;

    if (pthread_mutex_lock(&adu_refs_mutex) != 0) {
        log_error("add_adu: Failed to lock SDR mutex.");
        return -1;
    }

    ref = malloc(sizeof(struct adu_reference));
    if (!ref) {
        log_error("add_adu: Failed to allocate memory for bundle reference.");
        pthread_mutex_unlock(&adu_refs_mutex);
        return -ENOMEM;
    }

    ref->adu = adu;
    ref->dest_node_id = dest_node_id;
    ref->dest_service_id = dest_service_id;
    ref->src_node_id = src_node_id;
    ref->src_service_id = src_service_id;
    ref->next = adu_refs;
    adu_refs = ref;

    pthread_mutex_unlock(&adu_refs_mutex);
    return 0;
}

struct adu_reference *find_adu_ref(u_int32_t dest_node_id, u_int32_t dest_service_id) {
    struct adu_reference *ref;

    if (pthread_mutex_lock(&adu_refs_mutex) != 0) {
        log_error("find_adu_ref: Failed to lock adu_refs mutex.");
        return NULL;
    }

    for (ref = adu_refs; ref != NULL; ref = ref->next) {
        if (ref->dest_node_id == dest_node_id && ref->dest_service_id == dest_service_id) {
            pthread_mutex_unlock(&adu_refs_mutex);
            return ref;
        }
    }
    pthread_mutex_unlock(&adu_refs_mutex);
    return NULL;
}

Object remove_adu_ref(u_int32_t dest_node_id, u_int32_t dest_service_id) {
    struct adu_reference *prev = NULL;
    struct adu_reference *current = adu_refs;
    Object adu = 0;

    if (pthread_mutex_lock(&adu_refs_mutex) != 0) {
        log_error("remove_adu_ref: Failed to lock adu_refs mutex.");
        return 0;
    }

    while (current) {
        if (current->dest_node_id == dest_node_id && current->dest_service_id == dest_service_id) {
            adu = current->adu;
            if (prev) {
                prev->next = current->next;
            } else {
                adu_refs = current->next;
            }

            free(current);
            pthread_mutex_unlock(&adu_refs_mutex);
            return adu;
        }
        prev = current;
        current = current->next;
    }

    pthread_mutex_unlock(&adu_refs_mutex);
    log_warn("remove_adu_ref: no bundle found (ipn:%u.%u)", dest_node_id, dest_service_id);
    return adu;
}