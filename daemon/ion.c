#include "ion.h"
#include "log.h"
#include "sdr.h"
#include <bp.h>
#include <pthread.h>

static struct adu_reference *adu_refs = NULL;
static pthread_mutex_t adu_refs_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t sdrmutex = PTHREAD_MUTEX_INITIALIZER;

const char *bp_result_text(BpIndResult result) {
    switch (result) {
    case BpPayloadPresent:
        return "BpPayloadPresent";
    case BpReceptionTimedOut:
        return "BpReceptionTimedOut";
    case BpReceptionInterrupted:
        return "BpReceptionInterrupted";
    case BpEndpointStopped:
        return "BpEndpointStopped";
    default:
        return "Unknown";
    }
}

int add_adu(Sdr sdr, Object adu, u_int32_t dest_node_id, u_int32_t dest_service_id,
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

Object find_adu(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id) {
    struct adu_reference *ref;

    for (ref = adu_refs; ref != NULL; ref = ref->next) {
        if (ref->dest_node_id == dest_node_id && ref->dest_service_id == dest_service_id) {
            return ref->adu;
        }
    }
    return 0;
}

int destroy_adu(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id) {
    struct adu_reference *prev = NULL;
    struct adu_reference *current = adu_refs;

    if (pthread_mutex_lock(&adu_refs_mutex) != 0) {
        log_error("destroy_adu: Failed to lock adu_refs mutex.");
        return -EAGAIN;
    }

    while (current) {
        if (current->dest_node_id == dest_node_id && current->dest_service_id == dest_service_id) {
            if (prev) {
                prev->next = current->next;
            } else {
                adu_refs = current->next;
            }

            if (pthread_mutex_lock(&sdrmutex) != 0) {
                log_error("destroy_adu: Failed to lock SDR mutex.");
                free(current);
                pthread_mutex_unlock(&adu_refs_mutex);
                return -EAGAIN;
            }

            zco_destroy(sdr, current->adu);
            free(current);
            pthread_mutex_unlock(&sdrmutex);
            pthread_mutex_unlock(&adu_refs_mutex);
            return 0;
        }
        prev = current;
        current = current->next;
    }

    pthread_mutex_unlock(&adu_refs_mutex);
    log_warn("destroy_adu: no bundle found (ipn:%u.%u)", dest_node_id, dest_service_id);
    return -ENOENT;
}

int bp_send_to_eid(Sdr sdr, void *payload, size_t payload_size, char *dest_eid) {
    Object sdr_buffer = 0;
    Object adu;
    int ret = 0;

    if (sdr_begin_xn(sdr) == 0) {
        log_error("bp_send_to_eid: sdr_begin_xn failed.");
        return -EIO;
    }

    sdr_buffer = sdr_malloc(sdr, payload_size);
    if (sdr_buffer == 0) {
        log_error("sdr_malloc failed.");
        ret = -ENOMEM;
        goto out;
    }

    sdr_write(sdr, sdr_buffer, payload, payload_size);

    adu = zco_create(sdr, ZcoSdrSource, sdr_buffer, 0, payload_size, ZcoOutbound);
    if (adu <= 0) {
        log_error("zco_create failed.");
        sdr_free(sdr, sdr_buffer);
        ret = -ENOMEM;
        goto out;
    }

    if (bp_send(NULL, dest_eid, NULL, 86400, BP_STD_PRIORITY, 0, 0, 0, NULL, adu, NULL) <= 0) {
        log_error("bp_send failed.");
        sdr_free(sdr, sdr_buffer);
        ret = -EIO;
        goto out;
    }

out:
    sdr_end_xn(sdr);
    return ret;
}

void *bp_recv_once(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id, size_t *payload_size,
                   u_int32_t *src_node_id, u_int32_t *src_service_id) {
    BpSAP sap;
    BpDelivery dlv;
    ZcoReader reader;
    Object adu;
    u_int32_t own_node_id;
    void *payload = NULL;
    int eid_size;
    char eid[64];

    own_node_id = getOwnNodeNbr();
    if (dest_node_id != own_node_id) {
        log_error("bp_recv_once: node ID mismatch. Expected %u, got %u", own_node_id, dest_node_id);
        return NULL;
    }

    adu = find_adu(sdr, dest_node_id, dest_service_id);
    if (adu != 0) {
        *payload_size = zco_source_data_length(sdr, adu);
        payload = malloc(*payload_size);
        if (!payload) {
            log_error("bp_recv_once: Failed to allocate memory for payload.");
            return NULL;
        }
        zco_start_receiving(adu, &reader);
        if (zco_receive_source(sdr, &reader, *payload_size, payload) < 0) {
            log_error("bp_recv_once: zco_receive_source failed.");
            free(payload);
            return NULL;
        }
        return payload;
    }

    eid_size = snprintf(eid, sizeof(eid), "ipn:%u.%u", dest_node_id, dest_service_id);
    if (eid_size < 0 || eid_size >= (int)sizeof(eid)) {
        log_error("bp_recv_once: failed to construct EID string.");
        return NULL;
    }

    if (bp_open(eid, &sap) < 0) {
        log_error("bp_recv_once: failed to open BpSAP (node_id=%u service_id=%u)", dest_node_id,
                  dest_service_id);
        return NULL;
    }

    if (bp_receive(sap, &dlv, BP_BLOCKING) < 0) {
        log_error("bp_recv_once: bundle reception failed.");
        goto close_sap;
    }

    if (dlv.result != BpPayloadPresent || dlv.adu == 0) {
        log_error("bp_recv_once: %s", bp_result_text(dlv.result));
        goto release_dlv;
    }

    if (sscanf(dlv.bundleSourceEid, "ipn:%u.%u", src_node_id, src_service_id) != 2) {
        log_error("bp_recv_once: failed to parse bundleSourceEid: %s", dlv.bundleSourceEid);
        goto release_dlv;
    }

    if (add_adu(sdr, dlv.adu, dest_node_id, dest_service_id, *src_node_id, *src_service_id) < 0) {
        log_error("bp_recv_once: failed to add bundle reference.");
        goto release_dlv;
    }

    if (pthread_mutex_lock(&sdrmutex) != 0) {
        log_error("bp_recv_once: Failed to lock SDR mutex.");
        goto release_dlv;
    }

    if (sdr_begin_xn(sdr) == 0) {
        log_error("bp_recv_once: sdr_begin_xn failed.");
        pthread_mutex_unlock(&sdrmutex);
        goto release_dlv;
    }

    *payload_size = zco_source_data_length(sdr, dlv.adu);
    payload = malloc(*payload_size);
    if (!payload) {
        log_error("bp_recv_once: Failed to allocate memory for payload.");
        sdr_end_xn(sdr);
        pthread_mutex_unlock(&sdrmutex);
        goto release_dlv;
    }

    zco_start_receiving(dlv.adu, &reader);
    if (zco_receive_source(sdr, &reader, *payload_size, payload) < 0) {
        log_error("bp_recv_once: zco_receive_source failed.");
        free(payload);
        payload = NULL;
        sdr_end_xn(sdr);
        pthread_mutex_unlock(&sdrmutex);
        goto release_dlv;
    }

    sdr_end_xn(sdr);
    pthread_mutex_unlock(&sdrmutex);
    bp_release_delivery(&dlv, 0);
    bp_close(sap);

    return payload;

release_dlv:
    bp_release_delivery(&dlv, 0);
close_sap:
    bp_close(sap);
    return NULL;
}
