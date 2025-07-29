#include "ion.h"
#include "adu_ref.h"
#include "log.h"
#include "sdr.h"
#include <bp.h>
#include <pthread.h>

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

int destroy_bundle(Sdr sdr, Object adu) {
    if (pthread_mutex_lock(&sdrmutex) != 0) {
        log_error("destroy_bundle: Failed to lock SDR mutex.");
        return -EAGAIN;
    }

    if (sdr_begin_xn(sdr) == 0) {
        log_error("destroy_bundle: sdr_begin_xn failed.");
        pthread_mutex_unlock(&sdrmutex);
        return -EIO;
    }

    zco_destroy(sdr, adu);

    sdr_end_xn(sdr);
    pthread_mutex_unlock(&sdrmutex);
    return 0;
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

struct reply_bundle bp_recv_once(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id) {
    BpSAP sap;
    BpDelivery dlv;
    ZcoReader reader;
    struct adu_reference *adu_ref;
    u_int32_t own_node_id;
    void *payload = NULL;
    size_t payload_size;
    int eid_size;
    char eid[64];
    struct reply_bundle reply = {0};
    u_int32_t src_node_id, src_service_id;

    reply.is_present = false;
    reply.payload = NULL;

    own_node_id = getOwnNodeNbr();
    if (dest_node_id != own_node_id) {
        log_error("bp_recv_once: node ID mismatch. Expected %u, got %u", own_node_id, dest_node_id);
        goto out;
    }

    adu_ref = find_adu_ref(sdr, dest_node_id, dest_service_id);
    if (adu_ref != NULL) {
        payload_size = zco_source_data_length(sdr, adu_ref->adu);
        payload = malloc(payload_size);
        if (!payload) {
            log_error("bp_recv_once: Failed to allocate memory for payload.");
            goto out;
        }
        zco_start_receiving(adu_ref->adu, &reader);
        if (zco_receive_source(sdr, &reader, payload_size, payload) < 0) {
            log_error("bp_recv_once: zco_receive_source failed.");
            goto out;
        }

        src_node_id = adu_ref->src_node_id;
        src_service_id = adu_ref->src_service_id;
    } else {
        eid_size = snprintf(eid, sizeof(eid), "ipn:%u.%u", dest_node_id, dest_service_id);
        if (eid_size < 0 || eid_size >= (int)sizeof(eid)) {
            log_error("bp_recv_once: failed to construct EID string.");
            goto out;
        }

        if (bp_open(eid, &sap) < 0) {
            log_error("bp_recv_once: failed to open BpSAP (node_id=%u service_id=%u)", dest_node_id,
                      dest_service_id);
            goto out;
        }

        if (bp_receive(sap, &dlv, BP_BLOCKING) < 0) {
            log_error("bp_recv_once: bundle reception failed.");
            bp_close(sap);
            goto out;
        }

        if (dlv.result != BpPayloadPresent || dlv.adu == 0) {
            log_error("bp_recv_once: %s", bp_result_text(dlv.result));
            bp_release_delivery(&dlv, 0);
            bp_close(sap);
            goto out;
        }

        if (sscanf(dlv.bundleSourceEid, "ipn:%u.%u", &src_node_id, &src_service_id) != 2) {
            log_error("bp_recv_once: failed to parse bundleSourceEid: %s", dlv.bundleSourceEid);
            bp_release_delivery(&dlv, 0);
            bp_close(sap);
            goto out;
        }

        if (add_adu(sdr, dlv.adu, dest_node_id, dest_service_id, src_node_id, src_service_id) < 0) {
            log_error("bp_recv_once: failed to add bundle reference.");
            bp_release_delivery(&dlv, 0);
            bp_close(sap);
            goto out;
        }

        if (pthread_mutex_lock(&sdrmutex) != 0) {
            log_error("bp_recv_once: Failed to lock SDR mutex.");
            bp_release_delivery(&dlv, 0);
            bp_close(sap);
            goto out;
        }

        if (sdr_begin_xn(sdr) == 0) {
            log_error("bp_recv_once: sdr_begin_xn failed.");
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            bp_close(sap);
            goto out;
        }

        payload_size = zco_source_data_length(sdr, dlv.adu);
        payload = malloc(payload_size);
        if (!payload) {
            log_error("bp_recv_once: Failed to allocate memory for payload.");
            sdr_end_xn(sdr);
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            bp_close(sap);
            goto out;
        }

        zco_start_receiving(dlv.adu, &reader);
        if (zco_receive_source(sdr, &reader, payload_size, payload) < 0) {
            log_error("bp_recv_once: zco_receive_source failed.");
            free(payload);
            payload = NULL;
            sdr_end_xn(sdr);
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            bp_close(sap);
            goto out;
        }

        sdr_end_xn(sdr);
        pthread_mutex_unlock(&sdrmutex);
        bp_release_delivery(&dlv, 0);
        bp_close(sap);
    }

    if (payload == NULL) {
        log_info("bp_recv_once: no payload received for node_id=%u service_id=%u", dest_node_id,
                 dest_service_id);
        goto out;
    }

    reply.is_present = true;
    reply.payload = payload;
    reply.payload_size = payload_size;
    reply.src_node_id = src_node_id;
    reply.src_service_id = src_service_id;

out:
    if (payload && !reply.is_present) {
        free(payload);
    }
    return reply;
}
