#include "ion.h"
#include "adu_registry.h"
#include "log.h"
#include "nl_utils.h"
#include "sap_registry.h"
#include "sdr.h"
#include <bp.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t sdrmutex = PTHREAD_MUTEX_INITIALIZER;
Sdr sdr;

static int make_eid(char *buf, size_t bufsize, u_int32_t node_id, u_int32_t service_id) {
    int n = snprintf(buf, bufsize, "ipn:%u.%u", node_id, service_id);
    if (n < 0 || n >= (int)bufsize) return -1;
    return 0;
}

int ion_open_endpoint(u_int32_t node_id, u_int32_t service_id) {
    char eid[64];
    BpSAP sap;

    if (make_eid(eid, sizeof(eid), node_id, service_id) < 0) {
        log_error("ion_open_endpoint: EID too long");
        return -EINVAL;
    }

    if (sap_registry_contains(node_id, service_id)) {
        return 0; // already open
    }

    if (bp_open(eid, &sap) < 0) {
        log_error("ion_open_endpoint: bp_open failed for %s", eid);
        return -EIO;
    }

    if (sap_registry_add(node_id, service_id, sap) < 0) {
        bp_close(sap);
        return -ENOMEM;
    }
    return 0;
}

int ion_close_endpoint(u_int32_t node_id, u_int32_t service_id) {
    BpSAP sap = sap_registry_get(node_id, service_id);
    if (sap) {
        if (sap_registry_has_active_receive(node_id, service_id)) {
            log_info("[ipn:%u.%u] CLOSE_ENDPOINT: interrupting active reception", node_id,
                     service_id);
            bp_interrupt(sap);
        } else {
            log_info("[ipn:%u.%u] CLOSE_ENDPOINT: no active reception, closing directly", node_id,
                     service_id);
        }

        bp_close(sap);
    }
    sap_registry_remove(node_id, service_id);
    return 0;
}

void *ion_send_thread(void *arg) {
    struct ion_send_args *args = arg;
    const char *dest_eid = args->dest_eid;
    const void *payload = args->payload;
    size_t payload_size = args->payload_size;
    u_int32_t src_node_id = args->src_node_id;
    u_int32_t src_service_id = args->src_service_id;
    BpSAP sap = NULL;
    Object sdr_buffer = 0;
    Object adu = 0;
    int ret = 0;

    if (!dest_eid || !payload || payload_size == 0) {
        log_error("ion_send_thread: invalid parameters");
        ret = -EINVAL;
        goto cleanup_and_notify;
    }

    sap = sap_registry_get(src_node_id, src_service_id);
    if (!sap) {
        log_error("ion_send_thread: no SAP for ipn:%u.%u", src_node_id, src_service_id);
        ret = -ENODEV;
        goto cleanup_and_notify;
    }

    if (pthread_mutex_lock(&sdrmutex) != 0) {
        log_error("ion_send_thread: sdr mutex lock failed");
        ret = -EAGAIN;
        goto cleanup_and_notify;
    }

    if (sdr_begin_xn(sdr) == 0) {
        pthread_mutex_unlock(&sdrmutex);
        log_error("ion_send_thread: sdr_begin_xn failed");
        ret = -EIO;
        goto cleanup_and_notify;
    }

    sdr_buffer = sdr_malloc(sdr, payload_size);
    if (sdr_buffer == 0) {
        pthread_mutex_unlock(&sdrmutex);
        log_error("ion_send_thread: no space for payload");
        ret = -ENOSPC;
        goto cleanup_and_notify;
    }

    sdr_write(sdr, sdr_buffer, (char *)payload, payload_size);

    adu = zco_create(sdr, ZcoSdrSource, sdr_buffer, 0, (vast)payload_size, ZcoOutbound);
    if (adu <= 0) {
        pthread_mutex_unlock(&sdrmutex);
        log_error("ion_send_thread: zco_create failed");
        ret = -ENOMEM;
        goto cleanup_and_notify;
    }

    if (sdr_end_xn(sdr) < 0) {
        pthread_mutex_unlock(&sdrmutex);
        log_error("ion_send_thread: sdr_end_xn failed");
        ret = -EIO;
        goto cleanup_and_notify;
    }

    pthread_mutex_unlock(&sdrmutex);

    if (bp_send(sap, (char *)dest_eid, NULL, 86400, BP_STD_PRIORITY, NoCustodyRequested, 0, 0, NULL,
                adu, NULL) <= 0) {
        log_error("ion_send_thread: bp_send failed");
        ret = -EIO;
        goto cleanup_and_notify;
    }

    log_info("[ipn:%u.%u] SEND_BUNDLE: bundle sent to EID %s, size %zu (bytes)", args->src_node_id,
             args->src_service_id, args->dest_eid, args->payload_size);

    if (nl_send_bundle_confirmation(args->netlink_family, args->netlink_sock, args->src_node_id,
                                    args->src_service_id) < 0) {
        log_error("[ipn:%u.%u] SEND_BUNDLE: failed to send confirmation to kernel",
                  args->src_node_id, args->src_service_id);
    } else {
        log_info("[ipn:%u.%u] SEND_BUNDLE: confirmation sent to kernel", args->src_node_id,
                 args->src_service_id);
    }

    free(args->dest_eid);
    free(args->payload);
    free(args);
    return (void *)(intptr_t)0;

cleanup_and_notify: {
    int nl_ret = nl_send_bundle_failure(args->netlink_family, args->netlink_sock, args->src_node_id,
                                        args->src_service_id, ret);
    if (nl_ret < 0) {
        log_error(
            "[ipn:%u.%u] SEND_BUNDLE: failed to send failure notification to kernel (err: %d)",
            args->src_node_id, args->src_service_id, nl_ret);
    } else {
        log_info("[ipn:%u.%u] SEND_BUNDLE: failure notification sent to kernel", args->src_node_id,
                 args->src_service_id);
    }
}

    free(args->dest_eid);
    free(args->payload);
    free(args);
    return (void *)(intptr_t)ret;
}

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

int ion_destroy_bundle(Object adu) {
    if (pthread_mutex_lock(&sdrmutex) != 0) {
        log_error("ion_destroy_bundle: Failed to lock SDR mutex.");
        return -EAGAIN;
    }

    if (sdr_begin_xn(sdr) == 0) {
        log_error("ion_destroy_bundle: sdr_begin_xn failed.");
        pthread_mutex_unlock(&sdrmutex);
        return -EIO;
    }

    zco_destroy(sdr, adu);

    sdr_end_xn(sdr);
    pthread_mutex_unlock(&sdrmutex);
    return 0;
}

void *ion_receive_thread(void *arg) {
    struct ion_recv_args *args = arg;
    const u_int32_t dest_node_id = args->node_id;
    const u_int32_t dest_service_id = args->service_id;

    sap_registry_mark_receive_active(dest_node_id, dest_service_id);

    BpSAP sap;
    BpDelivery dlv;
    ZcoReader reader;
    adu_node_t *adu_ref;
    u_int32_t own_node_id;
    void *payload = NULL;
    size_t payload_size = 0;
    u_int32_t src_node_id = 0, src_service_id = 0;
    int err;

    {
        uvast own = getOwnNodeNbr();
        if (own > (uvast)0xFFFFFFFFu) {
            log_error("ion_receive_thread: own node ID out of 32-bit range: %llu",
                      (unsigned long long)own);
            goto cancel;
        }
        own_node_id = (u_int32_t)own;
    }
    if (dest_node_id != own_node_id) {
        log_error("ion_receive_thread: node ID mismatch. Expected %u, got %u", own_node_id,
                  dest_node_id);
        goto cancel;
    }

    adu_ref = adu_registry_get(dest_node_id, dest_service_id);
    if (adu_ref != NULL) {
        if (pthread_mutex_lock(&sdrmutex) != 0) {
            log_error("ion_receive_thread: Failed to lock SDR mutex.");
            goto cancel;
        }
        if (sdr_begin_xn(sdr) == 0) {
            log_error("ion_receive_thread: sdr_begin_xn failed.");
            pthread_mutex_unlock(&sdrmutex);
            goto cancel;
        }
        payload_size = (size_t)zco_source_data_length(sdr, adu_ref->adu);
        payload = malloc(payload_size);
        if (!payload) {
            log_error("ion_receive_thread: Failed to allocate memory for payload.");
            sdr_end_xn(sdr);
            pthread_mutex_unlock(&sdrmutex);
            goto cancel;
        }
        zco_start_receiving(adu_ref->adu, &reader);
        if (zco_receive_source(sdr, &reader, (vast)payload_size, payload) < 0) {
            log_error("ion_receive_thread: zco_receive_source failed.");
            free(payload);
            payload = NULL;
            sdr_end_xn(sdr);
            pthread_mutex_unlock(&sdrmutex);
            goto cancel;
        }
        src_node_id = adu_ref->src_node_id;
        src_service_id = adu_ref->src_service_id;
        sdr_end_xn(sdr);
        pthread_mutex_unlock(&sdrmutex);
    } else {
        sap = sap_registry_get(dest_node_id, dest_service_id);
        if (!sap) {
            log_error("ion_receive_thread: no SAP for ipn:%u.%u", dest_node_id, dest_service_id);
            goto cancel;
        }

        while (1) {
            if (bp_receive(sap, &dlv, BP_BLOCKING) < 0) {
                log_error("ion_receive_thread: bundle reception failed.");
                goto cancel;
            }

            if (dlv.result == BpReceptionInterrupted) {
                if (!sap_registry_contains(dest_node_id, dest_service_id)) {
                    log_info("ion_receive_thread: endpoint closing, stopping");
                    bp_release_delivery(&dlv, 0);
                    goto cancel;
                }
                log_info("ion_receive_thread: reception interrupted, continuing to wait");
                bp_release_delivery(&dlv, 0);
                continue;
            }

            if (dlv.adu == 0) {
                log_info("ion_receive_thread: no ADU, continuing to wait");
                bp_release_delivery(&dlv, 0);
                continue;
            }

            if (dlv.result == BpEndpointStopped) {
                log_info("ion_receive_thread: endpoint stopped");
                bp_release_delivery(&dlv, 0);
                goto cancel;
            }

            break;
        }
        if (sscanf(dlv.bundleSourceEid, "ipn:%u.%u", &src_node_id, &src_service_id) != 2) {
            log_error("ion_receive_thread: failed to parse bundleSourceEid: %s",
                      dlv.bundleSourceEid);
            bp_release_delivery(&dlv, 0);
            goto cancel;
        }
        if (adu_registry_add(dlv.adu, dest_node_id, dest_service_id, src_node_id, src_service_id) <
            0) {
            log_error("ion_receive_thread: failed to add bundle reference.");
            bp_release_delivery(&dlv, 0);
            goto cancel;
        }
        if (pthread_mutex_lock(&sdrmutex) != 0) {
            log_error("ion_receive_thread: Failed to lock SDR mutex.");
            bp_release_delivery(&dlv, 0);
            goto cancel;
        }
        if (sdr_begin_xn(sdr) == 0) {
            log_error("ion_receive_thread: sdr_begin_xn failed.");
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            goto cancel;
        }
        payload_size = (size_t)zco_source_data_length(sdr, dlv.adu);
        payload = malloc(payload_size);
        if (!payload) {
            log_error("ion_receive_thread: Failed to allocate memory for payload.");
            sdr_end_xn(sdr);
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            goto cancel;
        }
        zco_start_receiving(dlv.adu, &reader);
        if (zco_receive_source(sdr, &reader, (vast)payload_size, payload) < 0) {
            log_error("ion_receive_thread: zco_receive_source failed.");
            free(payload);
            payload = NULL;
            sdr_end_xn(sdr);
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            goto cancel;
        }
        sdr_end_xn(sdr);
        pthread_mutex_unlock(&sdrmutex);
        bp_release_delivery(&dlv, 0);
    }

    if (!payload) {
        log_info("ion_receive_thread: no payload received for node_id=%u service_id=%u",
                 dest_node_id, dest_service_id);
        goto cancel;
    }

    err = nl_send_deliver_bundle(args->netlink_family, args->netlink_sock, payload, payload_size,
                                 src_node_id, src_service_id, dest_node_id, dest_service_id);
    if (err < 0) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: failed with error %d", dest_node_id,
                  dest_service_id, err);
    } else {
        log_info("[ipn:%u.%u] DELIVER_BUNDLE: bundle sent to kernel", dest_node_id,
                 dest_service_id);
    }
    sap_registry_mark_receive_inactive(dest_node_id, dest_service_id);

    free(payload);
    free(args);
    return NULL;

cancel:
    // Mark thread as inactive before cleanup
    sap_registry_mark_receive_inactive(dest_node_id, dest_service_id);

    err = nl_send_cancel_bundle_request(args->netlink_family, args->netlink_sock, dest_node_id,
                                        dest_service_id);
    if (err < 0) {
        log_error("[ipn:%u.%u] nl_send_cancel_bundle_request failed with error %d", dest_node_id,
                  dest_service_id, err);
    } else {
        log_info("[ipn:%u.%u] CANCEL_BUNDLE_REQUEST: bundle request cancelled", dest_node_id,
                 dest_service_id);
    }
    if (payload) free(payload);
    free(args);
    return NULL;
}
