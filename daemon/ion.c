#include "ion.h"
#include "../include/bp_socket.h"
#include "bp_genl.h"
#include "endpoint_registry.h"
#include "log.h"
#include "sdr.h"
#include <bp.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t sdrmutex = PTHREAD_MUTEX_INITIALIZER;
Sdr sdr;

static int make_eid(char *buf, size_t bufsize, u_int32_t node_id, u_int32_t service_id) {
    int n = snprintf(buf, bufsize, "ipn:%u.%u", node_id, service_id);
    if (n < 0 || n >= (int)bufsize) return -1;
    return 0;
}

int ion_open_endpoint(u_int32_t node_id, u_int32_t service_id, struct nl_sock *netlink_sock,
                      pthread_mutex_t *netlink_mutex, int netlink_family) {
    struct ion_recv_args *args;
    struct endpoint_ctx *ctx;
    char eid[64];
    BpSAP sap;
    int err;

    if (make_eid(eid, sizeof(eid), node_id, service_id) < 0) {
        log_error("ion_open_endpoint: EID too long");
        return -EINVAL;
    }

    if (endpoint_registry_exists(node_id, service_id)) {
        log_error("ion_open_endpoint: endpoint ipn:%u.%u already exists", node_id, service_id);
        return -EADDRINUSE;
    }

    if (bp_open(eid, &sap) < 0) {
        log_error("ion_open_endpoint: bp_open failed for %s", eid);
        return -EIO;
    }

    ctx = calloc(1, sizeof(struct endpoint_ctx));
    if (!ctx) {
        log_error("ion_open_endpoint: failed to allocate endpoint context");
        bp_close(sap);
        return -ENOMEM;
    }
    ctx->node_id = node_id;
    ctx->service_id = service_id;
    ctx->sap = sap;
    atomic_init(&ctx->running, 1);

    err = endpoint_registry_add(ctx);
    if (err) {
        __atomic_store_n(&ctx->running, 0, __ATOMIC_RELAXED);
        bp_close(sap);
        free(ctx);
        return -ENOMEM;
    }

    args = calloc(1, sizeof(struct ion_recv_args));
    if (!args) {
        log_error("ion_open_endpoint: failed to allocate thread args");
        bp_close(sap);
        free(ctx);
        return -ENOMEM;
    }
    args->netlink_sock = netlink_sock;
    args->netlink_mutex = netlink_mutex;
    args->netlink_family = netlink_family;
    args->ctx = ctx;

    if (pthread_create(&ctx->recv_thread, NULL, ion_receive_thread, args) != 0) {
        log_error("ion_open_endpoint: failed to create receive thread: %s", strerror(errno));
        bp_close(sap);
        free(args);
        free(ctx);
        return -errno;
    }

    return 0;
}

int ion_close_endpoint(u_int32_t node_id, u_int32_t service_id) {
    struct endpoint_ctx *ctx = endpoint_registry_get(node_id, service_id);
    if (!ctx) {
        log_error("ion_close_endpoint: endpoint ipn:%u.%u not found", node_id, service_id);
        return -ENOENT;
    }

    __atomic_store_n(&ctx->running, 0, __ATOMIC_RELAXED);

    bp_interrupt(ctx->sap);
    pthread_join(ctx->recv_thread, NULL);
    bp_close(ctx->sap);

    endpoint_registry_remove(node_id, service_id);

    return 0;
}

void *ion_send_thread(void *arg) {
    struct ion_send_args *args = arg;
    const char *dest_eid = args->dest_eid;
    const void *payload = args->payload;
    size_t payload_size = args->payload_size;
    u_int32_t node_id = args->node_id;
    u_int32_t service_id = args->service_id;
    struct endpoint_ctx *ctx;
    Object sdr_buffer = 0;
    Object adu = 0;
    struct bp_send_flags parsed_flags;
    int ret = 0;

    if (!dest_eid || !payload || payload_size == 0) {
        log_error("ion_send_thread: invalid parameters");
        ret = -EINVAL;
        goto cleanup;
    }

    ctx = endpoint_registry_get(node_id, service_id);
    if (!ctx) {
        log_error("ion_send_thread: no endpoint for ipn:%u.%u", node_id, service_id);
        ret = -ENODEV;
        goto cleanup;
    }

    if (!ctx->sap) {
        log_error("ion_send_thread: invalid SAP for ipn:%u.%u", node_id, service_id);
        ret = -EINVAL;
        goto cleanup;
    }

    if (pthread_mutex_lock(&sdrmutex) != 0) {
        log_error("ion_send_thread: sdr mutex lock failed");
        ret = -EAGAIN;
        goto cleanup;
    }

    if (sdr_begin_xn(sdr) == 0) {
        pthread_mutex_unlock(&sdrmutex);
        log_error("ion_send_thread: sdr_begin_xn failed");
        ret = -EIO;
        goto cleanup;
    }

    sdr_buffer = sdr_malloc(sdr, payload_size);
    if (sdr_buffer == 0) {
        pthread_mutex_unlock(&sdrmutex);
        log_error("ion_send_thread: no space for payload");
        ret = -ENOSPC;
        goto cleanup;
    }

    sdr_write(sdr, sdr_buffer, (char *)payload, payload_size);

    adu = zco_create(sdr, ZcoSdrSource, sdr_buffer, 0, (vast)payload_size, ZcoOutbound);
    if (adu <= 0) {
        pthread_mutex_unlock(&sdrmutex);
        log_error("ion_send_thread: zco_create failed");
        ret = -ENOMEM;
        goto cleanup;
    }

    if (sdr_end_xn(sdr) < 0) {
        pthread_mutex_unlock(&sdrmutex);
        log_error("ion_send_thread: sdr_end_xn failed");
        ret = -EIO;
        goto cleanup;
    }

    pthread_mutex_unlock(&sdrmutex);

    parsed_flags = bp_parse_flags(args->flags);
    if (bp_send(ctx->sap, (char *)dest_eid, NULL, 86400, parsed_flags.class_of_service,
                parsed_flags.custody_switch, parsed_flags.srr_flags, parsed_flags.ack_requested,
                NULL, adu, NULL) <= 0) {
        log_error("ion_send_thread: bp_send failed");
        ret = -EIO;
        goto cleanup;
    }

    log_info("[ipn:%u.%u] SEND_BUNDLE: bundle sent to EID %s, size %zu (bytes)", node_id,
             service_id, args->dest_eid, args->payload_size);

    free(args->dest_eid);
    free(args->payload);
    free(args);
    return (void *)(intptr_t)0;

cleanup:
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
    struct endpoint_ctx *ctx = args->ctx;

    const u_int32_t dest_node_id = ctx->node_id;
    const u_int32_t dest_service_id = ctx->service_id;
    BpSAP sap = ctx->sap;
    BpDelivery dlv;
    ZcoReader reader;
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
            goto out;
        }
        own_node_id = (u_int32_t)own;
    }
    if (dest_node_id != own_node_id) {
        log_error("ion_receive_thread: node ID mismatch. Expected %u, got %u", own_node_id,
                  dest_node_id);
        goto out;
    }

    if (!sap) {
        log_error("ion_receive_thread: invalid SAP for ipn:%u.%u", dest_node_id, dest_service_id);
        goto out;
    }

    while (__atomic_load_n(&ctx->running, __ATOMIC_RELAXED)) {
        payload = NULL;
        payload_size = 0;
        src_node_id = 0;
        src_service_id = 0;

        if (bp_receive(sap, &dlv, BP_BLOCKING) < 0) {
            log_error("ion_receive_thread: bundle reception failed.");
            goto out;
        }

        if (dlv.result == BpReceptionInterrupted || dlv.adu == 0) {
            bp_release_delivery(&dlv, 0);
            continue;
        }

        if (dlv.result == BpEndpointStopped) {
            bp_release_delivery(&dlv, 0);
            goto out;
        }

        if (sscanf(dlv.bundleSourceEid, "ipn:%u.%u", &src_node_id, &src_service_id) != 2) {
            log_error("ion_receive_thread: failed to parse bundleSourceEid: %s",
                      dlv.bundleSourceEid);
            bp_release_delivery(&dlv, 0);
            continue;
        }

        if (pthread_mutex_lock(&sdrmutex) != 0) {
            log_error("ion_receive_thread: Failed to lock SDR mutex.");
            bp_release_delivery(&dlv, 0);
            continue;
        }
        if (sdr_begin_xn(sdr) == 0) {
            log_error("ion_receive_thread: sdr_begin_xn failed.");
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            continue;
        }
        payload_size = (size_t)zco_source_data_length(sdr, dlv.adu);
        payload = malloc(payload_size);
        if (!payload) {
            log_error("ion_receive_thread: Failed to allocate memory for payload.");
            sdr_end_xn(sdr);
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            continue;
        }
        zco_start_receiving(dlv.adu, &reader);
        if (zco_receive_source(sdr, &reader, (vast)payload_size, payload) < 0) {
            log_error("ion_receive_thread: zco_receive_source failed.");
            free(payload);
            payload = NULL;
            sdr_end_xn(sdr);
            pthread_mutex_unlock(&sdrmutex);
            bp_release_delivery(&dlv, 0);
            continue;
        }
        sdr_end_xn(sdr);
        pthread_mutex_unlock(&sdrmutex);
        bp_release_delivery(&dlv, 0);

        if (!payload) {
            log_info("ion_receive_thread: no payload received for node_id=%u service_id=%u",
                     dest_node_id, dest_service_id);
            continue;
        }

        err = bp_genl_enqueue_bundle(args->netlink_family, args->netlink_sock, args->netlink_mutex,
                                     payload, payload_size, src_node_id, src_service_id,
                                     dest_node_id, dest_service_id, dlv.adu);
        if (err < 0) {
            log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed with error %d", dest_node_id,
                      dest_service_id, err);
        } else {
            log_info("[ipn:%u.%u] ENQUEUE_BUNDLE: incoming bundle queued in the kernel (adu: %llu)",
                     dest_node_id, dest_service_id, (unsigned long long)dlv.adu);
        }

        free(payload);
        payload = NULL;
    }

out:
    if (payload) free(payload);
    free(args);
    return NULL;
}
