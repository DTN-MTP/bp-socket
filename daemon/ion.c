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
    struct ion_recv_args *recv_args;
    struct ion_send_args *send_args;
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
    ctx->send_queue_head = NULL;
    ctx->send_queue_tail = NULL;
    ctx->send_queue_size = 0;
    pthread_mutex_init(&ctx->send_queue_mutex, NULL);
    pthread_cond_init(&ctx->send_queue_cond, NULL);

    err = endpoint_registry_add(ctx);
    if (err) {
        __atomic_store_n(&ctx->running, 0, __ATOMIC_RELAXED);
        pthread_mutex_destroy(&ctx->send_queue_mutex);
        pthread_cond_destroy(&ctx->send_queue_cond);
        bp_close(sap);
        free(ctx);
        return -ENOMEM;
    }

    recv_args = calloc(1, sizeof(struct ion_recv_args));
    if (!recv_args) {
        log_error("ion_open_endpoint: failed to allocate receive thread args");
        bp_close(sap);
        free(ctx);
        return -ENOMEM;
    }
    recv_args->netlink_sock = netlink_sock;
    recv_args->netlink_mutex = netlink_mutex;
    recv_args->netlink_family = netlink_family;
    recv_args->ctx = ctx;

    if (pthread_create(&ctx->recv_thread, NULL, ion_receive_thread, recv_args) != 0) {
        log_error("ion_open_endpoint: failed to create receive thread: %s", strerror(errno));
        bp_close(sap);
        free(recv_args);
        free(ctx);
        return -errno;
    }

    send_args = calloc(1, sizeof(struct ion_send_args));
    if (!send_args) {
        log_error("ion_open_endpoint: failed to allocate send thread args");
        bp_close(sap);
        free(recv_args);
        free(ctx);
        return -ENOMEM;
    }
    send_args->ctx = ctx;

    if (pthread_create(&ctx->send_thread, NULL, ion_send_thread, send_args) != 0) {
        log_error("ion_open_endpoint: failed to create send thread: %s", strerror(errno));
        bp_close(sap);
        free(send_args);
        free(recv_args);
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

    pthread_mutex_lock(&ctx->send_queue_mutex);
    pthread_cond_broadcast(&ctx->send_queue_cond);
    pthread_mutex_unlock(&ctx->send_queue_mutex);
    bp_interrupt(ctx->sap);
    pthread_join(ctx->recv_thread, NULL);
    pthread_join(ctx->send_thread, NULL);

    pthread_mutex_lock(&ctx->send_queue_mutex);
    struct send_queue_item *item = ctx->send_queue_head;
    while (item) {
        struct send_queue_item *next = item->next;
        free(item->dest_eid);
        free(item->payload);
        free(item);
        item = next;
    }
    ctx->send_queue_head = NULL;
    ctx->send_queue_tail = NULL;
    ctx->send_queue_size = 0;
    pthread_mutex_unlock(&ctx->send_queue_mutex);
    pthread_mutex_destroy(&ctx->send_queue_mutex);
    pthread_cond_destroy(&ctx->send_queue_cond);

    bp_close(ctx->sap);
    endpoint_registry_remove(node_id, service_id);

    return 0;
}

void *ion_send_thread(void *arg) {
    struct ion_send_args *args = arg;
    struct endpoint_ctx *ctx = args->ctx;
    struct send_queue_item *item;
    Object sdr_buffer = 0;
    Object adu = 0;
    struct bp_send_flags parsed_flags;

    while (true) {
        pthread_mutex_lock(&ctx->send_queue_mutex);
        while (ctx->send_queue_head == NULL && __atomic_load_n(&ctx->running, __ATOMIC_RELAXED)) {
            pthread_cond_wait(&ctx->send_queue_cond, &ctx->send_queue_mutex);
        }

        if (ctx->send_queue_head == NULL && !__atomic_load_n(&ctx->running, __ATOMIC_RELAXED)) {
            pthread_mutex_unlock(&ctx->send_queue_mutex);
            break;
        }

        item = ctx->send_queue_head;
        ctx->send_queue_head = item->next;
        if (ctx->send_queue_head == NULL) {
            ctx->send_queue_tail = NULL;
        }
        ctx->send_queue_size--;
        pthread_mutex_unlock(&ctx->send_queue_mutex);

        if (pthread_mutex_lock(&sdrmutex) != 0) {
            log_error("ion_send_thread: sdr mutex lock failed");
            goto cleanup_item;
        }

        if (sdr_begin_xn(sdr) == 0) {
            pthread_mutex_unlock(&sdrmutex);
            log_error("ion_send_thread: sdr_begin_xn failed");
            goto cleanup_item;
        }

        sdr_buffer = sdr_malloc(sdr, item->payload_size);
        if (sdr_buffer == 0) {
            pthread_mutex_unlock(&sdrmutex);
            log_error("ion_send_thread: no space for payload");
            goto cleanup_item;
        }

        sdr_write(sdr, sdr_buffer, (char *)item->payload, item->payload_size);

        adu = zco_create(sdr, ZcoSdrSource, sdr_buffer, 0, (vast)item->payload_size, ZcoOutbound);
        if (adu <= 0) {
            pthread_mutex_unlock(&sdrmutex);
            log_error("ion_send_thread: zco_create failed");
            goto cleanup_item;
        }

        if (sdr_end_xn(sdr) < 0) {
            pthread_mutex_unlock(&sdrmutex);
            log_error("ion_send_thread: sdr_end_xn failed");
            goto cleanup_item;
        }

        pthread_mutex_unlock(&sdrmutex);

        parsed_flags = bp_parse_flags(item->flags);
        if (bp_send(ctx->sap, (char *)item->dest_eid, NULL, 86400, parsed_flags.class_of_service,
                    parsed_flags.custody_switch, parsed_flags.srr_flags, parsed_flags.ack_requested,
                    NULL, adu, NULL) <= 0) {
            log_error("ion_send_thread: bp_send failed for %s", item->dest_eid);
            goto cleanup_item;
        }

        log_info("[ipn:%u.%u] Outbound bundle: destination=%s, payload_size=%zu bytes, "
                 "flags=0x%08x",
                 ctx->node_id, ctx->service_id, item->dest_eid, item->payload_size, item->flags);

    cleanup_item:
        free(item->dest_eid);
        free(item->payload);
        free(item);
    }

    free(args);
    return NULL;
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
            log_debug("ion_receive_thread: no payload received for node_id=%u service_id=%u",
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
            log_info("[ipn:%u.%u] Inbound bundle: source=ipn:%u.%u, payload_size=%zu bytes",
                     ctx->node_id, ctx->service_id, src_node_id, src_service_id, payload_size);
        }

        free(payload);
        payload = NULL;
    }

out:
    if (payload) free(payload);
    free(args);
    return NULL;
}
