#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../include/bp_socket.h"
#include "bp.h"
#include "bp_genl_handlers.h"
#include "daemon.h"
#include "endpoint_registry.h"
#include "ion.h"
#include "log.h"
#include <errno.h>

int handle_open_endpoint(Daemon *daemon, struct nlattr **attrs) {
    u_int32_t node_id, service_id;
    int ret;

    if (!attrs[BP_GENL_A_DEST_NODE_ID] || !attrs[BP_GENL_A_DEST_SERVICE_ID]) {
        log_error("handle_open_endpoint: missing attribute(s)");
        return -EINVAL;
    }
    node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);

    ret = ion_open_endpoint(node_id, service_id, daemon->genl_bp_sock, &daemon->netlink_mutex,
                            daemon->genl_bp_family_id);
    if (ret == 0) {
        log_info("[ipn:%u.%u] OPEN_ENDPOINT: endpoint opened successfully", node_id, service_id);
    } else {
        log_error("[ipn:%u.%u] OPEN_ENDPOINT: failed to open endpoint (error %d)", node_id,
                  service_id, ret);
    }
    return ret;
}

int handle_close_endpoint(Daemon *daemon, struct nlattr **attrs) {
    u_int32_t node_id, service_id;
    (void)daemon;

    if (!attrs[BP_GENL_A_DEST_NODE_ID] || !attrs[BP_GENL_A_DEST_SERVICE_ID]) {
        log_error("handle_close_endpoint: missing attribute(s)");
        return -EINVAL;
    }
    node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);

    int ret = ion_close_endpoint(node_id, service_id);
    if (ret == 0) {
        log_info("[ipn:%u.%u] CLOSE_ENDPOINT: closing endpoint", node_id, service_id);
    } else {
        log_error("[ipn:%u.%u] CLOSE_ENDPOINT: failed to close endpoint (error %d)", node_id,
                  service_id, ret);
    }

    return ret;
}

int handle_send_bundle(Daemon *daemon, struct nlattr **attrs) {
    (void)daemon;
    void *payload;
    size_t payload_size;
    u_int32_t dest_node_id, dest_service_id, src_node_id, src_service_id;
    char dest_eid[64];
    int written;
    pthread_t thread;
    struct ion_send_args *args;
    struct endpoint_ctx *ctx;
    void *payload_copy;

    if (!attrs[BP_GENL_A_PAYLOAD] || !attrs[BP_GENL_A_DEST_NODE_ID] ||
        !attrs[BP_GENL_A_DEST_SERVICE_ID] || !attrs[BP_GENL_A_SRC_NODE_ID] ||
        !attrs[BP_GENL_A_SRC_SERVICE_ID]) {
        log_error(
            "handle_send_bundle: missing attribute(s) in SEND_BUNDLE command (payload, node ID, "
            "service ID)");
        return -EINVAL;
    }

    payload = nla_data(attrs[BP_GENL_A_PAYLOAD]);
    payload_size = (size_t)nla_len(attrs[BP_GENL_A_PAYLOAD]);
    dest_node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    dest_service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);
    src_node_id = nla_get_u32(attrs[BP_GENL_A_SRC_NODE_ID]);
    src_service_id = nla_get_u32(attrs[BP_GENL_A_SRC_SERVICE_ID]);

    written = snprintf(dest_eid, sizeof(dest_eid), "ipn:%u.%u", dest_node_id, dest_service_id);
    if (written < 0 || written >= (int)sizeof(dest_eid)) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to construct EID string", src_node_id,
                  src_service_id);
        return -EINVAL;
    }

    ctx = endpoint_registry_get(src_node_id, src_service_id);
    if (!ctx) {
        log_error("[ipn:%u.%u] handle_send_bundle: no endpoint for ipn:%u.%u", src_node_id,
                  src_service_id, src_node_id, src_service_id);
        return -ENODEV;
    }

    payload_copy = malloc(payload_size);
    if (!payload_copy) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to allocate payload", src_node_id,
                  src_service_id);
        return -ENOMEM;
    }
    memcpy(payload_copy, payload, payload_size);

    // Enqueue to send thread using source endpoint SAP
    // Launch async send thread
    args = malloc(sizeof(struct ion_send_args));
    if (!args) return -ENOMEM;
    args->node_id = src_node_id;
    args->service_id = src_service_id;
    args->dest_eid = strndup(dest_eid, sizeof(dest_eid));
    args->netlink_sock = daemon->genl_bp_sock;
    args->netlink_mutex = &daemon->netlink_mutex;
    args->netlink_family = daemon->genl_bp_family_id;
    args->payload = payload_copy;
    args->payload_size = payload_size;

    if (pthread_create(&thread, NULL, ion_send_thread, args) != 0) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to create send thread", src_node_id,
                  src_service_id);
        free(args->dest_eid);
        free(args->payload);
        free(args);
        return -errno;
    }

    return 0;
}

int handle_destroy_bundle(Daemon *daemon, struct nlattr **attrs) {
    (void)daemon;
    uint64_t adu;
    int ret = 0;

    if (!attrs[BP_GENL_A_ADU]) {
        log_error("handle_destroy_bundle: missing ADU attribute in DESTROY_BUNDLE command");
        return -EINVAL;
    }

    adu = nla_get_u64(attrs[BP_GENL_A_ADU]);

    ret = ion_destroy_bundle((Object)adu);
    if (ret < 0) {
        log_error("handle_destroy_bundle: ion_destroy_bundle failed with error %d", ret);
        return ret;
    }

    log_info("DESTROY_BUNDLE: bundle consumed by a socket (adu: %llu)", (unsigned long long)adu);

    return 0;
}