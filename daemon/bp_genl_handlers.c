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
    u_int32_t flags;
    int ret;

    if (!attrs[BP_GENL_A_PAYLOAD] || !attrs[BP_GENL_A_DEST_NODE_ID] ||
        !attrs[BP_GENL_A_DEST_SERVICE_ID] || !attrs[BP_GENL_A_SRC_NODE_ID] ||
        !attrs[BP_GENL_A_SRC_SERVICE_ID] || !attrs[BP_GENL_A_FLAGS]) {
        log_error(
            "handle_send_bundle: missing attribute(s) in SEND_BUNDLE command (payload, node ID, "
            "service ID, flags)");
        return -EINVAL;
    }

    payload = nla_data(attrs[BP_GENL_A_PAYLOAD]);
    payload_size = (size_t)nla_len(attrs[BP_GENL_A_PAYLOAD]);
    dest_node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    dest_service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);
    src_node_id = nla_get_u32(attrs[BP_GENL_A_SRC_NODE_ID]);
    src_service_id = nla_get_u32(attrs[BP_GENL_A_SRC_SERVICE_ID]);
    flags = nla_get_u32(attrs[BP_GENL_A_FLAGS]);

    written = snprintf(dest_eid, sizeof(dest_eid), "ipn:%u.%u", dest_node_id, dest_service_id);
    if (written < 0 || written >= (int)sizeof(dest_eid)) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to construct EID string", src_node_id,
                  src_service_id);
        return -EINVAL;
    }

    ret = endpoint_registry_enqueue_send(src_node_id, src_service_id, dest_eid, payload,
                                         payload_size, flags);
    if (ret < 0) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to enqueue send (error: %d)", src_node_id,
                  src_service_id, ret);
        return ret;
    }

    log_info("[ipn:%u.%u] SEND_BUNDLE: bundle queued for sending to EID %s, size %zu (bytes)",
             src_node_id, src_service_id, dest_eid, payload_size);

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