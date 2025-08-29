#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../include/bp_socket.h"
#include "adu_registry.h"
#include "bp.h"
#include "bp_genl_handlers.h"
#include "daemon.h"
#include "ion.h"
#include "log.h"
#include <errno.h>

int handle_open_endpoint(Daemon *daemon, struct nlattr **attrs) {
    u_int32_t node_id, service_id;
    (void)daemon;

    if (!attrs[BP_GENL_A_DEST_NODE_ID] || !attrs[BP_GENL_A_DEST_SERVICE_ID]) {
        log_error("handle_open_endpoint: missing attribute(s)");
        return -EINVAL;
    }
    node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);

    log_info("[ipn:%u.%u] OPEN_ENDPOINT: opening endpoint", node_id, service_id);
    int ret = ion_open_endpoint(node_id, service_id);
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

    log_info("[ipn:%u.%u] CLOSE_ENDPOINT: closing endpoint", node_id, service_id);
    int ret = ion_close_endpoint(node_id, service_id);
    if (ret == 0) {
        log_info("[ipn:%u.%u] CLOSE_ENDPOINT: endpoint closed successfully", node_id, service_id);
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

    // Enqueue to send thread using source endpoint SAP
    // Launch async send thread
    pthread_t send_thread;
    struct ion_send_args *send_args = malloc(sizeof(struct ion_send_args));
    if (!send_args) return -ENOMEM;
    send_args->src_node_id = src_node_id;
    send_args->src_service_id = src_service_id;
    send_args->dest_eid = strndup(dest_eid, sizeof(dest_eid));
    send_args->payload = malloc(payload_size);
    send_args->netlink_sock = daemon->genl_bp_sock;
    send_args->netlink_family = daemon->genl_bp_family_id;
    if (!send_args->dest_eid || !send_args->payload) {
        free(send_args->dest_eid);
        free(send_args->payload);
        free(send_args);
        return -ENOMEM;
    }
    memcpy(send_args->payload, payload, payload_size);
    send_args->payload_size = payload_size;
    if (pthread_create(&send_thread, NULL, ion_send_thread, send_args) != 0) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to create send thread", src_node_id,
                  src_service_id);
        free(send_args->dest_eid);
        free(send_args->payload);
        free(send_args);
        return -errno;
    }
    pthread_detach(send_thread);

    return 0;
}

int handle_request_bundle(Daemon *daemon, struct nlattr **attrs) {
    pthread_t thread;
    struct ion_recv_args *args;
    u_int32_t node_id, service_id;

    if (!attrs[BP_GENL_A_DEST_SERVICE_ID] || !attrs[BP_GENL_A_DEST_NODE_ID]) {
        log_error("handle_request_bundle: missing attribute(s) in REQUEST_BUNDLE "
                  "command (service "
                  "ID, node ID)");
        return -EINVAL;
    }

    node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);

    args = malloc(sizeof(struct ion_recv_args));
    if (!args) {
        log_error("handle_request_bundle: failed to allocate thread args", node_id, service_id);
        return -ENOMEM;
    }
    args->node_id = node_id;
    args->service_id = service_id;
    args->netlink_sock = daemon->genl_bp_sock;
    args->netlink_family = daemon->genl_bp_family_id;

    log_info("[ipn:%u.%u] REQUEST_BUNDLE: bundle request initiated", node_id, service_id);
    if (pthread_create(&thread, NULL, ion_receive_thread, args) != 0) {
        log_error("[ipn:%u.%u] handle_request_bundle: failed to create receive thread: %s", node_id,
                  service_id, strerror(errno));
        free(args);
        return -errno;
    }

    pthread_detach(thread);

    return 0;
}

int handle_destroy_bundle(Daemon *daemon, struct nlattr **attrs) {
    (void)daemon;
    u_int32_t node_id, service_id;
    Object adu;
    int ret = 0;

    if (!attrs[BP_GENL_A_DEST_NODE_ID] || !attrs[BP_GENL_A_DEST_SERVICE_ID]) {
        log_error("handle_destroy_bundle: missing attribute(s) in DESTROY_BUNDLE "
                  "command (node ID, "
                  "service ID)");
        ret = -EINVAL;
        goto out;
    }

    node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);

    adu = adu_registry_remove(node_id, service_id);
    if (adu == 0) {
        log_error("[ipn:%u.%u] handle_destroy_bundle: failed to destroy bundle: %s", node_id,
                  service_id, strerror(-ret));
        goto out;
    }
    ret = ion_destroy_bundle(adu);
    if (ret < 0) {
        log_error("[ipn:%u.%u] handle_destroy_bundle: ion_destroy_bundle failed with error %d",
                  node_id, service_id, ret);
        goto out;
    }

    log_info("[ipn:%u.%u] DESTROY_BUNDLE: bundle destroy from ION", node_id, service_id);

out:
    return ret;
}