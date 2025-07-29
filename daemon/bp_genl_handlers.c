#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../include/bp_socket.h"
#include "adu_ref.h"
#include "bp.h"
#include "bp_genl_handlers.h"
#include "daemon.h"
#include "ion.h"
#include "log.h"

int handle_send_bundle(Daemon *daemon, struct nlattr **attrs) {
    void *payload;
    size_t payload_size;
    u_int32_t node_id, service_id;
    char dest_eid[64];
    int err = 0;
    int written;

    if (!attrs[BP_GENL_A_PAYLOAD] || !attrs[BP_GENL_A_DEST_NODE_ID] ||
        !attrs[BP_GENL_A_DEST_SERVICE_ID]) {
        log_error(
            "handle_send_bundle: missing attribute(s) in SEND_BUNDLE command (payload, node ID, "
            "service ID)");
        return -EINVAL;
    }

    payload = nla_data(attrs[BP_GENL_A_PAYLOAD]);
    payload_size = nla_len(attrs[BP_GENL_A_PAYLOAD]);
    node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);

    written = snprintf(dest_eid, sizeof(dest_eid), "ipn:%u.%u", node_id, service_id);
    if (written < 0 || written >= (int)sizeof(dest_eid)) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to construct EID string", node_id,
                  service_id);
        return -EINVAL;
    }

    err = bp_send_to_eid(daemon->sdr, payload, payload_size, dest_eid);
    if (err < 0) {
        log_error("[ipn:%u.%u] handle_send_bundle: bp_send_to_eid failed with error %d", node_id,
                  service_id, err);
        return err;
    }

    log_info("[ipn:%u.%u] SEND_BUNDLE: bundle sent to EID %s, size %d (bytes)", node_id, service_id,
             dest_eid, payload_size);

    return 0;
}

int handle_request_bundle(Daemon *daemon, struct nlattr **attrs) {
    pthread_t thread;
    struct thread_args *args;
    u_int32_t node_id, service_id;

    if (!attrs[BP_GENL_A_DEST_SERVICE_ID] || !attrs[BP_GENL_A_DEST_NODE_ID]) {
        log_error("handle_request_bundle: missing attribute(s) in REQUEST_BUNDLE "
                  "command (service "
                  "ID, node ID)");
        return -EINVAL;
    }

    node_id = nla_get_u32(attrs[BP_GENL_A_DEST_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_DEST_SERVICE_ID]);

    args = malloc(sizeof(struct thread_args));
    if (!args) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to allocate thread args", args->node_id,
                  args->service_id);
        return -ENOMEM;
    }
    args->node_id = node_id;
    args->service_id = service_id;
    args->netlink_sock = daemon->genl_bp_sock;
    args->netlink_family = daemon->genl_bp_family_id;
    args->sdr = daemon->sdr;

    log_info("[ipn:%u.%u] REQUEST_BUNDLE: bundle request initiated", node_id, service_id);
    if (pthread_create(&thread, NULL, (void *(*)(void *))handle_recv_thread, args) != 0) {
        log_error("[ipn:%u.%u] handle_request_bundle: failed to create receive thread: %s", node_id,
                  service_id, strerror(errno));
        return -errno;
    }

    pthread_detach(thread);

    return 0;
}

void *handle_recv_thread(struct thread_args *args) {
    int err;
    struct reply_bundle reply;

    reply = bp_recv_once(args->sdr, args->node_id,
                         args->service_id); // Blocking invocation to receive a bundle
    if (!reply.is_present) {
        err = handle_cancel_bundle_request(args->netlink_family, args->netlink_sock, args->node_id,
                                           args->service_id);
        if (err < 0) {
            log_error("[ipn:%u.%u] handle_cancel_bundle_request failed with error %d",
                      args->node_id, args->service_id, err);
            goto out;
        }

        log_info("[ipn:%u.%u] CANCEL_BUNDLE_REQUEST: bundle request cancelled", args->node_id,
                 args->service_id);
    } else {
        err = handle_deliver_bundle(args->netlink_family, args->netlink_sock, reply.payload,
                                    reply.payload_size, reply.src_node_id, reply.src_service_id,
                                    args->node_id, args->service_id);
        if (err < 0) {
            log_error("[ipn:%u.%u] handle_deliver_bundle: failed with error %d", args->node_id,
                      args->service_id, err);
            goto out;
        }

        log_info("[ipn:%u.%u] DELIVER_BUNDLE: bundle sent to kernel", reply.src_node_id,
                 reply.src_service_id);
    }

out:
    if (reply.payload) free(reply.payload);
    free(args);
    return NULL;
}

int handle_cancel_bundle_request(int netlink_family, struct nl_sock *netlink_sock,
                                 u_int32_t node_id, u_int32_t service_id) {
    struct nl_msg *msg = NULL;
    void *hdr;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        log_error("[ipn:%u.%u] handle_cancel_bundle_request: failed to allocate Netlink msg",
                  node_id, service_id);
        ret = -ENOMEM;
        goto out;
    }

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0,
                      BP_GENL_CMD_CANCEL_BUNDLE_REQUEST, BP_GENL_VERSION);
    if (!hdr) {
        log_error("[ipn:%u.%u] handle_cancel_bundle_request: failed to create Netlink header",
                  node_id, service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, node_id) < 0) {
        log_error("[ipn:%u.%u] handle_cancel_bundle_request: failed to add NODE_ID attribute",
                  node_id, service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, service_id) < 0) {
        log_error("[ipn:%u.%u] handle_cancel_bundle_request: failed to add SERVICE_ID attribute",
                  node_id, service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    ret = nl_send_sync(netlink_sock, msg);
    if (ret < 0) {
        log_error("[ipn:%u.%u] handle_cancel_bundle_request: bundle request not cancelled", node_id,
                  service_id);
        ret = -errno;
        goto out;
    }

    return 0;

err_free_msg:
    nlmsg_free(msg);
out:
    return ret;
}

int handle_deliver_bundle(int netlink_family, struct nl_sock *netlink_sock, void *payload,
                          int payload_size, u_int32_t src_node_id, u_int32_t src_service_id,
                          u_int32_t dest_node_id, u_int32_t dest_service_id) {
    struct nl_msg *msg = NULL;
    void *hdr;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to allocate Netlink msg", dest_node_id,
                  dest_service_id);
        ret = -ENOMEM;
        goto out;
    }

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0,
                      BP_GENL_CMD_DELIVER_BUNDLE, BP_GENL_VERSION);
    if (!hdr) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to create Netlink header",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, dest_node_id) < 0) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to add NODE_ID attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, dest_service_id) < 0) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to add SERVICE_ID attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_NODE_ID, src_node_id) < 0) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to add SRC_NODE_ID attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_SERVICE_ID, src_service_id) < 0) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to add SRC_SERVICE_ID attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put(msg, BP_GENL_A_PAYLOAD, payload_size, payload) < 0) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to add PAYLOAD attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    ret = nl_send_sync(netlink_sock, msg);
    if (ret < 0) {
        log_warn("[ipn:%u.%u] DELIVER_BUNDLE: bundle not delivered to kernel, keeping reference in "
                 "memory (no active BP socket "
                 "client)",
                 dest_node_id, dest_service_id);
        ret = -ENODEV;
        goto out;
    }

    return 0;

err_free_msg:
    nlmsg_free(msg);
out:
    return ret;
}

int handle_destroy_bundle(Daemon *daemon, struct nlattr **attrs) {
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

    adu = remove_adu_ref(daemon->sdr, node_id, service_id);
    if (adu == 0) {
        log_error("[ipn:%u.%u] handle_destroy_bundle: failed to destroy bundle: %s", node_id,
                  service_id, strerror(-ret));
        goto out;
    }
    ret = destroy_bundle(daemon->sdr, adu);
    if (ret < 0) {
        log_error("[ipn:%u.%u] handle_destroy_bundle: destroy_bundle failed with error %d", node_id,
                  service_id, ret);
        goto out;
    }

    log_info("[ipn:%u.%u] DESTROY_BUNDLE: bundle destroy from ION", node_id, service_id);

out:
    return ret;
}