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
#include "ion.h"
#include "log.h"

int handle_send_bundle(Daemon *daemon, struct nlattr **attrs) {
    void *payload;
    int payload_size;
    u_int32_t node_id, service_id;
    char eid[64];
    int eid_size;

    if (!attrs[BP_GENL_A_PAYLOAD] || !attrs[BP_GENL_A_NODE_ID] || !attrs[BP_GENL_A_SERVICE_ID]) {
        log_error(
            "handle_send_bundle: missing attribute(s) in SEND_BUNDLE command (payload, node ID, "
            "service ID)");
        return -EINVAL;
    }

    payload = nla_data(attrs[BP_GENL_A_PAYLOAD]);
    payload_size = nla_len(attrs[BP_GENL_A_PAYLOAD]);
    node_id = nla_get_u32(attrs[BP_GENL_A_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_SERVICE_ID]);

    eid_size = snprintf(eid, sizeof(eid), "ipn:%u.%u", node_id, service_id) + 1;
    if (eid_size < 0 || eid_size >= (int)sizeof(eid)) {
        log_error("[ipn:%u.%u] handle_send_bundle: failed to construct EID string", node_id,
                  service_id);
        return -EINVAL;
    }

    log_info("[ipn:%u.%u] SEND_BUNDLE: sending bundle to EID %s, size %d (bytes)", eid,
             payload_size, node_id, service_id);

    return bp_send_to_eid(daemon->sdr, payload, payload_size, eid, eid_size);
}

int handle_request_bundle(Daemon *daemon, struct nlattr **attrs) {
    pthread_t thread;
    struct thread_args *args;
    u_int32_t node_id, service_id;

    if (!attrs[BP_GENL_A_SERVICE_ID] || !attrs[BP_GENL_A_NODE_ID]) {
        log_error("handle_request_bundle: missing attribute(s) in REQUEST_BUNDLE "
                  "command (service "
                  "ID, node ID)");
        return -EINVAL;
    }

    node_id = nla_get_u32(attrs[BP_GENL_A_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_SERVICE_ID]);

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
    void *payload = NULL;
    size_t payload_size;
    int err;
    bool bundle_present;
    Object adu;

    adu = find_adu(args->sdr, args->node_id, args->service_id);
    bundle_present = adu != 0;

    payload = bp_recv_once(args->sdr, args->node_id, args->service_id, &payload_size);
    if (!payload) {
        log_error("[ipn:%u.%u] handle_recv_thread: failed to receive bundle", args->node_id,
                  args->service_id);
        goto out;
    }

    if (!bundle_present) {
        log_info("[ipn:%u.%u] REQUEST_BUNDLE: bundle received, size %zu bytes", args->node_id,
                 args->service_id, payload_size);
    } else {
        log_warn("[ipn:%u.%u] REQUEST_BUNDLE: bundle reference already present in memory, size %zu "
                 "bytes",
                 args->node_id, args->service_id, payload_size);
    }

    err = handle_deliver_bundle(payload, payload_size, args);
    if (err < 0) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed with error %d", err, args->node_id,
                  args->service_id);
    }

out:
    if (payload) free(payload);
    free(args);
    return NULL;
}

int handle_deliver_bundle(void *payload, int payload_size, struct thread_args *args) {
    struct nl_msg *msg = NULL;
    void *hdr;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to allocate Netlink msg",
                  args->node_id, args->service_id);
        ret = -ENOMEM;
        goto out;
    }

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, args->netlink_family, 0, 0,
                      BP_GENL_CMD_DELIVER_BUNDLE, BP_GENL_VERSION);
    if (!hdr) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to create Netlink header",
                  args->node_id, args->service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SERVICE_ID, args->service_id) < 0) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to add SERVICE_ID attribute",
                  args->node_id, args->service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_NODE_ID, args->node_id) < 0) {
        log_error("[ipn:%u.%u] handle_deliver_bundle: failed to add NODE_ID attribute",
                  args->node_id, args->service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put(msg, BP_GENL_A_PAYLOAD, payload_size, payload) < 0) {
        log_error("[ipn:%u.%u] [ipn:%u.%u] handle_deliver_bundle: failed to add PAYLOAD attribute",
                  args->node_id, args->service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    ret = nl_send_sync(args->netlink_sock, msg);
    if (ret < 0) {
        log_warn("[ipn:%u.%u] DELIVER_BUNDLE: bundle not delivered to kernel, keeping reference in "
                 "memory (no active BP socket "
                 "client)",
                 args->node_id, args->service_id);
        ret = 0; // Do not return an error, just log it
        goto out;
    }

    log_info("[ipn:%u.%u] DELIVER_BUNDLE: bundle sent to kernel", args->node_id, args->service_id);

    return 0;

err_free_msg:
    nlmsg_free(msg);
out:
    return ret;
}

int handle_destroy_bundle(Daemon *daemon, struct nlattr **attrs) {
    u_int32_t node_id, service_id;
    int ret = 0;

    if (!attrs[BP_GENL_A_NODE_ID] || !attrs[BP_GENL_A_SERVICE_ID]) {
        log_error("handle_destroy_bundle: missing attribute(s) in DESTROY_BUNDLE "
                  "command (node ID, "
                  "service ID)");
        ret = -EINVAL;
        goto out;
    }

    node_id = nla_get_u32(attrs[BP_GENL_A_NODE_ID]);
    service_id = nla_get_u32(attrs[BP_GENL_A_SERVICE_ID]);

    ret = destroy_adu(daemon->sdr, node_id, service_id);
    if (ret < 0) {
        log_error("[ipn:%u.%u] handle_destroy_bundle: failed to destroy bundle: %s", node_id,
                  service_id, strerror(-ret));
        goto out;
    }

    log_info("[ipn:%u.%u] DESTROY_BUNDLE: bundle destroy from ION", node_id, service_id);

out:
    return ret;
}