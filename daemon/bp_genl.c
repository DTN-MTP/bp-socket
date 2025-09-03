#include <errno.h>
#include <limits.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/bp_socket.h"
#include "bp_genl.h"
#include "bp_genl_handlers.h"
#include "daemon.h"
#include "log.h"

struct nl_sock *bp_genl_socket_create(Daemon *daemon) {
    struct nl_sock *sk;
    int family_id;
    int err;

    sk = nl_socket_alloc();
    if (!sk) {
        log_error("Failed to allocate Netlink socket: %s", nl_geterror(-ENOMEM));
        return NULL;
    }

    nl_socket_set_local_port(sk, daemon->nl_pid);
    nl_socket_disable_seq_check(sk);
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, bp_genl_message_handler, daemon);
    nl_socket_set_peer_port(sk, 0); // Send to kernel

    err = genl_connect(sk);
    if (err < 0) {
        log_error("Failed to connect to Generic Netlink: %s", nl_geterror(err));
        nl_socket_free(sk);
        return NULL;
    }

    family_id = genl_ctrl_resolve(sk, daemon->genl_bp_family_name);
    if (family_id < 0) {
        log_error("Failed to resolve Generic Netlink family '%s': %s", daemon->genl_bp_family_name,
                  nl_geterror(family_id));
        nl_socket_free(sk);
        return NULL;
    }

    daemon->genl_bp_family_id = family_id;
    return sk;
}

void bp_genl_socket_destroy(Daemon *daemon) {
    if (!daemon->genl_bp_sock) return;

    nl_socket_free(daemon->genl_bp_sock);
    daemon->genl_bp_sock = NULL;
    daemon->genl_bp_family_id = -1;

    log_info("Generic Netlink socket closed");
}

int bp_genl_message_handler(struct nl_msg *msg, void *arg) {
    Daemon *daemon = (Daemon *)arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = nlmsg_data(nlh);
    struct nlattr *attrs[BP_GENL_A_MAX + 1];
    int err;

    err = nla_parse(attrs, BP_GENL_A_MAX, genlmsg_attrdata(genlhdr, 0), genlmsg_attrlen(genlhdr, 0),
                    NULL);
    if (err < 0) {
        log_error("Failed to parse Netlink attributes: %s", nl_geterror(err));
        return NL_SKIP;
    }

    switch (genlhdr->cmd) {
    case BP_GENL_CMD_SEND_BUNDLE:
        return handle_send_bundle(daemon, attrs);
    case BP_GENL_CMD_OPEN_ENDPOINT:
        return handle_open_endpoint(daemon, attrs);
    case BP_GENL_CMD_CLOSE_ENDPOINT:
        return handle_close_endpoint(daemon, attrs);
    case BP_GENL_CMD_DESTROY_BUNDLE:
        return handle_destroy_bundle(daemon, attrs);
    default:
        log_error("Unknown Generic Netlink command: %d", genlhdr->cmd);
        return NL_SKIP;
    }
}

int bp_genl_enqueue_bundle(int netlink_family, struct nl_sock *netlink_sock, pthread_mutex_t *netlink_mutex,
                           void *payload, size_t payload_size, uint32_t src_node_id,
                           uint32_t src_service_id, uint32_t dest_node_id, uint32_t dest_service_id,
                           uint64_t adu) {
    if (payload_size > (size_t)INT_MAX) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: payload too large", dest_node_id,
                  dest_service_id);
        return -EMSGSIZE;
    }
    struct nl_msg *msg = NULL;
    void *hdr;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed to allocate Netlink msg",
                  dest_node_id, dest_service_id);
        ret = -ENOMEM;
        goto out;
    }

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0,
                      BP_GENL_CMD_ENQUEUE_BUNDLE, BP_GENL_VERSION);
    if (!hdr) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed to create Netlink header",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, dest_node_id) < 0) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed to add NODE_ID attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, dest_service_id) < 0) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed to add SERVICE_ID attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_NODE_ID, src_node_id) < 0) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed to add SRC_NODE_ID attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_SERVICE_ID, src_service_id) < 0) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed to add SRC_SERVICE_ID attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put(msg, BP_GENL_A_PAYLOAD, (int)payload_size, payload) < 0) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed to add PAYLOAD attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u64(msg, BP_GENL_A_ADU, adu) < 0) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: failed to add ADU attribute", dest_node_id,
                  dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (pthread_mutex_lock(netlink_mutex) != 0) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: mutex lock failed", dest_node_id,
                  dest_service_id);
        ret = -EAGAIN;
        goto err_free_msg;
    }

    ret = nl_send_sync(netlink_sock, msg);
    pthread_mutex_unlock(netlink_mutex);

    if (ret < 0) {
        log_error("[ipn:%u.%u] bp_genl_enqueue_bundle: enqueue bundle not sent", dest_node_id,
                  dest_service_id);
        ret = -errno;
        goto out;
    }

    return 0;

err_free_msg:
    nlmsg_free(msg);
out:
    return ret;
}
