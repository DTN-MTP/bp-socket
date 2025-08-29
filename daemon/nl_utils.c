#include "nl_utils.h"
#include <errno.h>
#include <limits.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <stdlib.h>

#include "../include/bp_socket.h"
#include "log.h"

int nl_send_cancel_bundle_request(int netlink_family, struct nl_sock *netlink_sock,
                                  uint32_t node_id, uint32_t service_id) {
    struct nl_msg *msg = NULL;
    void *hdr;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        log_error("[ipn:%u.%u] nl_send_cancel_bundle_request: failed to allocate Netlink msg",
                  node_id, service_id);
        ret = -ENOMEM;
        goto out;
    }

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0,
                      BP_GENL_CMD_CANCEL_BUNDLE_REQUEST, BP_GENL_VERSION);
    if (!hdr) {
        log_error("[ipn:%u.%u] nl_send_cancel_bundle_request: failed to create Netlink header",
                  node_id, service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, node_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_cancel_bundle_request: failed to add NODE_ID attribute",
                  node_id, service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, service_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_cancel_bundle_request: failed to add SERVICE_ID attribute",
                  node_id, service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    ret = nl_send_sync(netlink_sock, msg);
    if (ret < 0) {
        log_error("[ipn:%u.%u] nl_send_cancel_bundle_request: bundle request not cancelled",
                  node_id, service_id);
        ret = -errno;
        goto out;
    }

    return 0;

err_free_msg:
    nlmsg_free(msg);
out:
    return ret;
}

int nl_send_deliver_bundle(int netlink_family, struct nl_sock *netlink_sock, void *payload,
                           size_t payload_size, uint32_t src_node_id, uint32_t src_service_id,
                           uint32_t dest_node_id, uint32_t dest_service_id) {
    if (payload_size > (size_t)INT_MAX) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: payload too large", dest_node_id,
                  dest_service_id);
        return -EMSGSIZE;
    }
    struct nl_msg *msg = NULL;
    void *hdr;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: failed to allocate Netlink msg",
                  dest_node_id, dest_service_id);
        ret = -ENOMEM;
        goto out;
    }

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0,
                      BP_GENL_CMD_DELIVER_BUNDLE, BP_GENL_VERSION);
    if (!hdr) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: failed to create Netlink header",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, dest_node_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: failed to add NODE_ID attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, dest_service_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: failed to add SERVICE_ID attribute",
                  dest_node_id, dest_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_NODE_ID, src_node_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: failed to add SRC_NODE_ID attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_SERVICE_ID, src_service_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: failed to add SRC_SERVICE_ID attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put(msg, BP_GENL_A_PAYLOAD, (int)payload_size, payload) < 0) {
        log_error("[ipn:%u.%u] nl_send_deliver_bundle: failed to add PAYLOAD attribute",
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

int nl_send_bundle_confirmation(int netlink_family, struct nl_sock *netlink_sock,
                                uint32_t src_node_id, uint32_t src_service_id) {
    struct nl_msg *msg = NULL;
    void *hdr;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        log_error("[ipn:%u.%u] nl_send_bundle_confirmation: failed to allocate Netlink msg",
                  src_node_id, src_service_id);
        ret = -ENOMEM;
        goto out;
    }

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0,
                      BP_GENL_CMD_SEND_BUNDLE_CONFIRMATION, BP_GENL_VERSION);
    if (!hdr) {
        log_error("[ipn:%u.%u] nl_send_bundle_confirmation: failed to create Netlink header",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_NODE_ID, src_node_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_bundle_confirmation: failed to add SRC_NODE_ID attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_SERVICE_ID, src_service_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_bundle_confirmation: failed to add SRC_SERVICE_ID attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    ret = nl_send_sync(netlink_sock, msg);
    if (ret < 0) {
        log_error("[ipn:%u.%u] nl_send_bundle_confirmation: confirmation not sent", src_node_id,
                  src_service_id);
        ret = -errno;
        goto out;
    }

    return 0;

err_free_msg:
    nlmsg_free(msg);
out:
    return ret;
}

int nl_send_bundle_failure(int netlink_family, struct nl_sock *netlink_sock, uint32_t src_node_id,
                           uint32_t src_service_id, int error_code) {
    struct nl_msg *msg = NULL;
    void *hdr;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        log_error("[ipn:%u.%u] nl_send_bundle_failure: failed to allocate Netlink msg", src_node_id,
                  src_service_id);
        ret = -ENOMEM;
        goto out;
    }

    hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0,
                      BP_GENL_CMD_SEND_BUNDLE_FAILURE, BP_GENL_VERSION);
    if (!hdr) {
        log_error("[ipn:%u.%u] nl_send_bundle_failure: failed to create Netlink header",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_NODE_ID, src_node_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_bundle_failure: failed to add SRC_NODE_ID attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_SRC_SERVICE_ID, src_service_id) < 0) {
        log_error("[ipn:%u.%u] nl_send_bundle_failure: failed to add SRC_SERVICE_ID attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    if (nla_put_u32(msg, BP_GENL_A_ERROR_CODE, (uint32_t)error_code) < 0) {
        log_error("[ipn:%u.%u] nl_send_bundle_failure: failed to add ERROR_CODE attribute",
                  src_node_id, src_service_id);
        ret = -EMSGSIZE;
        goto err_free_msg;
    }

    ret = nl_send_sync(netlink_sock, msg);
    if (ret < 0) {
        log_error("[ipn:%u.%u] nl_send_bundle_failure: failure notification not sent", src_node_id,
                  src_service_id);
        ret = -errno;
        goto out;
    }

    return 0;

err_free_msg:
    nlmsg_free(msg);
out:
    return ret;
}
