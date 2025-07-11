#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <stdlib.h>
#include <string.h>

#include "../include/bp_socket.h"
#include "bp_genl.h"
#include "bp_genl_handlers.h"
#include "daemon.h"
#include "log.h"

struct nl_sock *genl_bp_sock_init(Daemon *daemon) {
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
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, genl_bp_sock_recvmsg_cb, daemon);
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

void genl_bp_sock_close(Daemon *daemon) {
    if (!daemon->genl_bp_sock) return;

    nl_socket_free(daemon->genl_bp_sock);
    daemon->genl_bp_sock = NULL;
    daemon->genl_bp_family_id = -1;

    log_info("Generic Netlink socket closed");
}

int genl_bp_sock_recvmsg_cb(struct nl_msg *msg, void *arg) {
    Daemon *daemon = (Daemon *)arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = nlmsg_data(nlh);
    struct nlattr *attrs[BP_GENL_A_MAX + 1];
    int err;

    err = nla_parse(attrs, BP_GENL_A_MAX, genlmsg_attrdata(genlhdr, 0), genlmsg_attrlen(genlhdr, 0),
                    NULL);
    if (err < 0) {
        log_error("Failed to parse Netlink attributes: %s", strerror(-err));
        return NL_SKIP;
    }

    switch (genlhdr->cmd) {
    case BP_GENL_CMD_SEND_BUNDLE:
        return handle_send_bundle(daemon, attrs);
    case BP_GENL_CMD_REQUEST_BUNDLE:
        return handle_request_bundle(daemon, attrs);
    // case BP_GENL_CMD_DELIVER_BUNDLE:
    //     return handle_deliver_bundle_reply(daemon, attrs);
    case BP_GENL_CMD_DESTROY_BUNDLE:
        return handle_destroy_bundle(daemon, attrs);
    default:
        log_error("Unknown Generic Netlink command: %d", genlhdr->cmd);
        return NL_SKIP;
    }
}
