#ifndef BP_GENL_HANDLERS_H
#define BP_GENL_HANDLERS_H

#include "bp.h"
#include "daemon.h"

struct thread_args {
    struct nl_sock *netlink_sock;
    int netlink_family;
    u_int32_t node_id;
    u_int32_t service_id;
    Sdr sdr;
};

int handle_send_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_request_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_cancel_bundle_request(int netlink_family, struct nl_sock *netlink_sock,
                                 u_int32_t node_id, u_int32_t service_id);
int handle_deliver_bundle(int netlink_family, struct nl_sock *netlink_sock, void *payload,
                          int payload_size, u_int32_t src_node_id, u_int32_t src_service_id,
                          u_int32_t dest_node_id, u_int32_t dest_service_id);
int handle_destroy_bundle(Daemon *daemon, struct nlattr **attrs);

void *handle_recv_thread(struct thread_args *arg);

#endif