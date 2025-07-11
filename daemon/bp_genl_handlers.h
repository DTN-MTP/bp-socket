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
int handle_deliver_bundle(void *payload, int payload_size, struct thread_args *args);
int handle_destroy_bundle(Daemon *daemon, struct nlattr **attrs);

void *handle_recv_thread(struct thread_args *arg);

#endif