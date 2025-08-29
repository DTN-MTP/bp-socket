#ifndef BP_GENL_HANDLERS_H
#define BP_GENL_HANDLERS_H

#include "bp.h"
#include "daemon.h"

struct thread_args {
    struct nl_sock *netlink_sock;
    int netlink_family;
    u_int32_t node_id;
    u_int32_t service_id;
};

int handle_send_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_request_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_open_endpoint(Daemon *daemon, struct nlattr **attrs);
int handle_close_endpoint(Daemon *daemon, struct nlattr **attrs);
int handle_destroy_bundle(Daemon *daemon, struct nlattr **attrs);

void *handle_recv_thread(struct thread_args *arg);

#endif