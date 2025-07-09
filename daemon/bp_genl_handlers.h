#ifndef BP_GENL_HANDLERS_H
#define BP_GENL_HANDLERS_H

#include "bp.h"
#include "daemon.h"

struct thread_args {
    struct nl_sock *netlink_sock;
    int netlink_family;
    unsigned int service_id;
    Sdr sdr;
};

int handle_send_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_request_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_deliver_bundle(char *payload, int payload_size, struct thread_args *args);

void *handle_recv_thread(void *arg);

#endif