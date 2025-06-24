#ifndef BP_GENL_HANDLERS_H
#define BP_GENL_HANDLERS_H

#include "daemon.h"

struct thread_args
{
    struct nl_sock *netlink_sock;
    int netlink_family;
    unsigned int service_id;
};

int handle_send_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_request_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_deliver_bundle(struct thread_args *args);
void *bp_recv_thread(void *arg);

#endif