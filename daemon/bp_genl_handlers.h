#ifndef BP_GENL_HANDLERS_H
#define BP_GENL_HANDLERS_H

#include "daemon.h"

struct thread_args {
    struct nl_sock *netlink_sock;
    int netlink_family;
    unsigned int service_id;
    Sdr sdr;
};

int handle_open_endpoint(Daemon *daemon, struct nlattr **attrs);
int handle_close_endpoint(Daemon *daemon, struct nlattr **attrs);
int handle_abort_endpoint(Daemon *daemon, struct nlattr **attrs);
int handle_send_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_request_bundle(Daemon *daemon, struct nlattr **attrs);
int handle_deliver_bundle(char *payload, int payload_size, struct thread_args *args);

void *handle_recv_thread(void *arg);

#endif