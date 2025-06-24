#ifndef BP_GENL_H
#define BP_GENL_H

#include "daemon.h"

struct thread_args
{
    struct nl_sock *netlink_sock;
    int netlink_family;
    unsigned int agent_id;
};

struct nl_sock *genl_bp_sock_init(Daemon *daemon);
void genl_bp_sock_close(Daemon *daemon);
int genl_bp_sock_sendmsg(Daemon *self, void *payload, size_t len);
int genl_bp_sock_recvmsg(Daemon *self, void *payload, size_t len);
int genl_bp_sock_recvmsg_cb(struct nl_msg *msg, void *arg);

int nl_reply_bundle(struct nl_sock *netlink_sock, int netlink_family, unsigned int agent_id, char *payload);
void *start_bp_recv_agent(void *arg);

#endif
