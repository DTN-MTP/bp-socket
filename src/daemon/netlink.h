#ifndef NETLINK_H
#define NETLINK_H

#include "daemon.h"

struct nl_sock *nl_connect_and_configure(tls_daemon_ctx_t *ctx);
int nl_disconnect(struct nl_sock *sock);
void nl_recvmsg(evutil_socket_t fd, short events, void *arg);
int nl_recvmsg_cb(struct nl_msg *msg, void *arg);
int nl_reply_bundle(struct nl_sock *netlink_sock, int netlink_family, unsigned int agent_id, char *payload);
void *start_bp_recv_agent(void *arg);

#endif
