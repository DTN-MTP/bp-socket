#ifndef DAEMON_H
#define DAEMON_H

#include "bp.h"
#include <event2/event.h>
#include <netlink/socket.h>

typedef struct Daemon {
    struct nl_sock *genl_bp_sock;
    const char *genl_bp_family_name;
    int genl_bp_family_id;
    unsigned int nl_pid;

    struct event_base *base;
    struct event *event_on_sigpipe;
    struct event *event_on_sigint;
    struct event *event_on_nl_sock;
} Daemon;

void on_sigint(evutil_socket_t fd, short what, void *arg);
void on_sigpipe(evutil_socket_t fd, short what, void *arg);
void on_netlink(evutil_socket_t fd, short what, void *arg);

int daemon_run(Daemon *self);
void daemon_free(Daemon *self);

#endif
