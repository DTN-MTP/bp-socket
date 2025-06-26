#include "daemon.h"
#include "bp.h"
#include "bp_genl.h"
#include "log.h"
#include <event2/event.h>
#include <event2/util.h>
#include <netlink/genl/genl.h>

void on_sigint(evutil_socket_t fd, short what, void *arg) {
    struct event_base *base = arg;
    log_info("SIGINT received, exiting...");
    event_base_loopexit(base, NULL);
}

void on_sigpipe(evutil_socket_t fd, short what, void *arg) {
    struct event_base *base = arg;
    log_info("SIGINT received, exiting...");
    event_base_loopexit(base, NULL);
}

void on_netlink(int fd, short event, void *arg) {
    Daemon *daemon = (Daemon *)arg;
    nl_recvmsgs_default(
        daemon->genl_bp_sock); // call the callback registered with genl_bp_sock_recvmsg_cb()
}

int daemon_start(Daemon *self) {
    int ret;

    self->base = event_base_new();
    log_info("Using libevent version %s with %s behind the scenes", (char *)event_get_version(),
             (char *)event_base_get_method(self->base));

    self->event_on_sigint = evsignal_new(self->base, SIGINT, on_sigint, self->base);
    event_add(self->event_on_sigint, NULL);

    self->event_on_sigpipe = evsignal_new(self->base, SIGPIPE, on_sigpipe, self->base);
    event_add(self->event_on_sigpipe, NULL);

    self->genl_bp_sock = genl_bp_sock_init(self);
    if (!self->genl_bp_sock) {
        log_error("Failed to initialize Generic Netlink socket");
        daemon_free(self);
        return 1;
    }
    log_info("Generic Netlink: GENL_BP open socket");

    int genl_bp_sock_fd = nl_socket_get_fd(self->genl_bp_sock);
    self->event_on_nl_sock =
        event_new(self->base, genl_bp_sock_fd, EV_READ | EV_PERSIST, on_netlink, self);
    if (event_add(self->event_on_nl_sock, NULL) == -1) {
        log_error("Couldn't add Netlink event");
        daemon_free(self);
        return 1;
    }

    ret = evutil_make_socket_nonblocking(genl_bp_sock_fd);
    if (ret == -1) {
        log_error("Failed in evutil_make_socket_nonblocking: %s",
                  evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        daemon_free(self);
        return 1;
    }

    log_info("Attempting to attach to ION...");
    if (bp_attach() < 0) {
        log_error("Can't attach to BP");
        daemon_free(self);
        return 1;
    }
    log_info("Successfully attached to ION");

    log_info("Daemon started successfully");
    event_base_dispatch(self->base);
    log_info("Daemon terminated");

    daemon_free(self);

    return 0;
}

void daemon_free(Daemon *self) {
    if (!self) return;

    genl_bp_sock_close(self);

    if (self->event_on_nl_sock) event_free(self->event_on_nl_sock);
    if (self->event_on_sigpipe) event_free(self->event_on_sigpipe);
    if (self->event_on_sigint) event_free(self->event_on_sigint);
    if (self->base) event_base_free(self->base);

#if LIBEVENT_VERSION_NUMBER >= 0x02010000
    libevent_global_shutdown();
#endif
}