#include "daemon.h"
#include "unix_ipc.h"
#include "endpoint_registry.h"
#include "ion.h"
#include "log.h"
#include <bp.h>
#include <event2/event.h>
#include <event2/util.h>

void on_sigint(evutil_socket_t fd, short event, void *arg) {
    (void)fd;
    (void)event;
    struct event_base *base = arg;
    log_info("SIGINT received, exiting...");
    event_base_loopexit(base, NULL);
}

void on_sigpipe(evutil_socket_t fd, short event, void *arg) {
    (void)fd;
    (void)event;
    struct event_base *base = arg;
    log_info("SIGPIPE received, exiting...");
    event_base_loopexit(base, NULL);
}

int daemon_run(Daemon *self) {
    int ret;
    self->base = event_base_new();
    if (!self->base) {
        log_error("Failed to create libevent base");
        return -ENOMEM;
    }

    log_debug("Using libevent version %s with %s behind the scenes",
              (char *)event_get_version(),
              (char *)event_base_get_method(self->base));

    self->event_on_sigint = evsignal_new(self->base, SIGINT, on_sigint, self->base);
    if (!self->event_on_sigint) {
        log_error("Couldn't create SIGINT event");
        daemon_free(self);
        return -ENOMEM;
    }
    ret = event_add(self->event_on_sigint, NULL);
    if (ret < 0) {
        log_error("Couldn't add SIGINT event");
        daemon_free(self);
        return ret;
    }

    self->event_on_sigpipe = evsignal_new(self->base, SIGPIPE, on_sigpipe, self->base);
    if (!self->event_on_sigpipe) {
        log_error("Couldn't create SIGPIPE event");
        daemon_free(self);
        return -ENOMEM;
    }
    ret = event_add(self->event_on_sigpipe, NULL);
    if (ret < 0) {
        log_error("Couldn't add SIGPIPE event");
        daemon_free(self);
        return ret;
    }

    if (bp_attach() < 0) {
        log_error("Can't attach to BP");
        daemon_free(self);
        return -EAGAIN;
    }
    sdr = bp_get_sdr();

    if (unix_ipc_init(self) < 0) {
        log_error("Failed to initialize Unix socket listener");
        daemon_free(self);
        return -1;
    }

    log_info("Daemon started successfully - attached to ION, Unix IPC ready");
    event_base_dispatch(self->base);
    log_info("Daemon terminated");
    daemon_free(self);
    bp_detach();
    return 0;
}

void daemon_free(Daemon *self) {
    if (!self) return;
    if (self->event_on_sigpipe) event_free(self->event_on_sigpipe);
    if (self->event_on_sigint) event_free(self->event_on_sigint);
    if (self->base) event_base_free(self->base);
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
    libevent_global_shutdown();
#endif
}