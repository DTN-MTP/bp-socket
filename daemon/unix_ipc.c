#include "unix_ipc.h"
#include "../include/bp_ipc.h"
#include "endpoint_registry.h"
#include "ion.h"
#include "log.h"
#include <event2/event.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_CLIENTS 64

static int client_fds[MAX_CLIENTS];
static int client_count = 0;

struct client_ctx {
    struct event *ev;
};

static void on_hook_message(evutil_socket_t fd, short what, void *arg) {
    (void)what;
    struct client_ctx *ctx = arg;
    bp_ipc_msg_t msg;
    bp_ipc_response_t resp;

    if (read(fd, &msg, sizeof(msg)) <= 0) {
        log_error("unix_ipc: client disconnected fd=%d", fd);
        event_del(ctx->ev);
        event_free(ctx->ev);
        free(ctx);
        close(fd);
        return;
    }

    switch (msg.cmd) {

    case BP_IPC_OPEN_ENDPOINT:
        log_info("unix_ipc: OPEN_ENDPOINT ipn:%u.%u", msg.src_node_id, msg.src_service_id);
        if (endpoint_registry_exists(msg.src_node_id, msg.src_service_id)) {
        resp.status = BP_IPC_OK;
        } else if (ion_open_endpoint(msg.src_node_id, msg.src_service_id) == 0) {
        resp.status = BP_IPC_OK;
        } else {
        resp.status = BP_IPC_ERR;
        }
        break;

    case BP_IPC_CLOSE_ENDPOINT:
        log_info("unix_ipc: CLOSE_ENDPOINT ipn:%u.%u", msg.src_node_id, msg.src_service_id);
        if (ion_close_endpoint(msg.src_node_id, msg.src_service_id) == 0)
            resp.status = BP_IPC_OK;
        else
            resp.status = BP_IPC_ERR;
        break;

    case BP_IPC_SEND_BUNDLE: {
        log_info("unix_ipc: SEND_BUNDLE ipn:%u.%u -> ipn:%u.%u", msg.src_node_id,
                 msg.src_service_id, msg.dst_node_id, msg.dst_service_id);

        void *payload = malloc(msg.payload_len);
        if (!payload) {
            resp.status = BP_IPC_ERR;
            break;
        }

        read(fd, payload, msg.payload_len);

        char dest_eid[64];
        snprintf(dest_eid, sizeof(dest_eid), "ipn:%u.%u", msg.dst_node_id, msg.dst_service_id);

        if (endpoint_registry_enqueue_send(msg.src_node_id, msg.src_service_id, dest_eid, payload,
                                           msg.payload_len, msg.flags) == 0)
            resp.status = BP_IPC_OK;
        else
            resp.status = BP_IPC_ERR;

        free(payload);
        break;
    }

    default:
        log_error("unix_ipc: unknown command %d", msg.cmd);
        resp.status = BP_IPC_ERR;
        break;
    }

    write(fd, &resp, sizeof(resp));
}

static void on_hook_connect(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    Daemon *daemon = arg;

    int client_fd = accept(fd, NULL, NULL);
    if (client_fd < 0) {
        log_error("unix_ipc: accept failed");
        return;
    }

    if (client_count < MAX_CLIENTS)
        client_fds[client_count++] = client_fd;

    log_info("unix_ipc: client connected fd=%d", client_fd);

    struct client_ctx *ctx = malloc(sizeof(struct client_ctx));
    ctx->ev = event_new(daemon->base, client_fd,
                        EV_READ | EV_PERSIST,
                        on_hook_message, ctx);
    event_add(ctx->ev, NULL);
}
int unix_ipc_init(Daemon *daemon) {
    struct sockaddr_un addr;

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        log_error("unix_ipc: failed to create socket");
        return -1;
    }

    unlink(BP_IPC_SOCKET_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BP_IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("unix_ipc: bind failed");
        return -1;
    }

    if (listen(sock_fd, 10) < 0) {
        log_error("unix_ipc: listen failed");
        return -1;
    }

    struct event *ev =
        event_new(daemon->base, sock_fd, EV_READ | EV_PERSIST, on_hook_connect, daemon);
    event_add(ev, NULL);

    log_info("unix_ipc: listening on %s", BP_IPC_SOCKET_PATH);
    return 0;
}

int unix_ipc_send_bundle(void *payload, size_t payload_size, uint32_t src_node_id,
                         uint32_t src_service_id, uint32_t dst_node_id, uint32_t dst_service_id,
                         uint64_t adu) {
    (void)adu;

    bp_ipc_msg_t msg = {
        .cmd = BP_IPC_RECV_BUNDLE,
        .src_node_id = src_node_id,
        .src_service_id = src_service_id,
        .dst_node_id = dst_node_id,
        .dst_service_id = dst_service_id,
        .flags = 0,
        .payload_len = (uint32_t)payload_size,
    };

    for (int i = 0; i < client_count; i++) {
        write(client_fds[i], &msg, sizeof(msg));
        write(client_fds[i], payload, payload_size);
    }

    return 0;
}