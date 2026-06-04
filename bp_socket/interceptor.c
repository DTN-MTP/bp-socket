#define _GNU_SOURCE
#include "bp_ipc.h"
#include "bp_socket.h"
#include "fd_table.h"
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int (*real_socket)(int, int, int) = NULL;
static int (*real_close)(int) = NULL;
static int (*real_bind)(int, const struct sockaddr*, socklen_t) = NULL;
static ssize_t (*real_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t) = NULL;

static void __attribute__((constructor)) init()
{
	real_socket = dlsym(RTLD_NEXT, "socket");
	real_close = dlsym(RTLD_NEXT, "close");
	real_bind = dlsym(RTLD_NEXT, "bind");
	real_sendto = dlsym(RTLD_NEXT, "sendto");
}

static int connect_to_daemon()
{
	struct sockaddr_un addr;
	int fd = real_socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, BP_IPC_SOCKET_PATH, sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		real_close(fd);
		return -1;
	}
	return fd;
}

int socket(int domain, int type, int protocol)
{
    if (domain != AF_BP)
        return real_socket(domain, type, protocol);

    int unix_fd = connect_to_daemon();
    if (unix_fd < 0) {
        return -1;
    }

    fd_table_add(unix_fd, unix_fd, 0, 0);
    return unix_fd;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!is_bp_fd(sockfd))
        return real_bind(sockfd, addr, addrlen);

    struct sockaddr_bp *bp_addr = (struct sockaddr_bp *)addr;
    bp_fd_entry_t *entry        = fd_table_get(sockfd);

    entry->node_id    = bp_addr->bp_addr.ipn.node_id;
    entry->service_id = bp_addr->bp_addr.ipn.service_id;

    bp_ipc_msg_t msg = {
        .cmd            = BP_IPC_OPEN_ENDPOINT,
        .src_node_id    = entry->node_id,
        .src_service_id = entry->service_id,
        .payload_len    = 0,
    };
    write(entry->unix_fd, &msg, sizeof(msg));

    bp_ipc_response_t resp;
    read(entry->unix_fd, &resp, sizeof(resp));

    if (resp.status == BP_IPC_OK)
        return 0;

    return -1;
}

int close(int fd)
{
    if (!is_bp_fd(fd))
        return real_close(fd);

    bp_fd_entry_t *entry = fd_table_get(fd);

    bp_ipc_msg_t msg = {
        .cmd            = BP_IPC_CLOSE_ENDPOINT,
        .src_node_id    = entry->node_id,
        .src_service_id = entry->service_id,
        .payload_len    = 0,
    };
    write(entry->unix_fd, &msg, sizeof(msg));

    bp_ipc_response_t resp;
    read(entry->unix_fd, &resp, sizeof(resp));

    fd_table_remove(fd);
    real_close(fd);

    return 0;
}

ssize_t sendto(int sockfd, const void* buf, size_t len, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen)
{
	if (!is_bp_fd(sockfd))
		return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);

	struct sockaddr_bp* bp_dest = (struct sockaddr_bp*)dest_addr;
	bp_fd_entry_t* entry = fd_table_get(sockfd);

	bp_ipc_msg_t msg = {
		.cmd = BP_IPC_SEND_BUNDLE,
		.src_node_id = entry->node_id,
		.src_service_id = entry->service_id,
		.dst_node_id = bp_dest->bp_addr.ipn.node_id,
		.dst_service_id = bp_dest->bp_addr.ipn.service_id,
		.flags = (uint32_t)flags,
		.payload_len = (uint32_t)len,
	};
	write(entry->unix_fd, &msg, sizeof(msg));
	write(entry->unix_fd, buf, len);

	bp_ipc_response_t resp;
	read(entry->unix_fd, &resp, sizeof(resp));

	if (resp.status == BP_IPC_OK)
		return (ssize_t)len;

	return -1;
}