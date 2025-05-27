#ifndef DAEMON_H
#define DAEMON_H

#include <netinet/in.h>
#include <event2/event.h>
#include <event2/util.h>
#include "hashmap.h"
#include "bp.h"

#define MAX_HOSTNAME 255

typedef struct tls_daemon_ctx
{
	struct event_base *base;
	struct nl_sock *netlink_sock;
	int netlink_family;
	int port; /* Port to use for both listening and netlink */
	hmap_t *sock_map;
	hmap_t *sock_map_port;
} tls_daemon_ctx_t;

typedef struct sock_ctx
{
	unsigned long id;
	evutil_socket_t fd;
	int has_bound; /* Nonzero if we've called bind locally */
	struct sockaddr int_addr;
	int int_addrlen;
	union
	{
		struct sockaddr ext_addr;
		struct sockaddr rem_addr;
	};
	union
	{
		int ext_addrlen;
		int rem_addrlen;
	};
	int is_connected;
	int is_accepting; /* acting as a TLS server or client? */
	struct evconnlistener *listener;
	char rem_hostname[MAX_HOSTNAME];
	tls_daemon_ctx_t *daemon;
} sock_ctx_t;

int bp_send_cb(tls_daemon_ctx_t *ctx, char *payload, int payload_size, char *eid, int eid_size);
void signal_cb(evutil_socket_t fd, short event, void *arg);
evutil_socket_t create_server_socket(ev_uint16_t port, int family, int protocol);
void free_sock_ctx(sock_ctx_t *sock_ctx);
int mainloop(int port);

#endif
