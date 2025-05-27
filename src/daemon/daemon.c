#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <assert.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "daemon.h"
#include "hashmap.h"
#include "netlink.h"
#include "log.h"
#include "bp.h"
#include "../include/bp.h"

#define HASHMAP_NUM_BUCKETS 100

int mainloop(int port)
{
	int ret;
	// evutil_socket_t server_sock;
	// struct evconnlistener* listener;
	struct event_base *base;
	struct event *event_on_sigpipe, *event_on_sigint, *event_on_nl_sock;
	struct nl_sock *netlink_sock;
#ifndef NO_LOG
	const char *ev_version = event_get_version();
#endif

	base = event_base_new();
	log_printf(LOG_INFO, "Using libevent version %s with %s behind the scenes\n", ev_version, event_base_get_method(base));

	event_on_sigpipe = evsignal_new(base, SIGPIPE, signal_cb, NULL);
	event_on_sigint = evsignal_new(base, SIGINT, signal_cb, base);

	evsignal_add(event_on_sigpipe, NULL);
	evsignal_add(event_on_sigint, NULL);

	tls_daemon_ctx_t daemon_ctx = {
		.base = base,
		.netlink_sock = NULL,
		.port = port,
		.sock_map = hashmap_create(HASHMAP_NUM_BUCKETS),
		.sock_map_port = hashmap_create(HASHMAP_NUM_BUCKETS),
	};

	/* Set up server socket with event base */
	// server_sock =
	create_server_socket(port, PF_INET, SOCK_STREAM);
	// listener = evconnlistener_new(base, accept_cb, &daemon_ctx,
	// 	LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, server_sock);
	// if (listener == NULL) {
	// 	log_printf(LOG_ERROR, "Couldn't create evconnlistener\n");
	// 	return 1;
	// }
	// evconnlistener_set_error_cb(listener, accept_error_cb);

	/* Set up netlink socket with event base */
	netlink_sock = nl_connect_and_configure(&daemon_ctx);
	if (netlink_sock == NULL)
	{
		log_printf(LOG_ERROR, "Couldn't create Netlink socket\n");
		return 1;
	}
	ret = evutil_make_socket_nonblocking(nl_socket_get_fd(netlink_sock));
	if (ret == -1)
	{
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
				   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	}
	event_on_nl_sock = event_new(base, nl_socket_get_fd(netlink_sock), EV_READ | EV_PERSIST, nl_recvmsg, netlink_sock);
	if (event_add(event_on_nl_sock, NULL) == -1)
	{
		log_printf(LOG_ERROR, "Couldn't add Netlink event\n");
		return 1;
	}

	log_printf(LOG_INFO, "Attach to ION.\n");
	if (bp_attach() < 0)
	{
		log_printf(LOG_ERROR, "Can't attach to BP.\n");
		/* user inser error handling code */
		return 1;
	}

	log_printf(LOG_INFO, "Main event loop started\n");

	/* Main event loop */
	event_base_dispatch(base);
	log_printf(LOG_INFO, "Main event loop terminated\n");
	nl_socket_free(netlink_sock);

	/* Cleanup */
	// evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */
	hashmap_free(daemon_ctx.sock_map_port);
	hashmap_deep_free(daemon_ctx.sock_map, (void (*)(void *))free_sock_ctx);
	event_free(event_on_nl_sock);
	event_free(event_on_sigpipe);
	event_free(event_on_sigint);
	event_base_free(base);
/* This function hushes the wails of memory leak
 * testing utilities, but was not introduced until
 * libevent 2.1
 */
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	libevent_global_shutdown();
#endif

	return 0;
}

/* Creates a listening socket that binds to local IPv4 and IPv6 interfaces.
 * It also makes the socket nonblocking (since this software uses libevent)
 * @param port numeric port for listening
 * @param type SOCK_STREAM or SOCK_DGRAM
 */
evutil_socket_t create_server_socket(ev_uint16_t port, int family, int type)
{
	evutil_socket_t sock;
	char port_buf[6];
	int ret;

	struct evutil_addrinfo hints;
	struct evutil_addrinfo *addr_ptr;
	struct evutil_addrinfo *addr_list;
	struct sockaddr_un bind_addr = {
		.sun_family = AF_UNIX,
	};

	/* Convert port to string for getaddrinfo */
	evutil_snprintf(port_buf, sizeof(port_buf), "%d", (int)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = type;

	if (family == PF_UNIX)
	{
		sock = socket(AF_UNIX, type, 0);
		if (sock == -1)
		{
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
					   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
					   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		strcpy(bind_addr.sun_path + 1, port_buf);
		ret = bind(sock, (struct sockaddr *)&bind_addr, sizeof(sa_family_t) + 1 + strlen(port_buf));
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}
		return sock;
	}

	/* AI_PASSIVE for filtering out addresses on which we
	 * can't use for servers
	 *
	 * AI_ADDRCONFIG to filter out address types the system
	 * does not support
	 *
	 * AI_NUMERICSERV to indicate port parameter is a number
	 * and not a string
	 *
	 * */
	hints.ai_flags = EVUTIL_AI_PASSIVE | EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_NUMERICSERV;
	/*
	 *  On Linux binding to :: also binds to 0.0.0.0
	 *  Null is fine for TCP, but UDP needs both
	 *  See https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
	 */
	ret = evutil_getaddrinfo(type == SOCK_DGRAM ? "::" : NULL, port_buf, &hints, &addr_list);
	if (ret != 0)
	{
		log_printf(LOG_ERROR, "Failed in evutil_getaddrinfo: %s\n", evutil_gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next)
	{
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1)
		{
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			continue;
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
					   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
					   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = bind(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}
		break;
	}
	evutil_freeaddrinfo(addr_list);
	if (addr_ptr == NULL)
	{
		log_printf(LOG_ERROR, "Failed to find a suitable address for binding\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

int bp_send_cb(tls_daemon_ctx_t *ctx, char *payload, int payload_size, char *eid, int eid_size)
{
	Sdr sdr;
	Object bundlePayload;
	Object bundleZco;

	sdr = bp_get_sdr();
	if (sdr == NULL)
	{
		puts("*** Failed to get sdr.");
		return 0;
	}
	oK(sdr_begin_xn(sdr));
	bundlePayload = sdr_string_create(sdr, payload);
	if (bundlePayload == 0)
	{
		sdr_end_xn(sdr);
		putErrmsg("No text object.", NULL);
		return 0;
	}

	bundleZco = zco_create(sdr, ZcoSdrSource, bundlePayload, 0,
						   payload_size, ZcoOutbound);
	if (bundleZco == 0 || bundleZco == (Object)ERROR)
	{
		sdr_end_xn(sdr);
		putErrmsg("No text object.", NULL);
		return 0;
	}

	if (bp_send(NULL, eid, NULL, 86400, BP_STD_PRIORITY, 0, 0, 0, NULL,
				bundleZco, NULL) <= 0)
	{
		sdr_end_xn(sdr);
		putErrmsg("No text object.", NULL);
		putErrmsg("bpsockets daemon can't send bundle.", NULL);
		return 0;
	}

	sdr_end_xn(sdr);
	return 1;
}

void signal_cb(evutil_socket_t fd, short event, void *arg)
{
	int signum = fd; /* why is this fd? */
	switch (signum)
	{
	case SIGPIPE:
		log_printf(LOG_DEBUG, "Caught SIGPIPE and ignored it\n");
		break;
	case SIGINT:
		log_printf(LOG_DEBUG, "Caught SIGINT\n");
		event_base_loopbreak(arg);
		break;
	default:
		break;
	}
	return;
}

/* This function is provided to the hashmap implementation
 * so that it can correctly free all held data */
void free_sock_ctx(sock_ctx_t *sock_ctx)
{
	if (sock_ctx->listener != NULL)
	{
		evconnlistener_free(sock_ctx->listener);
	}
	else if (sock_ctx->is_connected == 1)
	{
		/* connections under the control of the tls_wrapper code
		 * clean up themselves as a result of the close event
		 * received from one of the endpoints. In this case we
		 * only need to clean up the sock_ctx */
	}
	else
	{
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
	}
	// tls_opts_free(sock_ctx->tls_opts);
	// if (sock_ctx->tls_conn != NULL) {
	//	free_tls_conn_ctx(sock_ctx->tls_conn);
	// }
	free(sock_ctx);
	return;
}
