#ifndef BP_GENL_H
#define BP_GENL_H

#include "daemon.h"
#include <netlink/socket.h>
#include <pthread.h>
#include <stdint.h>

struct nl_sock *bp_genl_socket_create(Daemon *daemon);
void bp_genl_socket_destroy(Daemon *daemon);
int bp_genl_message_handler(struct nl_msg *msg, void *arg);

// Netlink send functions
int bp_genl_enqueue_bundle(int netlink_family, struct nl_sock *netlink_sock, pthread_mutex_t *mutex,
                           void *payload, size_t payload_size, uint32_t src_node_id,
                           uint32_t src_service_id, uint32_t dest_node_id, uint32_t dest_service_id,
                           uint64_t adu);

#endif
