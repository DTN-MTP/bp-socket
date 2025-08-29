#ifndef NL_UTILS_H
#define NL_UTILS_H

#include <netlink/netlink.h>
#include <stddef.h>
#include <stdint.h>

int nl_send_cancel_bundle_request(int netlink_family, struct nl_sock *netlink_sock,
                                  uint32_t node_id, uint32_t service_id);
int nl_send_deliver_bundle(int netlink_family, struct nl_sock *netlink_sock, void *payload,
                           size_t payload_size, uint32_t src_node_id, uint32_t src_service_id,
                           uint32_t dest_node_id, uint32_t dest_service_id);
int nl_send_bundle_confirmation(int netlink_family, struct nl_sock *netlink_sock,
                                uint32_t src_node_id, uint32_t src_service_id);
int nl_send_bundle_failure(int netlink_family, struct nl_sock *netlink_sock, uint32_t src_node_id,
                           uint32_t src_service_id, int error_code);

#endif
