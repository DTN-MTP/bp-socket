#ifndef BP_GENL_H
#define BP_GENL_H

#include <net/genetlink.h>

extern struct genl_family genl_fam;

int open_endpoint_doit(u_int32_t node_id, u_int32_t service_id, int port_id);
int close_endpoint_doit(u_int32_t node_id, u_int32_t service_id, int port_id);
int send_bundle_doit(void* payload, size_t payload_size, u_int32_t dest_node_id,
    u_int32_t dest_service_id, u_int32_t src_node_id, u_int32_t src_service_id,
    int port_id);
int send_bundle_confirmation_doit(struct sk_buff* skb, struct genl_info* info);
int send_bundle_failure_doit(struct sk_buff* skb, struct genl_info* info);
int deliver_bundle_doit(struct sk_buff* skb, struct genl_info* info);
int request_bundle_doit(
    u_int32_t dest_node_id, u_int32_t dest_service_id, int port_id);
int cancel_bundle_request_doit(struct sk_buff* skb, struct genl_info* info);
int destroy_bundle_doit(
    u_int32_t dest_node_id, u_int32_t dest_service_id, int port_id);

#endif