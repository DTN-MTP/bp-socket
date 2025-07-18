#ifndef BP_GENL_H
#define BP_GENL_H

#include <net/genetlink.h>

extern struct genl_family genl_fam;

int send_bundle_doit(void* payload, int payload_size, u_int32_t node_id,
    u_int32_t service_id, int port_id);
int deliver_bundle_doit(struct sk_buff* skb, struct genl_info* info);
int request_bundle_doit(u_int32_t node_id, u_int32_t service_id, int port_id);
int destroy_bundle_doit(u_int32_t node_id, u_int32_t service_id, int port_id);

#endif