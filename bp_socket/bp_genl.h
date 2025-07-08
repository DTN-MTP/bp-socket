#ifndef BP_GENL_H
#define BP_GENL_H

#include <net/genetlink.h>

extern struct genl_family genl_fam;

int fail_doit(struct sk_buff* skb, struct genl_info* info);
int open_endpoint_doit(u32 node_id, u32 service_id, int port_id);
int close_endpoint_doit(u32 node_id, u32 service_id, int port_id);
int abort_endpoint_doit(u32 node_id, u32 service_id, int port_id);
int send_bundle_doit(u64 sockid, const char* payload, int payload_size,
    u32 node_id, u32 service_id, int port_id);
int deliver_bundle_doit(struct sk_buff* skb, struct genl_info* info);
int request_bundle_doit(u32 service_id, int port_id);

#endif