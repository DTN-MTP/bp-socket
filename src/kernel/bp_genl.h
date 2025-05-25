#ifndef BP_GENL_H
#define BP_GENL_H

extern struct genl_family genl_fam;

int fail_doit(struct sk_buff *skb, struct genl_info *info);
int send_bundle_doit(u64 sockid, char *payload, int payload_size, char *eid, int eid_size, int port_id);
int recv_reply_bundle_doit(struct sk_buff *skb, struct genl_info *info);
int notify_deamon_doit(u32 agent_id, int port_id);

#endif