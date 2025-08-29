#ifndef AF_BP_H
#define AF_BP_H

#include <linux/net.h>
#include <net/sock.h>

struct bp_skb_cb {
	u_int32_t src_node_id;
	u_int32_t src_service_id;
};

#define bp_sk(ptr) container_of(ptr, struct bp_sock, sk)
#define BP_SKB_CB(skb) ((struct bp_skb_cb*)((skb)->cb))

extern struct hlist_head bp_list;
extern rwlock_t bp_list_lock;
extern struct proto bp_proto;
extern const struct net_proto_family bp_family_ops;

struct bp_sock {
	struct sock sk;
	u_int32_t bp_node_id;
	u_int32_t bp_service_id;
	struct sk_buff_head rx_queue;
	wait_queue_head_t rx_waitq;
	bool rx_canceled;
};

int bp_bind(struct socket* sock, struct sockaddr* addr, int addr_len);
int bp_create(struct net* net, struct socket* sock, int protocol, int kern);
int bp_release(struct socket* sock);
int bp_sendmsg(struct socket* sock, struct msghdr* msg, size_t size);
int bp_recvmsg(struct socket* sock, struct msghdr* msg, size_t size, int flags);

#endif
