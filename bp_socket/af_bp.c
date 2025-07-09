#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <net/sock.h>

#include "../include/bp_socket.h"
#include "af_bp.h"
#include "bp_genl.h"

HLIST_HEAD(bp_list);
DEFINE_RWLOCK(bp_list_lock);

struct proto bp_proto = {
	.name = "BP",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct bp_sock),
};

static struct sock* bp_alloc_socket(struct net* net, int kern)
{
	struct bp_sock* bp;
	struct sock* sk = sk_alloc(net, AF_BP, GFP_KERNEL, &bp_proto, 1);

	if (!sk)
		goto out;

	sock_init_data(NULL, sk);

	bp = bp_sk(sk);
	skb_queue_head_init(&bp->queue);
	init_waitqueue_head(&bp->wait_queue);

out:
	return sk;
}

const struct net_proto_family bp_family_ops = {
	.family = AF_BP,
	.create = bp_create,
	.owner = THIS_MODULE,
};

struct proto_ops bp_proto_ops = { .family = AF_BP,
	.owner = THIS_MODULE,
	.release = bp_release,
	.bind = bp_bind,
	.connect = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.sendmsg_locked = sock_no_sendmsg_locked,
	.mmap = sock_no_mmap,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	// .poll = datagram_poll,
	.ioctl = sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_common_setsockopt,
	.getsockopt = sock_common_getsockopt,
	.sendmsg = bp_sendmsg,
	.recvmsg = bp_recvmsg };

int bp_create(struct net* net, struct socket* sock, int protocol, int kern)
{
	struct sock* sk;
	struct bp_sock* bp;
	int rc = -EAFNOSUPPORT;

	if (!net_eq(net, &init_net))
		goto out;

	rc = -ENOMEM;
	if ((sk = bp_alloc_socket(net, kern)) == NULL)
		goto out;

	bp = bp_sk(sk);
	sock_init_data(sock, sk);

	sock->ops = &bp_proto_ops;
	sk->sk_protocol = protocol;

	rc = 0;
out:
	return rc;
}

int bp_bind(struct socket* sock, struct sockaddr* uaddr, int addr_len)
{
	struct sock *iter_sk, *sk = sock->sk;
	struct bp_sock *iter_bp, *bp;
	struct sockaddr_bp* addr = (struct sockaddr_bp*)uaddr;
	int service_id = -1;
	int node_id = -1;

	if (addr_len != sizeof(struct sockaddr_bp))
		return -EINVAL;

	if (addr->bp_family != AF_BP)
		return -EINVAL;

	switch (addr->bp_scheme) {
	case BP_SCHEME_IPN:
		service_id = addr->bp_addr.ipn.service_id;
		node_id = addr->bp_addr.ipn.node_id;

		if (service_id < 1 || service_id > 255) {
			pr_err("bp_bind: invalid service ID %d (must be in "
			       "[1,255])\n",
			    service_id);
			return -EINVAL;
		}

		if (node_id < 1) {
			pr_err("bp_bind: invalid node ID (must be > 0)\n");
			return -EINVAL;
		}

		break;

	case BP_SCHEME_DTN:
		pr_err("bp_bind: DTN scheme not supported\n");
		return -EAFNOSUPPORT;
	default:
		pr_err("bp_bind: unknown scheme %d\n", addr->bp_scheme);
		return -EINVAL;
	}

	read_lock_bh(&bp_list_lock);
	sk_for_each(iter_sk, &bp_list)
	{
		iter_bp = bp_sk(iter_sk);
		if (iter_bp->bp_service_id == service_id
		    && iter_bp->bp_node_id == node_id) {
			read_unlock_bh(&bp_list_lock);
			return -EADDRINUSE;
		}
	}
	read_unlock_bh(&bp_list_lock);

	lock_sock(sk);
	bp = bp_sk(sk);
	bp->bp_service_id = service_id;
	bp->bp_node_id = node_id;
	write_lock_bh(&bp_list_lock);
	sk_add_node(sk, &bp_list);
	write_unlock_bh(&bp_list_lock);

	release_sock(sk);
	return 0;
}

int bp_release(struct socket* sock)
{
	struct sock* sk = sock->sk;
	struct bp_sock* bp;

	if (!sk)
		return 0;

	lock_sock(sk);
	sock_orphan(sk);
	bp = bp_sk(sk);

	write_lock_bh(&bp_list_lock);
	sk_del_node_init(sk);
	write_unlock_bh(&bp_list_lock);
	skb_queue_purge(&bp->queue);

	sock->sk = NULL;
	release_sock(sk);
	sock_put(sk);

	return 0;
}

int bp_sendmsg(struct socket* sock, struct msghdr* msg, size_t size)
{
	struct sockaddr_bp* addr;
	void* payload;
	uintptr_t sockid;
	int service_id = -1;
	int node_id = -1;
	int ret;

	if (!msg->msg_name) {
		pr_err("bp_sendmsg: no destination address provided\n");
		return -EINVAL;
	}

	if (msg->msg_namelen < sizeof(struct sockaddr_bp)) {
		pr_err("bp_sendmsg: address length too short (expected: %zu, "
		       "provided: %u)\n",
		    sizeof(struct sockaddr_bp), msg->msg_namelen);
		return -EINVAL;
	}

	addr = (struct sockaddr_bp*)msg->msg_name;

	if (addr->bp_family != AF_BP) {
		pr_err("bp_sendmsg: unsupported address family %d\n",
		    addr->bp_family);
		return -EAFNOSUPPORT;
	}

	switch (addr->bp_scheme) {
	case BP_SCHEME_IPN:
		service_id = addr->bp_addr.ipn.service_id;
		node_id = addr->bp_addr.ipn.node_id;

		if (service_id < 1 || service_id > 255) {
			pr_err("bp_sendmsg: invalid service ID %d (must be in "
			       "[1,255])\n",
			    service_id);
			return -EINVAL;
		}
		if (node_id < 1) {
			pr_err("bp_sendmsg: invalid node ID (must be > 0)\n");
			return -EINVAL;
		}
		break;

	case BP_SCHEME_DTN:
		pr_err("bp_sendmsg: DTN scheme not supported\n");
		return -EAFNOSUPPORT;

	default:
		pr_err("bp_sendmsg: unknown scheme %d\n", addr->bp_scheme);
		return -EINVAL;
	}

	payload = kmalloc(size, GFP_KERNEL);
	if (!payload) {
		pr_err("bp_sendmsg: failed to allocate memory\n");
		return -ENOMEM;
	}

	if (copy_from_iter(payload, size, &msg->msg_iter) != size) {
		pr_err("bp_sendmsg: failed to copy data from user\n");
		kfree(payload);
		return -EFAULT;
	}

	sockid = (uintptr_t)sock->sk->sk_socket;

	ret = send_bundle_doit(
	    sockid, (char*)payload, size, node_id, service_id, 8443);
	kfree(payload);

	if (ret < 0) {
		pr_err("bp_sendmsg: send_bundle_doit failed (%d)\n", ret);
		return ret;
	}

	return size;
}

int bp_recvmsg(struct socket* sock, struct msghdr* msg, size_t size, int flags)
{
	struct sock* sk = sock->sk;
	struct bp_sock* bp;
	struct sk_buff* skb;
	u32 service_id;
	int ret;

	lock_sock(sk);
	bp = bp_sk(sk);
	service_id = bp->bp_service_id;
	request_bundle_doit(bp->bp_service_id, 8443);

	ret = wait_event_interruptible(
	    bp->wait_queue, !skb_queue_empty(&bp->queue));
	if (ret < 0) {
		pr_err("bp_recvmsg: interrupted while waiting\n");
		goto out_unlock;
	}

	if (sock_flag(sk, SOCK_DEAD)) {
		pr_err("bp_recvmsg: socket closed while waiting\n");
		ret = -ECONNRESET;
		goto out_unlock;
	}

	skb = skb_dequeue(&bp->queue);
	if (!skb) {
		pr_info("bp_recvmsg: no messages in the queue for service %d\n",
		    service_id);
		ret = -EAGAIN;
		goto out_unlock;
	}

	if (skb->len > size) {
		pr_err("bp_recvmsg: buffer too small for message (required=%u, "
		       "provided=%zu)\n",
		    skb->len, size);
		ret = -EMSGSIZE;
		goto out_free_skb;
	}

	if (copy_to_iter(skb->data, skb->len, &msg->msg_iter) != skb->len) {
		pr_err("bp_recvmsg: failed to copy data to user space\n");
		ret = -EFAULT;
		goto out_free_skb;
	}

	ret = skb->len;

out_free_skb:
	kfree_skb(skb);
out_unlock:
	release_sock(sk);

	return ret;
}
