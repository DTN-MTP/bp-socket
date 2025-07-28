#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <net/sock.h>

#include "../include/bp_socket.h"
#include "af_bp.h"
#include "bp_genl.h"

#define BP_MAX_PAYLOAD (256 * 1024)

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
	struct sock* sk;

	sk = sk_alloc(net, AF_BP, GFP_KERNEL, &bp_proto, 1);
	if (sk) {
		sock_init_data(NULL, sk);

		bp = bp_sk(sk);
		skb_queue_head_init(&bp->queue);
		init_waitqueue_head(&bp->wait_queue);
		bp->bp_node_id = 0;
		bp->bp_service_id = 0;
	}

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
	int ret;

	if (!net_eq(net, &init_net)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	if ((sk = bp_alloc_socket(net, kern)) == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	bp = bp_sk(sk);
	sock_init_data(sock, sk);

	sock->ops = &bp_proto_ops;
	sk->sk_protocol = protocol;

	return 0;

out:
	return ret;
}

int bp_bind(struct socket* sock, struct sockaddr* uaddr, int addr_len)
{
	struct sock *iter_sk, *sk;
	struct bp_sock *iter_bp, *bp;
	struct sockaddr_bp* addr;
	u_int32_t service_id;
	u_int32_t node_id;
	int ret;

	sk = sock->sk;
	addr = (struct sockaddr_bp*)uaddr;
	service_id = addr->bp_addr.ipn.service_id;
	node_id = addr->bp_addr.ipn.node_id;

	if (addr_len != sizeof(struct sockaddr_bp)) {
		ret = -EINVAL;
		goto out;
	}

	if (addr->bp_family != AF_BP) {
		ret = -EINVAL;
		goto out;
	}

	if (addr->bp_scheme != BP_SCHEME_IPN) {
		pr_err("bp_bind: unsupported address scheme %d\n",
		    addr->bp_scheme);
		ret = -EAFNOSUPPORT;
		goto out;
	}

	// https://www.rfc-editor.org/rfc/rfc9758.html#name-node-numbers
	if (node_id > 0xFFFFFFFF) {
		pr_err("bp_bind: invalid node ID (must be in [0;2^31])\n");
		ret = -EINVAL;
		goto out;
	}

	// https://www.rfc-editor.org/rfc/rfc9758.html#name-service-numbers
	if (service_id < 1 || service_id > 0xFFFFFFFF) {
		pr_err("bp_bind: invalid service ID %d (must be in "
		       "[1;2^31])\n",
		    service_id);
		ret = -EINVAL;
		goto out;
	}

	read_lock_bh(&bp_list_lock);
	sk_for_each(iter_sk, &bp_list)
	{
		iter_bp = bp_sk(iter_sk);
		if (iter_bp->bp_service_id == service_id
		    && iter_bp->bp_node_id == node_id) {
			read_unlock_bh(&bp_list_lock);
			ret = -EADDRINUSE;
			goto out;
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

out:
	return ret;
}

int bp_release(struct socket* sock)
{
	struct sock* sk = sock->sk;
	struct bp_sock* bp;

	if (sk) {
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
	}

	return 0;
}

int bp_sendmsg(struct socket* sock, struct msghdr* msg, size_t size)
{
	struct sockaddr_bp* addr;
	void* payload;
	u_int32_t service_id;
	u_int32_t node_id;
	int ret;

	if (!msg->msg_name) {
		pr_err("bp_sendmsg: no destination address provided\n");
		ret = -EINVAL;
		goto out;
	}

	if (msg->msg_namelen < sizeof(struct sockaddr_bp)) {
		pr_err("bp_sendmsg: address length too short (expected: %zu, "
		       "provided: %u)\n",
		    sizeof(struct sockaddr_bp), msg->msg_namelen);
		ret = -EINVAL;
		goto out;
	}

	addr = (struct sockaddr_bp*)msg->msg_name;

	if (addr->bp_family != AF_BP) {
		pr_err("bp_sendmsg: unsupported address family %d\n",
		    addr->bp_family);
		ret = -EAFNOSUPPORT;
		goto out;
	}

	if (addr->bp_scheme != BP_SCHEME_IPN) {
		pr_err("bp_sendmsg: unsupported address scheme %d\n",
		    addr->bp_scheme);
		ret = -EAFNOSUPPORT;
		goto out;
	}

	service_id = addr->bp_addr.ipn.service_id;
	node_id = addr->bp_addr.ipn.node_id;

	// https://www.rfc-editor.org/rfc/rfc9758.html#name-node-numbers
	if (node_id > 0xFFFFFFFF) {
		pr_err("bp_bind: invalid node ID (must be in [0;2^31])\n");
		ret = -EINVAL;
		goto out;
	}

	// https://www.rfc-editor.org/rfc/rfc9758.html#name-service-numbers
	if (service_id < 1 || service_id > 0xFFFFFFFF) {
		pr_err("bp_bind: invalid service ID %d (must be in "
		       "[1;2^31])\n",
		    service_id);
		ret = -EINVAL;
		goto out;
	}

	if (size > BP_MAX_PAYLOAD) {
		pr_err("bp_sendmsg: payload too big (%zu bytes)\n", size);
		ret = -EMSGSIZE;
		goto out;
	}

	if (size > 0) {
		payload = kmalloc(size, GFP_KERNEL);
		if (!payload) {
			pr_err("bp_sendmsg: failed to allocate memory\n");
			ret = -ENOMEM;
			goto out;
		}

		if (copy_from_iter(payload, size, &msg->msg_iter) != size) {
			pr_err("bp_sendmsg: failed to copy data from user\n");
			ret = -EFAULT;
			goto err_free;
		}

		ret = send_bundle_doit(
		    payload, size, node_id, service_id, 8443);
		if (ret < 0) {
			pr_err(
			    "bp_sendmsg: send_bundle_doit failed (%d)\n", ret);
			goto err_free;
		}

		kfree(payload);
	}

	return size;

err_free:
	kfree(payload);
out:
	return ret;
}

int bp_recvmsg(struct socket* sock, struct msghdr* msg, size_t size, int flags)
{
	struct sock* sk;
	struct bp_sock* bp;
	struct sk_buff* skb;
	struct sockaddr_bp* src_addr;
	int ret;

	sk = sock->sk;
	lock_sock(sk);
	bp = bp_sk(sk);
	ret = request_bundle_doit(bp->bp_node_id, bp->bp_service_id, 8443);
	if (ret < 0) {
		pr_err("bp_recvmsg: request_bundle_doit failed (%d)\n", ret);
		goto out;
	}

	ret = wait_event_interruptible(
	    bp->wait_queue, !skb_queue_empty(&bp->queue));
	if (ret < 0) {
		pr_err("bp_recvmsg: interrupted while waiting\n");
		goto out;
	}

	if (sock_flag(sk, SOCK_DEAD)) {
		pr_err("bp_recvmsg: socket closed while waiting\n");
		ret = -ESHUTDOWN;
		goto out;
	}

	skb = skb_dequeue(&bp->queue);
	if (!skb) {
		pr_info("bp_recvmsg: no messages in the queue for service %d\n",
		    bp->bp_service_id);
		ret = -ENOMSG;
		goto out;
	}

	if (skb->len > size) {
		pr_err("bp_recvmsg: buffer too small for message (required=%u, "
		       "provided=%zu)\n",
		    skb->len, size);
		ret = -EMSGSIZE;
		goto out;
	}

	src_addr->bp_family = AF_BP;
	src_addr->bp_scheme = BP_SCHEME_IPN;
	src_addr->bp_addr.ipn.node_id = BP_SKB_CB(skb)->src_node_id;
	src_addr->bp_addr.ipn.service_id = BP_SKB_CB(skb)->src_service_id;

	if (msg->msg_name && msg->msg_namelen >= sizeof(struct sockaddr_bp)) {
		memcpy(msg->msg_name, &src_addr, sizeof(struct sockaddr_bp));
		msg->msg_namelen = sizeof(struct sockaddr_bp); // important
	} else if (msg->msg_name) {
		pr_warn(
		    "bp_recvmsg: user msg_name buffer too small (%u bytes)\n",
		    msg->msg_namelen);
		ret = -EINVAL;
		goto out;
	}

	if (copy_to_iter(skb->data, skb->len, &msg->msg_iter) != skb->len) {
		pr_err("bp_recvmsg: failed to copy data to user space\n");
		ret = -EFAULT;
		goto out;
	}

	ret = destroy_bundle_doit(bp->bp_node_id, bp->bp_service_id, 8443);
	if (ret < 0) {
		pr_err(
		    "destroy_bundle_doit failed (%d), will retry later", ret);
		// enqueue_retry(bp->bp_node_id, bp->bp_service_id);
	}

	ret = skb->len;

out:
	if (skb)
		kfree_skb(skb);
	release_sock(sk);
	return ret;
}
