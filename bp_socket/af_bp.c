#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <net/sock.h>
#include <uapi/linux/time.h>

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
		skb_queue_head_init(&bp->rx_queue);
		init_waitqueue_head(&bp->rx_waitq);

		mutex_init(&bp->rx_mutex);

		bp->bp_node_id = 0;
		bp->bp_service_id = 0;
		sk->sk_rcvtimeo
		    = MAX_SCHEDULE_TIMEOUT; /* Default: no timeout */
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
	.poll = bp_poll,
	.ioctl = sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = bp_setsockopt,
	.getsockopt = bp_getsockopt,
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

	// Notify user-space daemon to open endpoint (bp_open) and prepare
	// threads/state
	ret = open_endpoint_doit(node_id, service_id, 8443);
	if (ret < 0) {
		pr_err("bp_bind: open_endpoint_doit failed (%d)\n", ret);
		goto out;
	}

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
		skb_queue_purge(&bp->rx_queue);

		// Notify user-space daemon to close endpoint (bp_close) and
		// cleanup
		if (bp->bp_node_id && bp->bp_service_id) {
			close_endpoint_doit(
			    bp->bp_node_id, bp->bp_service_id, 8443);
		}

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
	u_int32_t dest_node_id, dest_service_id;
	int ret;
	struct bp_sock* bp = bp_sk(sock->sk);

	if (bp->bp_node_id == 0 || bp->bp_service_id == 0) {
		pr_err("bp_sendmsg: socket must be bound before sending\n");
		ret = -EADDRNOTAVAIL;
		goto out;
	}

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

	dest_node_id = addr->bp_addr.ipn.node_id;
	dest_service_id = addr->bp_addr.ipn.service_id;

	// https://www.rfc-editor.org/rfc/rfc9758.html#name-node-numbers
	if (dest_node_id > 0xFFFFFFFF) {
		pr_err("bp_bind: invalid node ID (must be in [0;2^31])\n");
		ret = -EINVAL;
		goto out;
	}

	// https://www.rfc-editor.org/rfc/rfc9758.html#name-service-numbers
	if (dest_service_id < 1 || dest_service_id > 0xFFFFFFFF) {
		pr_err("bp_bind: invalid service ID %d (must be in "
		       "[1;2^31])\n",
		    dest_service_id);
		ret = -EINVAL;
		goto out;
	}

	if (size > BP_MAX_PAYLOAD) {
		pr_err("bp_sendmsg: payload too big (%zu bytes)\n", size);
		ret = -EMSGSIZE;
		goto out;
	}

	if (size > 0) {
		payload = kmalloc(size, GFP_ATOMIC);
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

		ret = send_bundle_doit(payload, size, dest_node_id,
		    dest_service_id, bp->bp_node_id, bp->bp_service_id,
		    msg->msg_flags, 8443);
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

__poll_t bp_poll(
    struct file* file, struct socket* sock, struct poll_table_struct* wait)
{
	struct sock* sk = sock->sk;
	struct bp_sock* bp = bp_sk(sk);
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);

	if (sk->sk_err)
		mask |= POLLERR;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLRDHUP | POLLIN | POLLRDNORM;

	if (sk->sk_shutdown == SHUTDOWN_MASK)
		mask |= POLLHUP;

	if (!skb_queue_empty(&bp->rx_queue))
		mask |= POLLIN | POLLRDNORM;

	if (sock_writeable(sk))
		mask |= POLLOUT | POLLWRNORM;

	return mask;
}

int bp_recvmsg(struct socket* sock, struct msghdr* msg, size_t size, int flags)
{
	struct sock* sk;
	struct bp_sock* bp;
	struct sk_buff* skb = NULL;
	struct sockaddr_bp* src_addr;
	long timeo;
	size_t copy_len;
	int ret;

	sk = sock->sk;
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	lock_sock(sk);
	bp = bp_sk(sk);

	if (bp->bp_node_id == 0 || bp->bp_service_id == 0) {
		pr_err("bp_recvmsg: socket must be bound before receiving\n");
		ret = -EADDRNOTAVAIL;
		goto out;
	}

	ret = wait_event_interruptible_timeout(
	    bp->rx_waitq, !skb_queue_empty(&bp->rx_queue), timeo);
	if (ret == 0) {
		pr_err("bp_recvmsg: timeout waiting for message\n");
		ret = -EAGAIN;
		goto out;
	}
	if (ret == -ERESTARTSYS) {
		pr_err("bp_recvmsg: interrupted by signal\n");
		ret = -EINTR;
		goto out;
	}

	if (sock_flag(sk, SOCK_DEAD)) {
		pr_err("bp_recvmsg: socket closed while waiting\n");
		ret = -ESHUTDOWN;
		goto out;
	}

	mutex_lock(&bp->rx_mutex);
	if (flags & MSG_PEEK) {
		skb = skb_peek(&bp->rx_queue);
	} else {
		skb = skb_dequeue(&bp->rx_queue);
	}
	if (!skb) {
		pr_info("bp_recvmsg: no messages in the queue for ipn:%u.%u\n",
		    bp->bp_node_id, bp->bp_service_id);
		mutex_unlock(&bp->rx_mutex);
		ret = -EAGAIN;
		goto out;
	}
	mutex_unlock(&bp->rx_mutex);

	if (skb->len > size) {
		if (flags & MSG_TRUNC) {
			msg->msg_flags |= MSG_TRUNC;
		} else {
			pr_err("bp_recvmsg: buffer too small for message "
			       "(required=%u, "
			       "provided=%zu)\n",
			    skb->len, size);
			ret = -EMSGSIZE;
			goto out;
		}
	}

	if (msg->msg_name) {
		src_addr = (struct sockaddr_bp*)msg->msg_name;
		src_addr->bp_family = AF_BP;
		src_addr->bp_scheme = BP_SCHEME_IPN;
		src_addr->bp_addr.ipn.node_id = BP_SKB_CB(skb)->src_node_id;
		src_addr->bp_addr.ipn.service_id
		    = BP_SKB_CB(skb)->src_service_id;
		msg->msg_namelen = sizeof(struct sockaddr_bp);
	}

	copy_len = (skb->len > size) ? size : skb->len;
	if (copy_to_iter(skb->data, copy_len, &msg->msg_iter) != copy_len) {
		pr_err("bp_recvmsg: failed to copy data to user space\n");
		ret = -EFAULT;
		goto out;
	}

	if (!(flags & MSG_PEEK)) {
		ret = destroy_bundle_doit(BP_SKB_CB(skb)->adu, 8443);
		if (ret < 0) {
			pr_warn("bp_recvmsg: failed to destroy bundle, bundle "
				"may leak\n");
		}
	}

	ret = skb->len;

out:
	if (skb && !(flags & MSG_PEEK))
		kfree_skb(skb);
	release_sock(sk);
	return ret;
}

int bp_setsockopt(struct socket* sock, int level, int optname, sockptr_t optval,
    unsigned int optlen)
{
	struct sock* sk = sock->sk;
	struct bp_sock* bp;
	int ret = 0;

	if (level != SOL_SOCKET)
		return sock_common_setsockopt(
		    sock, level, optname, optval, optlen);

	lock_sock(sk);
	bp = bp_sk(sk);

	switch (optname) {

	case SO_RCVTIMEO_OLD: {
		struct __kernel_old_timeval tv;
		unsigned long t;
		if (optlen < sizeof(tv)) {
			ret = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&tv, optval, sizeof(tv))) {
			ret = -EFAULT;
			break;
		}

		if (tv.tv_sec == 0 && tv.tv_usec == 0) {
			t = 0;
		} else if (tv.tv_sec < 0 || tv.tv_usec < 0
		    || tv.tv_usec >= 1000000) {
			ret = -EINVAL;
			break;
		} else {
			u64 usec = (u64)tv.tv_sec * 1000000ULL + tv.tv_usec;
			t = usecs_to_jiffies(usec);
		}
		sk->sk_rcvtimeo = t;
		break;
	}

	case SO_RCVTIMEO_NEW: {
		struct __kernel_timespec ts;
		unsigned long t;
		if (optlen < sizeof(ts)) {
			ret = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&ts, optval, sizeof(ts))) {
			ret = -EFAULT;
			break;
		}

		if (ts.tv_sec == 0 && ts.tv_nsec == 0) {
			t = 0;
		} else if (ts.tv_sec < 0 || ts.tv_nsec < 0
		    || ts.tv_nsec >= 1000000000L) {
			ret = -EINVAL;
			break;
		} else {
			struct timespec64 t64
			    = { .tv_sec = ts.tv_sec, .tv_nsec = ts.tv_nsec };
			t = timespec64_to_jiffies(&t64);
		}
		sk->sk_rcvtimeo = t;
		break;
	}

	default:
		ret = sock_common_setsockopt(
		    sock, level, optname, optval, optlen);
		break;
	}

	release_sock(sk);
	return ret;
}

int bp_getsockopt(struct socket* sock, int level, int optname,
    char __user* optval, int __user* optlen)
{
	struct sock* sk = sock->sk;
	struct bp_sock* bp;
	int ret = 0, len;

	if (level != SOL_SOCKET)
		return sock_common_getsockopt(
		    sock, level, optname, optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sk);
	bp = bp_sk(sk);

	switch (optname) {

	case SO_RCVTIMEO_OLD: {
		struct __kernel_old_timeval tv;
		unsigned long t = sk->sk_rcvtimeo; /* ou bp->rcv_timeout */

		if (len < (int)sizeof(tv)) {
			ret = -EINVAL;
			break;
		}

		if (t == MAX_SCHEDULE_TIMEOUT) {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		} else {
			unsigned long msec = jiffies_to_msecs(t);
			tv.tv_sec = msec / 1000;
			tv.tv_usec = (msec % 1000) * 1000;
		}

		if (copy_to_user(optval, &tv, sizeof(tv))
		    || put_user(sizeof(tv), optlen))
			ret = -EFAULT;
		break;
	}

	case SO_RCVTIMEO_NEW: {
		struct __kernel_timespec ts;
		unsigned long t = sk->sk_rcvtimeo;

		if (len < (int)sizeof(ts)) {
			ret = -EINVAL;
			break;
		}

		if (t == MAX_SCHEDULE_TIMEOUT) {
			ts.tv_sec = 0;
			ts.tv_nsec = 0;
		} else {
			unsigned long msec = jiffies_to_msecs(t);
			u64 ns = (u64)msec * 1000000ULL;
			ts.tv_sec = div_u64(ns, 1000000000ULL);
			ts.tv_nsec = ns % 1000000000ULL;
		}

		if (copy_to_user(optval, &ts, sizeof(ts))
		    || put_user(sizeof(ts), optlen))
			ret = -EFAULT;
		break;
	}

	default:
		ret = sock_common_getsockopt(
		    sock, level, optname, optval, optlen);
		break;
	}

	release_sock(sk);
	return ret;
}
