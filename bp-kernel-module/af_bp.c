#include <linux/module.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include "af_bp.h"
#include "bp_nl_gen.h"
#include "../bp-common.h"

HLIST_HEAD(bp_list);
DEFINE_RWLOCK(bp_list_lock);

struct proto bp_proto = {
    .name = "BP",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct bp_sock),
};

static struct sock *bp_alloc_socket(struct net *net, int kern)
{
    struct bp_sock *bp;
    struct sock *sk = sk_alloc(net, AF_BP, GFP_KERNEL, &bp_proto, 1);

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

struct proto_ops bp_proto_ops = {
    .family = AF_BP,
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
    .recvmsg = bp_recvmsg};

int bp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    struct bp_sock *bp;
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

int bp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sock *iter_sk, *sk = sock->sk;
    struct bp_sock *iter_bp, *bp;
    struct sockaddr_bp *addr = (struct sockaddr_bp *)uaddr;
    int rc = 0;

    if (addr_len < sizeof(struct sockaddr_bp))
    {
        pr_err("bp_bind: address length too short (expected: %zu, provided: %d)\n",
               sizeof(struct sockaddr_bp), addr_len);
        rc = -EINVAL;
        goto out;
    }
    if (addr->bp_family != AF_BP)
    {
        pr_err("bp_bind: unsupported address family %d\n", addr->bp_family);
        rc = -EAFNOSUPPORT;
        goto out;
    }
    if (addr->bp_agent_id < 1)
    {
        pr_err("bp_bind: invalid agent ID %d (must be >= 1)\n", addr->bp_agent_id);
        rc = -EINVAL;
        goto out;
    }

    read_lock_bh(&bp_list_lock);
    sk_for_each(iter_sk, &bp_list)
    {
        iter_bp = bp_sk(iter_sk);
        if (iter_bp->bp_agent_id == addr->bp_agent_id)
        {
            rc = -EADDRINUSE;
            pr_err("bp_bind: agent %d already bound\n", addr->bp_agent_id);
            read_unlock_bh(&bp_list_lock);
            goto out;
        }
    }
    read_unlock_bh(&bp_list_lock);

    bp = bp_sk(sk);

    lock_sock(sk);
    bp->bp_agent_id = addr->bp_agent_id;
    write_lock_bh(&bp_list_lock);
    sk_add_node(sk, &bp_list);
    write_unlock_bh(&bp_list_lock);
    release_sock(sk);

    pr_info("bp_bind: socket bound to agent %d\n", addr->bp_agent_id);
out:
    return rc;
}

int bp_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    struct bp_sock *bp = bp_sk(sk);

    if (!sk)
        return 0;

    write_lock_bh(&bp_list_lock);
    sk_del_node_init(sk);
    write_unlock_bh(&bp_list_lock);

    skb_queue_purge(&bp->queue);

    sock_hold(sk);
    lock_sock(sk);
    sock_orphan(sk);
    release_sock(sk);
    sock_put(sk);

    return 0;
}

int bp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
    struct sockaddr *addr;
    char *eid;
    void *payload;
    int eid_size;
    u32 sockid;
    int ret = 0;

    addr = (struct sockaddr *)msg->msg_name;
    eid = addr->sa_data;
    eid_size = strlen(addr->sa_data) + 1;

    pr_info("bp_sendmsg: entering function 2.0\n");

    payload = kmalloc(size, GFP_KERNEL);
    if (!payload)
    {
        pr_err("bp_sendmsg: failed to allocate memory\n");
        ret = -ENOMEM;
        goto out;
    }
    if (copy_from_iter((void *)payload, size, &msg->msg_iter) != size)
    {
        pr_err("bp_sendmsg: failed to copy data from user\n");
        kfree(payload);
        ret = -EFAULT;
        goto clean;
    }

    sockid = (u32)sock->sk->sk_socket;
    send_bundle_doit(sockid, (char *)payload, size, eid, eid_size, 8443);

clean:
    kfree(payload);
out:
    pr_info("bp_sendmsg: exiting function 2.0\n");

    return ret;
}

int bp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    struct sock *sk = sock->sk;
    struct bp_sock *bp = bp_sk(sk);
    u32 agent_id = bp->bp_agent_id;
    struct sk_buff *skb;
    int ret;

    pr_info("bp_recvmsg: entering function 2.0\n");
    notify_deamon_doit(bp->bp_agent_id, 8443);

    sock_hold(sk);
    lock_sock(sk);
    ret = wait_event_interruptible(bp->wait_queue, !skb_queue_empty(&bp->queue));
    if (ret < 0)
    {
        pr_err("bp_recvmsg: interrupted while waiting\n");
        goto out_unlock;
    }
    if (sock_flag(sk, SOCK_DEAD))
    {
        pr_err("bp_recvmsg: socket closed while waiting\n");
        ret = -ECONNRESET;
        goto out_unlock;
    }

    skb = skb_dequeue(&bp->queue);
    if (!skb)
    {
        pr_info("bp_recvmsg: no messages in the queue for agent %d\n", agent_id);
        ret = -EAGAIN;
        goto out_unlock;
    }

    pr_info("bp_recvmsg: message dequeued for agent %d\n", agent_id);

    if (skb->len > size)
    {
        pr_err("bp_recvmsg: buffer too small for message (required: %u, provided: %zu)\n",
               skb->len, size);
        ret = -EMSGSIZE;
        goto out_free_skb;
    }

    if (copy_to_user(msg->msg_iter.iov->iov_base, skb->data, skb->len))
    {
        pr_err("bp_recvmsg: failed to copy data to user space\n");
        ret = -EFAULT;
        goto out_free_skb;
    }

    ret = skb->len;

out_free_skb:
    kfree_skb(skb);
out_unlock:
    release_sock(sk);
    sock_put(sk);

    pr_info("bp_recvmsg: exiting function\n");

    return ret;
}
