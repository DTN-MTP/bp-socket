#include "bp_genl.h"
#include "../include/bp_socket.h"
#include "af_bp.h"
#include <linux/sched.h>
#include <net/genetlink.h>

static const struct nla_policy nla_policy[BP_GENL_A_MAX + 1] = {
	[BP_GENL_A_UNSPEC] = { .type = NLA_UNSPEC },
	[BP_GENL_A_SRC_NODE_ID] = { .type = NLA_U32 },
	[BP_GENL_A_SRC_SERVICE_ID] = { .type = NLA_U32 },
	[BP_GENL_A_DEST_NODE_ID] = { .type = NLA_U32 },
	[BP_GENL_A_DEST_SERVICE_ID] = { .type = NLA_U32 },
	[BP_GENL_A_PAYLOAD] = { .type = NLA_BINARY },
	[BP_GENL_A_ERROR_CODE] = { .type = NLA_U32 },
};

static struct genl_ops genl_ops[] = { {
					  .cmd = BP_GENL_CMD_DELIVER_BUNDLE,
					  .flags = GENL_ADMIN_PERM,
					  .policy = nla_policy,
					  .doit = deliver_bundle_doit,
					  .dumpit = NULL,
				      },
	{
	    .cmd = BP_GENL_CMD_CANCEL_BUNDLE_REQUEST,
	    .flags = GENL_ADMIN_PERM,
	    .policy = nla_policy,
	    .doit = cancel_bundle_request_doit,
	    .dumpit = NULL,
	},
	{
	    .cmd = BP_GENL_CMD_SEND_BUNDLE_CONFIRMATION,
	    .flags = GENL_ADMIN_PERM,
	    .policy = nla_policy,
	    .doit = send_bundle_confirmation_doit,
	    .dumpit = NULL,
	},
	{
	    .cmd = BP_GENL_CMD_SEND_BUNDLE_FAILURE,
	    .flags = GENL_ADMIN_PERM,
	    .policy = nla_policy,
	    .doit = send_bundle_failure_doit,
	    .dumpit = NULL,
	} };

/* Multicast groups for our family */
static const struct genl_multicast_group genl_mcgrps[] = {
	{ .name = BP_GENL_MC_GRP_NAME },
};

/* Generic Netlink family */
struct genl_family genl_fam = {
	.module = THIS_MODULE,
	.name = BP_GENL_NAME,
	.version = BP_GENL_VERSION,
	.maxattr = BP_GENL_A_MAX,
	.ops = genl_ops,
	.n_ops = ARRAY_SIZE(genl_ops),
	.mcgrps = genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(genl_mcgrps),
};

int send_bundle_doit(void* payload, size_t payload_size, u_int32_t dest_node_id,
    u_int32_t dest_service_id, u_int32_t src_node_id, u_int32_t src_service_id,
    int port_id)
{
	void* msg_head;
	struct sk_buff* msg;
	size_t msg_size;
	int ret;

	msg_size = 4 * nla_total_size(sizeof(u_int32_t))
	    + nla_total_size(payload_size);
	msg = genlmsg_new(msg_size, GFP_KERNEL);
	if (!msg) {
		pr_err("send_bundle: failed to allocate message buffer\n");
		ret = -ENOMEM;
		goto out;
	}

	msg_head
	    = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_SEND_BUNDLE);
	if (!msg_head) {
		pr_err("send_bundle: failed to create genetlink header\n");
		ret = -EMSGSIZE;
		goto err_free;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, dest_node_id);
	if (ret) {
		pr_err(
		    "send_bundle: failed to put BP_GENL_A_DEST_NODE_ID (%d)\n",
		    ret);
		goto err_cancel;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, dest_service_id);
	if (ret) {
		pr_err("send_bundle: failed to put BP_GENL_A_DEST_SERVICE_ID "
		       "(%d)\n",
		    ret);
		goto err_cancel;
	}

	ret = nla_put_u32(msg, BP_GENL_A_SRC_NODE_ID, src_node_id);
	if (ret) {
		pr_err(
		    "send_bundle: failed to put BP_GENL_A_SRC_NODE_ID (%d)\n",
		    ret);
		goto err_cancel;
	}

	ret = nla_put_u32(msg, BP_GENL_A_SRC_SERVICE_ID, src_service_id);
	if (ret) {
		pr_err("send_bundle: failed to put BP_GENL_A_SRC_SERVICE_ID "
		       "(%d)\n",
		    ret);
		goto err_cancel;
	}

	ret = nla_put(msg, BP_GENL_A_PAYLOAD, payload_size, payload);
	if (ret) {
		pr_err(
		    "send_bundle: failed to put BP_GENL_A_PAYLOAD (%d)\n", ret);
		goto err_cancel;
	}

	genlmsg_end(msg, msg_head);
	return genlmsg_unicast(&init_net, msg, port_id);

err_cancel:
	genlmsg_cancel(msg, msg_head);
err_free:
	nlmsg_free(msg);
out:
	return ret;
}

int request_bundle_doit(
    u_int32_t dest_node_id, u_int32_t dest_service_id, int port_id)
{
	void* msg_head;
	struct sk_buff* msg;
	size_t msg_size;
	int ret;

	msg_size = 2 * nla_total_size(sizeof(u_int32_t));
	msg = genlmsg_new(msg_size, GFP_KERNEL);
	if (!msg) {
		pr_err("request_bundle: failed to allocate message buffer\n");
		ret = -ENOMEM;
		goto out;
	}

	msg_head
	    = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_REQUEST_BUNDLE);
	if (!msg_head) {
		pr_err("request_bundle: failed to create genetlink header\n");
		ret = -EMSGSIZE;
		goto err_free;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, dest_node_id);
	if (ret) {
		pr_err("request_bundle: failed to put BP_GENL_A_DEST_NODE_ID "
		       "(%d)\n",
		    ret);
		goto err_cancel;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, dest_service_id);
	if (ret) {
		pr_err("request_bundle: failed to put "
		       "BP_GENL_A_DEST_SERVICE_ID (%d)\n",
		    ret);
		goto err_cancel;
	}

	genlmsg_end(msg, msg_head);
	return genlmsg_unicast(&init_net, msg, port_id);

err_cancel:
	genlmsg_cancel(msg, msg_head);
err_free:
	nlmsg_free(msg);
out:
	return ret;
}

int cancel_bundle_request_doit(struct sk_buff* skb, struct genl_info* info)
{
	struct sock* sk;
	struct bp_sock* bp;
	u_int32_t dest_node_id, dest_service_id;

	if (!info->attrs[BP_GENL_A_DEST_NODE_ID]
	    || !info->attrs[BP_GENL_A_DEST_SERVICE_ID]) {
		pr_err("cancel_bundle_request: missing required attributes\n");
		return -EINVAL;
	}

	dest_node_id = nla_get_u32(info->attrs[BP_GENL_A_DEST_NODE_ID]);
	dest_service_id = nla_get_u32(info->attrs[BP_GENL_A_DEST_SERVICE_ID]);

	read_lock_bh(&bp_list_lock);
	sk_for_each(sk, &bp_list)
	{
		bh_lock_sock(sk);
		bp = bp_sk(sk);

		if (bp->bp_node_id == dest_node_id
		    && bp->bp_service_id == dest_service_id) {

			if (waitqueue_active(&bp->rx_waitq)) {
				mutex_lock(&bp->rx_mutex);
				bp->rx_canceled = true;
				mutex_unlock(&bp->rx_mutex);
				wake_up_interruptible(&bp->rx_waitq);
			}
			bh_unlock_sock(sk);
			break;
		}
		bh_unlock_sock(sk);
	}
	read_unlock_bh(&bp_list_lock);

	return 0;
}

int deliver_bundle_doit(struct sk_buff* skb, struct genl_info* info)
{
	struct sock* sk;
	struct bp_sock* bp;
	struct sk_buff* new_skb;
	bool new_skb_queued = false;
	u_int32_t dest_node_id, dest_service_id, src_node_id, src_service_id;
	void* payload;
	size_t payload_len;
	int ret;

	if (!info->attrs[BP_GENL_A_DEST_NODE_ID]
	    || !info->attrs[BP_GENL_A_DEST_SERVICE_ID]
	    || !info->attrs[BP_GENL_A_SRC_NODE_ID]
	    || !info->attrs[BP_GENL_A_SRC_SERVICE_ID]
	    || !info->attrs[BP_GENL_A_PAYLOAD]) {
		pr_err("deliver_bundle: missing required attributes\n");
		ret = -EINVAL;
		goto out;
	}

	dest_node_id = nla_get_u32(info->attrs[BP_GENL_A_DEST_NODE_ID]);
	dest_service_id = nla_get_u32(info->attrs[BP_GENL_A_DEST_SERVICE_ID]);
	src_node_id = nla_get_u32(info->attrs[BP_GENL_A_SRC_NODE_ID]);
	src_service_id = nla_get_u32(info->attrs[BP_GENL_A_SRC_SERVICE_ID]);
	payload = nla_data(info->attrs[BP_GENL_A_PAYLOAD]);
	payload_len = nla_len(info->attrs[BP_GENL_A_PAYLOAD]);

	new_skb = alloc_skb(payload_len, GFP_KERNEL);
	if (!new_skb) {
		pr_err("Failed to allocate sk_buff for payload\n");
		ret = -ENOMEM;
		goto out;
	}
	skb_put_data(new_skb, payload, payload_len);
	BP_SKB_CB(new_skb)->src_node_id = src_node_id;
	BP_SKB_CB(new_skb)->src_service_id = src_service_id;

	read_lock_bh(&bp_list_lock);
	sk_for_each(sk, &bp_list)
	{
		bh_lock_sock(sk);
		bp = bp_sk(sk);

		if (bp->bp_node_id == dest_node_id
		    && bp->bp_service_id == dest_service_id) {

			mutex_lock(&bp->rx_mutex);
			skb_queue_tail(&bp->rx_queue, new_skb);
			mutex_unlock(&bp->rx_mutex);
			new_skb_queued = true;
			if (waitqueue_active(&bp->rx_waitq)) {
				wake_up_interruptible(&bp->rx_waitq);
			}
			bh_unlock_sock(sk);
			break;
		}
		bh_unlock_sock(sk);
	}
	read_unlock_bh(&bp_list_lock);

	if (!new_skb_queued) {
		pr_err("deliver_bundle: no socket found (ipn:%d.%d)\n",
		    dest_node_id, dest_service_id);
		ret = -ENODEV;
		goto err_free;
	}

	return 0;

err_free:
	kfree_skb(new_skb);
out:
	return ret;
}

int destroy_bundle_doit(
    u_int32_t dest_node_id, u_int32_t dest_service_id, int port_id)
{
	void* msg_head;
	struct sk_buff* msg;
	size_t msg_size;
	int ret;

	msg_size = 2 * nla_total_size(sizeof(u_int32_t));
	msg = genlmsg_new(msg_size, GFP_KERNEL);
	if (!msg) {
		pr_err("destroy_bundle: failed to allocate message buffer\n");
		ret = -ENOMEM;
		goto out;
	}

	msg_head
	    = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_DESTROY_BUNDLE);
	if (!msg_head) {
		pr_err("destroy_bundle: failed to create genetlink header\n");
		ret = -EMSGSIZE;
		goto err_free;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, dest_node_id);
	if (ret) {
		pr_err("destroy_bundle: failed to put BP_GENL_A_DEST_NODE_ID "
		       "(%d)\n",
		    ret);
		goto err_cancel;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, dest_service_id);
	if (ret) {
		pr_err("destroy_bundle: failed to put "
		       "BP_GENL_A_DEST_SERVICE_ID (%d)\n",
		    ret);
		goto err_cancel;
	}

	genlmsg_end(msg, msg_head);
	return genlmsg_unicast(&init_net, msg, port_id);

err_cancel:
	genlmsg_cancel(msg, msg_head);
err_free:
	nlmsg_free(msg);
out:
	return ret;
}

int open_endpoint_doit(u_int32_t node_id, u_int32_t service_id, int port_id)
{
	void* msg_head;
	struct sk_buff* msg;
	size_t msg_size;
	int ret;

	msg_size = 2 * nla_total_size(sizeof(u_int32_t));
	msg = genlmsg_new(msg_size, GFP_KERNEL);
	if (!msg) {
		pr_err("open_endpoint: failed to allocate message buffer\n");
		ret = -ENOMEM;
		goto out;
	}

	msg_head
	    = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_OPEN_ENDPOINT);
	if (!msg_head) {
		pr_err("open_endpoint: failed to create genetlink header\n");
		ret = -EMSGSIZE;
		goto err_free;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, node_id);
	if (ret) {
		pr_err("open_endpoint: failed to put BP_GENL_A_DEST_NODE_ID "
		       "(%d)\n",
		    ret);
		goto err_cancel;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, service_id);
	if (ret) {
		pr_err("open_endpoint: failed to put BP_GENL_A_DEST_SERVICE_ID "
		       "(%d)\n",
		    ret);
		goto err_cancel;
	}

	genlmsg_end(msg, msg_head);
	return genlmsg_unicast(&init_net, msg, port_id);

err_cancel:
	genlmsg_cancel(msg, msg_head);
err_free:
	nlmsg_free(msg);
out:
	return ret;
}

int send_bundle_confirmation_doit(struct sk_buff* skb, struct genl_info* info)
{
	u_int32_t src_node_id, src_service_id;
	struct sock* sk;
	struct bp_sock* bp;

	if (!info->attrs[BP_GENL_A_SRC_NODE_ID]
	    || !info->attrs[BP_GENL_A_SRC_SERVICE_ID]) {
		pr_err("send_bundle_confirmation_doit: missing attribute(s)\n");
		return -EINVAL;
	}

	src_node_id = nla_get_u32(info->attrs[BP_GENL_A_SRC_NODE_ID]);
	src_service_id = nla_get_u32(info->attrs[BP_GENL_A_SRC_SERVICE_ID]);

	pr_info("send_bundle_confirmation_doit: received confirmation for "
		"ipn:%u.%u\n",
	    src_node_id, src_service_id);

	// Find the socket waiting for confirmation
	read_lock_bh(&bp_list_lock);
	sk_for_each(sk, &bp_list)
	{
		bp = bp_sk(sk);
		if (bp->bp_node_id == src_node_id
		    && bp->bp_service_id == src_service_id) {
			// Found the socket, wake it up
			mutex_lock(&bp->tx_mutex);
			bp->tx_confirmed = true;
			mutex_unlock(&bp->tx_mutex);
			wake_up(&bp->tx_waitq);
			pr_info(
			    "send_bundle_confirmation_doit: woke up socket for "
			    "ipn:%u.%u\n",
			    src_node_id, src_service_id);
			break;
		}
	}
	read_unlock_bh(&bp_list_lock);

	return 0;
}

int send_bundle_failure_doit(struct sk_buff* skb, struct genl_info* info)
{
	u_int32_t src_node_id, src_service_id;
	struct sock* sk;
	struct bp_sock* bp;

	if (!info->attrs[BP_GENL_A_SRC_NODE_ID]
	    || !info->attrs[BP_GENL_A_SRC_SERVICE_ID]) {
		pr_err("send_bundle_failure_doit: missing attribute(s)\n");
		return -EINVAL;
	}

	src_node_id = nla_get_u32(info->attrs[BP_GENL_A_SRC_NODE_ID]);
	src_service_id = nla_get_u32(info->attrs[BP_GENL_A_SRC_SERVICE_ID]);

	pr_info("send_bundle_failure_doit: received failure notification for "
		"ipn:%u.%u\n",
	    src_node_id, src_service_id);

	// Find the socket waiting for confirmation and mark it as failed
	read_lock_bh(&bp_list_lock);
	sk_for_each(sk, &bp_list)
	{
		bp = bp_sk(sk);
		if (bp->bp_node_id == src_node_id
		    && bp->bp_service_id == src_service_id) {
			// Found the socket, mark as failed and wake it up
			mutex_lock(&bp->tx_mutex);
			bp->tx_confirmed = true;
			bp->tx_error = true;
			mutex_unlock(&bp->tx_mutex);
			wake_up(&bp->tx_waitq);
			pr_info("send_bundle_failure_doit: woke up socket for "
				"ipn:%u.%u with failure\n",
			    src_node_id, src_service_id);
			break;
		}
	}
	read_unlock_bh(&bp_list_lock);

	return 0;
}

int close_endpoint_doit(u_int32_t node_id, u_int32_t service_id, int port_id)
{
	void* msg_head;
	struct sk_buff* msg;
	size_t msg_size;
	int ret;

	msg_size = 2 * nla_total_size(sizeof(u_int32_t));
	msg = genlmsg_new(msg_size, GFP_KERNEL);
	if (!msg) {
		pr_err("close_endpoint: failed to allocate message buffer\n");
		ret = -ENOMEM;
		goto out;
	}

	msg_head
	    = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_CLOSE_ENDPOINT);
	if (!msg_head) {
		pr_err("close_endpoint: failed to create genetlink header\n");
		ret = -EMSGSIZE;
		goto err_free;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_NODE_ID, node_id);
	if (ret) {
		pr_err("close_endpoint: failed to put BP_GENL_A_DEST_NODE_ID "
		       "(%d)\n",
		    ret);
		goto err_cancel;
	}

	ret = nla_put_u32(msg, BP_GENL_A_DEST_SERVICE_ID, service_id);
	if (ret) {
		pr_err("close_endpoint: failed to put "
		       "BP_GENL_A_DEST_SERVICE_ID (%d)\n",
		    ret);
		goto err_cancel;
	}

	genlmsg_end(msg, msg_head);
	return genlmsg_unicast(&init_net, msg, port_id);

err_cancel:
	genlmsg_cancel(msg, msg_head);
err_free:
	nlmsg_free(msg);
out:
	return ret;
}