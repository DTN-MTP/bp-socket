#include "bp_genl.h"
#include "../include/bp_socket.h"
#include "af_bp.h"
#include <net/genetlink.h>

static const struct nla_policy nla_policy[BP_GENL_A_MAX + 1] = {
	[BP_GENL_A_UNSPEC] = { .type = NLA_UNSPEC },
	[BP_GENL_A_SOCKID] = { .type = NLA_U64 },
	[BP_GENL_A_NODE_ID] = { .type = NLA_U32 },
	[BP_GENL_A_SERVICE_ID] = { .type = NLA_U32 },
	[BP_GENL_A_PAYLOAD] = { .type = NLA_BINARY },
};

static struct genl_ops genl_ops[] = { {
    .cmd = BP_GENL_CMD_DELIVER_BUNDLE,
    .flags = GENL_ADMIN_PERM,
    .policy = nla_policy,
    .doit = deliver_bundle_doit,
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

int fail_doit(struct sk_buff* skb, struct genl_info* info)
{
	pr_alert("Kernel receieved an SSA netlink notification. This should "
		 "never happen.\n");
	return -1;
}

int send_bundle_doit(u64 sockid, const char* payload, int payload_size,
    u32 node_id, u32 service_id, int port_id)
{
	int ret = 0;
	void* hdr;
	struct sk_buff* msg;
	int msg_size;

	/* Compute total size of Netlink attributes */
	msg_size = nla_total_size(sizeof(u64)) + nla_total_size(sizeof(u32))
	    + nla_total_size(sizeof(u32)) + nla_total_size(payload_size);

	/* Allocate a new buffer */
	msg = genlmsg_new(msg_size + GENL_HDRLEN, GFP_KERNEL);
	if (!msg) {
		pr_err("send_bundle: failed to allocate message buffer\n");
		return -ENOMEM;
	}

	/* Generic Netlink header */
	hdr = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_SEND_BUNDLE);
	if (!hdr) {
		pr_err("send_bundle: failed to create genetlink header\n");
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	/* And the message */
	ret = nla_put_u64_64bit(msg, BP_GENL_A_SOCKID, sockid, 0);
	if (ret) {
		pr_err("send_bundle: failed to put SOCKID (%d)\n", ret);
		goto fail;
	}

	ret = nla_put_u32(msg, BP_GENL_A_NODE_ID, node_id);
	if (ret) {
		pr_err("send_bundle: failed to put NODE_ID (%d)\n", ret);
		goto fail;
	}

	ret = nla_put_u32(msg, BP_GENL_A_SERVICE_ID, service_id);
	if (ret) {
		pr_err("send_bundle: failed to put SERVICE_ID (%d)\n", ret);
		goto fail;
	}

	ret = nla_put(msg, BP_GENL_A_PAYLOAD, payload_size, payload);
	if (ret) {
		pr_err("send_bundle: failed to put PAYLOAD (%d)\n", ret);
		goto fail;
	}

	genlmsg_end(msg, hdr);
	ret = genlmsg_unicast(&init_net, msg, port_id);
	if (ret != 0) {
		pr_err("send_bundle: genlmsg_unicast failed (%d)\n", ret);
	}
	return ret;

fail:
	genlmsg_cancel(msg, hdr);
	nlmsg_free(msg);
	return ret;
}

int request_bundle_doit(u32 service_id, int port_id)
{
	int ret = 0;
	void* hdr;
	struct sk_buff* msg;
	int msg_size;

	/* Allocate a new buffer for the reply */
	msg_size = nla_total_size(sizeof(u32));
	msg = genlmsg_new(msg_size + GENL_HDRLEN, GFP_KERNEL);
	if (!msg) {
		pr_err("failed to allocate message buffer\n");
		return -ENOMEM;
	}

	/* Put the Generic Netlink header */
	hdr = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_REQUEST_BUNDLE);
	if (!hdr) {
		pr_err("failed to create genetlink header\n");
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	/* And the message */
	if ((ret = nla_put_u32(msg, BP_GENL_A_SERVICE_ID, service_id))) {
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}

	/* Finalize the message and send it */
	genlmsg_end(msg, hdr);
	ret = genlmsg_unicast(&init_net, msg, port_id);
	if (ret != 0) {
		pr_alert("Failed in gemlmsg_unicast [setsockopt notify]\n (%d)",
		    ret);
	}

out:
	return ret;
}

int deliver_bundle_doit(struct sk_buff* skb, struct genl_info* info)
{
	struct sock* sk;
	struct bp_sock* bp;
	u32 service_id;
	char* payload;
	size_t payload_len;
	struct sk_buff* new_skb;

	if (!info->attrs[BP_GENL_A_SERVICE_ID]
	    || !info->attrs[BP_GENL_A_PAYLOAD]) {
		pr_err("deliver_bundle: missing required attributes\n");
		return -EINVAL;
	}

	service_id = nla_get_u32(info->attrs[BP_GENL_A_SERVICE_ID]);
	payload = nla_data(info->attrs[BP_GENL_A_PAYLOAD]);
	payload_len = nla_len(info->attrs[BP_GENL_A_PAYLOAD]);

	new_skb = alloc_skb(payload_len, GFP_KERNEL);
	if (!new_skb) {
		pr_err("Failed to allocate sk_buff for payload\n");
		return -ENOMEM;
	}
	skb_put_data(new_skb, payload, payload_len);

	read_lock_bh(&bp_list_lock);
	sk_for_each(sk, &bp_list)
	{
		bh_lock_sock(sk);
		bp = bp_sk(sk);

		if (bp->bp_service_id == service_id) {

			skb_queue_tail(&bp->queue, new_skb);
			if (waitqueue_active(&bp->wait_queue))
				wake_up_interruptible(&bp->wait_queue);
			bh_unlock_sock(sk);
			break;
		}
		bh_unlock_sock(sk);
	}
	read_unlock_bh(&bp_list_lock);

	return 0;
}

int cancel_request_bundle_doit(u32 node_id, u32 service_id, int port_id)
{
	int ret = 0;
	void* hdr;
	struct sk_buff* msg;
	int msg_size;

	msg_size = 2 * nla_total_size(sizeof(u32));
	msg = genlmsg_new(msg_size + GENL_HDRLEN, GFP_KERNEL);
	if (!msg) {
		pr_err("cancel_bundle: failed to allocate message buffer\n");
		return -ENOMEM;
	}

	hdr = genlmsg_put(
	    msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_CANCEL_REQUEST_BUNDLE);
	if (!hdr) {
		pr_err("cancel_bundle: failed to create genetlink header\n");
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	if ((ret = nla_put_u32(msg, BP_GENL_A_SERVICE_ID, service_id))) {
		pr_err("cancel_bundle: failed to put service_id\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	if ((ret = nla_put_u32(msg, BP_GENL_A_NODE_ID, node_id))) {
		pr_err("cancel_bundle: failed to put node_id\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, hdr);
	ret = genlmsg_unicast(&init_net, msg, port_id);
	if (ret != 0) {
		pr_err("cancel_bundle: unicast failed (%d)\n", ret);
	}
	return ret;
}
