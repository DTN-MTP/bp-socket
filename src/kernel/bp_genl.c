#include <net/genetlink.h>
#include "../include/bp.h"
#include "bp_genl.h"
#include "af_bp.h"

static struct genl_ops genl_ops[] = {
	// {
	// 	.cmd = BP_GENL_CMD_FORWARD_BUNDLE,
	// 	.flags = GENL_ADMIN_PERM,
	// 	.policy = nla_policy,
	// 	.doit = fail_doit,
	// 	.dumpit = NULL,
	// },
	{
		.cmd = BP_GENL_CMD_REPLY_BUNDLE,
		.flags = GENL_ADMIN_PERM,
		.policy = nla_policy,
		.doit = recv_reply_bundle_doit,
		.dumpit = NULL,
	}};

/* Multicast groups for our family */
static const struct genl_multicast_group genl_mcgrps[] = {
	{.name = BP_GENL_MC_GRP_NAME},
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

int fail_doit(struct sk_buff *skb, struct genl_info *info)
{
	pr_alert("Kernel receieved an SSA netlink notification. This should never happen.\n");
	return -1;
}

int send_bundle_doit(u64 sockid, char *payload, int payload_size, char *eid, int eid_size, int port_id)
{
	int ret = 0;
	void *hdr;
	struct sk_buff *msg;
	int msg_size;

	/* Allocate a new buffer for the reply */
	msg_size = nla_total_size(sizeof(u64)) +
			   nla_total_size(eid_size) +
			   nla_total_size(payload_size);
	msg = genlmsg_new(msg_size + GENL_HDRLEN, GFP_KERNEL);
	if (!msg)
	{
		pr_err("failed to allocate message buffer\n");
		return -ENOMEM;
	}

	/* Put the Generic Netlink header */
	hdr = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_FORWARD_BUNDLE);
	if (!hdr)
	{
		pr_err("failed to create genetlink header\n");
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	/* And the message */
	if ((ret = nla_put_string(msg, BP_GENL_A_PAYLOAD, payload)))
	{
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}
	if ((ret = nla_put_string(msg, BP_GENL_A_EID, eid)))
	{
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}
	if ((ret = nla_put_u64_64bit(msg, BP_GENL_A_SOCKID, sockid, 0)))
	{
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}

	/* Finalize the message and send it */
	genlmsg_end(msg, hdr);
	ret = genlmsg_unicast(&init_net, msg, port_id);
	if (ret != 0)
	{
		pr_alert("Failed in gemlmsg_unicast [setsockopt notify]\n (%d)", ret);
	}

out:
	return ret;
}

int notify_deamon_doit(u32 agent_id, int port_id)
{
	int ret = 0;
	void *hdr;
	struct sk_buff *msg;
	int msg_size;

	/* Allocate a new buffer for the reply */
	msg_size = nla_total_size(sizeof(u32));
	msg = genlmsg_new(msg_size + GENL_HDRLEN, GFP_KERNEL);
	if (!msg)
	{
		pr_err("failed to allocate message buffer\n");
		return -ENOMEM;
	}

	/* Put the Generic Netlink header */
	hdr = genlmsg_put(msg, 0, 0, &genl_fam, 0, BP_GENL_CMD_REQUEST_BUNDLE);
	if (!hdr)
	{
		pr_err("failed to create genetlink header\n");
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	/* And the message */
	if ((ret = nla_put_u32(msg, BP_GENL_A_AGENT_ID, agent_id)))
	{
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}

	/* Finalize the message and send it */
	genlmsg_end(msg, hdr);
	ret = genlmsg_unicast(&init_net, msg, port_id);
	if (ret != 0)
	{
		pr_alert("Failed in gemlmsg_unicast [setsockopt notify]\n (%d)", ret);
	}

out:
	return ret;
}

int recv_reply_bundle_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct sock *sk;
	struct bp_sock *bp;
	u32 agent_id;
	char *payload;
	size_t payload_len;
	struct sk_buff *new_skb;

	pr_info("TRIGGER: received message\n");

	if (!info->attrs[BP_GENL_A_AGENT_ID])
	{
		pr_err("attribute missing from message\n");
		return -EINVAL;
	}
	agent_id = nla_get_u32(info->attrs[BP_GENL_A_AGENT_ID]);

	if (!info->attrs[BP_GENL_A_PAYLOAD])
	{
		pr_err("empty message received\n");
		return -EINVAL;
	}
	payload = nla_data(info->attrs[BP_GENL_A_PAYLOAD]);
	payload_len = nla_len(info->attrs[BP_GENL_A_PAYLOAD]);

	pr_info("Message for agent %d: %s\n", agent_id, payload);

	new_skb = alloc_skb(payload_len, GFP_KERNEL);
	if (!new_skb)
	{
		pr_err("Failed to allocate sk_buff for payload\n");
		return -ENOMEM;
	}
	skb_put_data(new_skb, payload, payload_len);

	read_lock_bh(&bp_list_lock);
	sk_for_each(sk, &bp_list)
	{
		bp = bp_sk(sk);

		if (bp->bp_agent_id == agent_id)
		{

			skb_queue_tail(&bp->queue, new_skb);
			wake_up_interruptible(&bp->wait_queue);
			pr_info("Payload queued successfully for agent: %d\n", bp->bp_agent_id);
			break;
		}
	}
	read_unlock_bh(&bp_list_lock);

	return 0;
}
