#include <linux/limits.h>
#include <event2/util.h>
#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include "bp_genl.h"
#include "daemon.h"
#include "ion.h"
#include "log.h"
#include "bp.h"
#include "../include/bp.h"

struct nl_sock *genl_bp_sock_init(Daemon *daemon)
{
	struct nl_sock *sk = nl_socket_alloc();
	if (!sk)
	{
		log_error("Failed to allocate Netlink socket");
		return NULL;
	}

	nl_socket_set_local_port(sk, daemon->nl_pid);
	nl_socket_disable_seq_check(sk);
	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, genl_bp_sock_recvmsg_cb, daemon);
	nl_socket_set_peer_port(sk, 0); // Send to kernel

	int err = genl_connect(sk);
	if (err < 0)
	{
		log_error("genl_connect() failed: %s", nl_geterror(err));
		nl_socket_free(sk);
		return NULL;
	}

	int family_id = genl_ctrl_resolve(sk, daemon->genl_bp_family_name);
	if (family_id < 0)
	{
		log_error("Failed to resolve family '%s': %s",
				  daemon->genl_bp_family_name, nl_geterror(family_id));
		nl_socket_free(sk);
		return NULL;
	}

	daemon->genl_bp_family_id = family_id;
	return sk;
}

void genl_bp_sock_close(Daemon *daemon)
{
	if (!daemon->genl_bp_sock)
		return;

	nl_socket_free(daemon->genl_bp_sock);
	log_info("Netlink socket closed");

	daemon->genl_bp_family_id = -1;
}

int genl_bp_sock_recvmsg_cb(struct nl_msg *msg, void *arg)
{
	Daemon *daemon = (Daemon *)arg;
	struct genlmsghdr *genlhdr = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attrs[BP_GENL_A_MAX + 1];
	int err = 0;
	char *payload, *eid;
	int payload_size, eid_size;
	unsigned long sockid;

	err = nla_parse(attrs, BP_GENL_A_MAX, genlmsg_attrdata(genlhdr, 0), genlmsg_attrlen(genlhdr, 0), NULL);
	if (err)
	{
		log_error("unable to parse message: %s", strerror(-err));
		return NL_SKIP;
	}

	switch (genlhdr->cmd)
	{
	case BP_GENL_CMD_FORWARD_BUNDLE:
		if (!attrs[BP_GENL_A_SOCKID])
		{
			log_error("attribute missing from message");
			return NL_SKIP;
		}
		sockid = nla_get_u64(attrs[BP_GENL_A_SOCKID]);
		log_info("Received notification for socket ID %lu", sockid);

		if (!attrs[BP_GENL_A_PAYLOAD])
		{
			log_error("attribute missing from message");
			return NL_SKIP;
		}
		payload = nla_get_string(attrs[BP_GENL_A_PAYLOAD]);
		payload_size = strlen(payload) + 1;

		if (!attrs[BP_GENL_A_EID])
		{
			log_error("attribute missing from message");
			return NL_SKIP;
		}
		eid = nla_get_string(attrs[BP_GENL_A_EID]);
		eid_size = strlen(eid) + 1;

		bp_send_to_eid(payload, payload_size, eid, eid_size);
		break;
	case BP_GENL_CMD_REQUEST_BUNDLE:
		pthread_t thread;

		if (!attrs[BP_GENL_A_AGENT_ID])
		{
			log_error("attribute missing from message");
			return NL_SKIP;
		}

		struct thread_args *args = malloc(sizeof(struct thread_args));
		if (!args)
		{
			log_error("failed to allocate memory for thread arguments");
			return -ENOMEM;
		}
		args->agent_id = nla_get_u32(attrs[BP_GENL_A_AGENT_ID]);
		args->netlink_family = daemon->genl_bp_family_id;
		args->netlink_sock = daemon->genl_bp_sock;

		if (pthread_create(&thread, NULL, start_bp_recv_agent, args) != 0)
		{
			fprintf(stderr, "Failed to create thread");
			free(args);
			return -1;
		}
		pthread_detach(thread);

		break;
	default:
		log_error("unrecognized command");
		break;
	}

	return 0;
}

int nl_reply_bundle(struct nl_sock *netlink_sock, int netlink_family, unsigned int agent_id, char *payload)
{

	int err = 0;
	size_t msg_size = NLMSG_SPACE(nla_total_size(strlen(payload) + 1) + nla_total_size(sizeof(unsigned int)));
	struct nl_msg *msg = nlmsg_alloc_size(msg_size + GENL_HDRLEN);
	if (!msg)
	{
		log_error("Failed to allocate payload");
		return -ENOMEM;
	}

	/* Put the genl header inside message buffer */
	void *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0, BP_GENL_CMD_REPLY_BUNDLE, BP_GENL_VERSION);
	if (!hdr)
	{
		log_error("Failed to put the genl header inside message buffer");
		return -EMSGSIZE;
	}

	/* Put the string inside the message. */
	err = nla_put_u32(msg, BP_GENL_A_AGENT_ID, agent_id);
	if (err < 0)
	{
		log_error("Failed to put the agent_id attribute");
		return -err;
	}
	err = nla_put_string(msg, BP_GENL_A_PAYLOAD, payload);
	if (err < 0)
	{
		log_error("Failed to put the payload attribute");
		return -err;
	}

	/* Send the message. */
	err = nl_send_auto(netlink_sock, msg);
	err = err >= 0 ? 0 : err;

	nlmsg_free(msg);

	return err;
}

void *start_bp_recv_agent(void *arg)
{
	struct thread_args *args = (struct thread_args *)arg;

	BpSAP txSap;
	BpDelivery dlv;
	char *payload;
	int payload_size;
	Sdr sdr = getIonsdr();
	vast len;
	ZcoReader reader;
	char *eid;
	int eid_size;
	int nodeNbr = getOwnNodeNbr();

	eid_size = snprintf(NULL, 0, "ipn:%d.%d", nodeNbr, args->agent_id) + 1;
	eid = malloc(eid_size);
	if (!eid)
	{
		log_error("Failed to allocate memory");
		goto out;
	}
	snprintf(eid, eid_size, "ipn:%d.%d", nodeNbr, args->agent_id);
	log_info("bp_recv_agent: Agent started with EID: %s", eid);

	if (bp_open(eid, &txSap) < 0 || txSap == NULL)
	{
		log_error("Failed to open source endpoint.");
		goto out;
	}

	if (bp_receive(txSap, &dlv, BP_BLOCKING) < 0)
	{
		log_error("Bundle reception failed.");
		goto out;
	}

	switch (dlv.result)
	{
	case BpPayloadPresent:
		CHKVOID(sdr_begin_xn(sdr));
		payload_size = zco_source_data_length(sdr, dlv.adu);
		payload = malloc((size_t)payload_size);
		if (!payload)
		{
			log_error("Failed to allocate memory for payload.");
			sdr_exit_xn(sdr);
			goto out;
		}

		zco_start_receiving(dlv.adu, &reader);
		len = zco_receive_source(sdr, &reader, payload_size, payload);

		if (sdr_end_xn(sdr) < 0 || len < 0)
		{
			sdr_exit_xn(sdr);
			log_error("Can't handle delivery. len = %d", len);
			free(payload);
			goto out;
		}

		log_info("bp_recv_agent: receive bundle");

		nl_reply_bundle(args->netlink_sock, args->netlink_family, args->agent_id, payload);

		log_info("bp_recv_agent: sending reply bundle to kernel");

		free(payload);
		break;
	default:
		log_info("No Bp Payload");
		break;
	}

	bp_release_delivery(&dlv, 0);
out:
	log_info("bp_recv_agent: Agent terminated with EID: %s", eid);

	bp_close(txSap);
	free(eid);
	free(args);
	return NULL;
}