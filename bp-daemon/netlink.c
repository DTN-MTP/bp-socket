/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/limits.h>
#include <event2/util.h>
#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include "netlink.h"
#include "daemon.h"
#include "log.h"
#include "bp.h"
#include "../common.h"

struct thread_args
{
	struct nl_sock *netlink_sock;
	int netlink_family;
	unsigned int agent_id;
};

struct nl_sock *
nl_connect_and_configure(tls_daemon_ctx_t *ctx)
{
	int mcgrp, fam, ret;
	struct nl_sock *sk;

	sk = nl_socket_alloc();
	if (!sk)
	{
		log_printf(LOG_ERROR, "failed to allocate socket\n");
		return NULL;
	}
	nl_socket_disable_seq_check(sk);
	nl_socket_set_local_port(sk, ctx->port);
	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nl_recvmsg_cb, (void *)ctx);
	genl_connect(sk);

	/* Resolve the genl family. One family for both unicast and multicast. */
	fam = genl_ctrl_resolve(sk, GENL_BP_NAME);
	if (fam < 0)
	{
		log_printf(LOG_ERROR, "failed to resolve generic netlink family: %s\n",
				   strerror(-fam));
		return NULL;
	}

	nl_socket_set_peer_port(sk, 0);

	/* Resolve the multicast group. */
	mcgrp = genl_ctrl_resolve_grp(sk, GENL_BP_NAME, GENL_BP_MC_GRP_NAME);
	if (mcgrp < 0)
	{
		log_printf(LOG_ERROR, "failed to resolve generic netlink multicast group: %s\n",
				   strerror(-mcgrp));
		return NULL;
	}

	/* Join the multicast group. */
	if ((ret = nl_socket_add_membership(sk, mcgrp) < 0))
	{
		log_printf(LOG_ERROR, "failed to join multicast group: %s\n", strerror(-ret));
		return NULL;
	}

	ctx->netlink_sock = sk;
	ctx->netlink_family = fam;

	return sk;
}

void nl_recvmsg(evutil_socket_t fd, short events, void *arg)
{
	nl_recvmsgs_default((struct nl_sock *)arg);
	return;
}

int nl_recvmsg_cb(struct nl_msg *msg, void *arg)
{
	tls_daemon_ctx_t *ctx = (tls_daemon_ctx_t *)arg;
	struct genlmsghdr *genlhdr = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attrs[GENL_BP_A_MAX + 1];
	int err = 0;
	char *payload, *eid;
	int payload_size, eid_size;
	unsigned long sockid;

	err = nla_parse(attrs, GENL_BP_A_MAX, genlmsg_attrdata(genlhdr, 0), genlmsg_attrlen(genlhdr, 0), NULL);
	if (err)
	{
		log_printf(LOG_ERROR, "unable to parse message: %s\n", strerror(-err));
		return NL_SKIP;
	}

	switch (genlhdr->cmd)
	{
	case GENL_BP_CMD_FORWARD_BUNDLE:
		if (!attrs[GENL_BP_A_SOCKID])
		{
			log_printf(LOG_ERROR, "attribute missing from message\n");
			return NL_SKIP;
		}
		sockid = nla_get_u64(attrs[GENL_BP_A_SOCKID]);
		log_printf(LOG_INFO, "Received setsockopt notification for socket ID %lu\n", sockid);

		if (!attrs[GENL_BP_A_PAYLOAD])
		{
			log_printf(LOG_ERROR, "attribute missing from message\n");
			return NL_SKIP;
		}
		payload = nla_get_string(attrs[GENL_BP_A_PAYLOAD]);
		payload_size = strlen(payload) + 1;

		if (!attrs[GENL_BP_A_EID])
		{
			log_printf(LOG_ERROR, "attribute missing from message\n");
			return NL_SKIP;
		}
		eid = nla_get_string(attrs[GENL_BP_A_EID]);
		eid_size = strlen(eid) + 1;

		bp_send_cb(ctx, payload, payload_size, eid, eid_size);
		break;
	case GENL_BP_CMD_REQUEST_BUNDLE:
		pthread_t thread;

		if (!attrs[GENL_BP_A_AGENT_ID])
		{
			log_printf(LOG_ERROR, "attribute missing from message\n");
			return NL_SKIP;
		}

		struct thread_args *args = malloc(sizeof(struct thread_args));
		if (!args)
		{
			log_printf(LOG_ERROR, "failed to allocate memory for thread arguments\n");
			return -ENOMEM;
		}
		args->agent_id = nla_get_u32(attrs[GENL_BP_A_AGENT_ID]);
		args->netlink_family = ctx->netlink_family;
		args->netlink_sock = ctx->netlink_sock;

		if (pthread_create(&thread, NULL, start_bp_recv_agent, args) != 0)
		{
			fprintf(stderr, "Failed to create thread\n");
			free(args);
			return -1;
		}
		pthread_detach(thread);

		break;
	default:
		log_printf(LOG_ERROR, "unrecognized command\n");
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
		log_printf(LOG_ERROR, "Failed to allocate payload\n");
		return -ENOMEM;
	}

	/* Put the genl header inside message buffer */
	void *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0, GENL_BP_CMD_REPLY_BUNDLE, GENL_BP_VERSION);
	if (!hdr)
	{
		log_printf(LOG_ERROR, "Failed to put the genl header inside message buffer\n");
		return -EMSGSIZE;
	}

	/* Put the string inside the message. */
	err = nla_put_u32(msg, GENL_BP_A_AGENT_ID, agent_id);
	if (err < 0)
	{
		log_printf(LOG_ERROR, "Failed to put the agent_id attribute\n");
		return -err;
	}
	err = nla_put_string(msg, GENL_BP_A_PAYLOAD, payload);
	if (err < 0)
	{
		log_printf(LOG_ERROR, "Failed to put the payload attribute\n");
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
		log_printf(LOG_ERROR, "Failed to allocate memory");
		goto out;
	}
	snprintf(eid, eid_size, "ipn:%d.%d", nodeNbr, args->agent_id);
	log_printf(LOG_INFO, "bp_recv_agent: Agent started with EID: %s\n", eid);

	if (bp_open(eid, &txSap) < 0 || txSap == NULL)
	{
		log_printf(LOG_ERROR, "Failed to open source endpoint.\n");
		goto out;
	}

	if (bp_receive(txSap, &dlv, BP_BLOCKING) < 0)
	{
		log_printf(LOG_ERROR, "Bundle reception failed.\n");
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
			log_printf(LOG_ERROR, "Failed to allocate memory for payload.\n");
			sdr_exit_xn(sdr);
			goto out;
		}

		zco_start_receiving(dlv.adu, &reader);
		len = zco_receive_source(sdr, &reader, payload_size, payload);

		if (sdr_end_xn(sdr) < 0 || len < 0)
		{
			sdr_exit_xn(sdr);
			log_printf(LOG_ERROR, "Can't handle delivery. len = %d\n", len);
			free(payload);
			goto out;
		}

		log_printf(LOG_INFO, "bp_recv_agent: receive bundle\n");

		nl_reply_bundle(args->netlink_sock, args->netlink_family, args->agent_id, payload);

		log_printf(LOG_INFO, "bp_recv_agent: sending reply bundle to kernel\n");

		free(payload);
		break;
	default:
		log_printf(LOG_INFO, "No Bp Payload\n");
		break;
	}

	bp_release_delivery(&dlv, 0);
out:
	log_printf(LOG_INFO, "bp_recv_agent: Agent terminated with EID: %s\n", eid);

	bp_close(txSap);
	free(eid);
	free(args);
	return NULL;
}