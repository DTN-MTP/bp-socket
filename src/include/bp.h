#ifndef BP_H
#define BP_H

#define AF_BP 28
#define BP_GENL_NAME "bp_genl"
#define BP_GENL_VERSION 1
#define BP_GENL_MC_GRP_NAME "bp_genl_mcgrp"

/* Attributes */
enum bp_genl_attrs
{
    BP_GENL_A_UNSPEC,
    BP_GENL_A_SOCKID,
    BP_GENL_A_AGENT_ID,
    BP_GENL_A_EID,
    BP_GENL_A_PAYLOAD,
    __BP_GENL_A_MAX,
};

#define BP_GENL_A_MAX (__BP_GENL_A_MAX - 1)

/* Commands */
enum bp_genl_cmds
{
    BP_GENL_CMD_UNSPEC,
    BP_GENL_CMD_FORWARD_BUNDLE,
    BP_GENL_CMD_REQUEST_BUNDLE,
    BP_GENL_CMD_REPLY_BUNDLE,
    __BP_GENL_CMD_MAX,
};

#define BP_GENL_CMD_MAX (__BP_GENL_CMD_MAX - 1)

static char *bp_genl_cmds_string[] = {
    "BP_GENL_CMD_UNSPEC",
    "BP_GENL_CMD_FORWARD_BUNDLE",
    "BP_GENL_CMD_REQUEST_BUNDLE",
    "BP_GENL_CMD_REPLY_BUNDLE",
};

#ifdef __KERNEL__
static const struct nla_policy nla_policy[BP_GENL_A_MAX + 1] = {
    [BP_GENL_A_UNSPEC] = {.type = NLA_UNSPEC},
    [BP_GENL_A_SOCKID] = {.type = NLA_U64},
    [BP_GENL_A_AGENT_ID] = {.type = NLA_U32},
    [BP_GENL_A_EID] = {.type = NLA_NUL_STRING},
    [BP_GENL_A_PAYLOAD] = {.type = NLA_NUL_STRING},
};
#endif

struct sockaddr_bp
{
    sa_family_t bp_family;
    u_int8_t bp_agent_id;
};

#endif