#ifndef BP_SOCKET_H
#define BP_SOCKET_H

#ifdef __KERNEL__
#include <linux/socket.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/socket.h>
#endif

#define AF_BP 28
#define BP_GENL_NAME "bp_genl"
#define BP_GENL_VERSION 1
#define BP_GENL_MC_GRP_NAME "bp_genl_mcgrp"

/* Generic Netlink attributes */
enum bp_genl_attrs {
  BP_GENL_A_UNSPEC,
  BP_GENL_A_SRC_NODE_ID,
  BP_GENL_A_SRC_SERVICE_ID,
  BP_GENL_A_DEST_NODE_ID,
  BP_GENL_A_DEST_SERVICE_ID,
  BP_GENL_A_PAYLOAD,
  BP_GENL_A_ADU,
  BP_GENL_A_FLAGS,
  __BP_GENL_A_MAX,
};
#define BP_GENL_A_MAX (__BP_GENL_A_MAX - 1)

/* Bundle Protocol socket flags */
/* ackRequested flag */
#define MSG_ACK_REQUESTED 0x00000001

/* Status reporting flags (srrFlags) - can be combined with OR */
#define MSG_RECEIVED_RPT 0x00000002
#define MSG_CUSTODY_RPT 0x00000004
#define MSG_FORWARDED_RPT 0x00000008
#define MSG_DELIVERED_RPT 0x00000010
#define MSG_DELETED_RPT 0x00000020

/* Priority flags (classOfService) - mutually exclusive */
#define MSG_BP_BULK_PRIORITY 0x00000100
#define MSG_BP_STD_PRIORITY 0x00000200
#define MSG_BP_EXPEDITED_PRIORITY 0x00000400

/* Custody flags (custodySwitch) - mutually exclusive */
#define MSG_SOURCE_CUSTODY_REQUIRED 0x00001000
#define MSG_SOURCE_CUSTODY_OPTIONAL 0x00002000
#define MSG_NO_CUSTODY_REQUIRED 0x00004000

/* Commands */
enum bp_genl_cmds {
  BP_GENL_CMD_UNSPEC,
  BP_GENL_CMD_SEND_BUNDLE,
  BP_GENL_CMD_ENQUEUE_BUNDLE,
  BP_GENL_CMD_DESTROY_BUNDLE,
  BP_GENL_CMD_OPEN_ENDPOINT,
  BP_GENL_CMD_CLOSE_ENDPOINT,
  __BP_GENL_CMD_MAX,
};

#define BP_GENL_CMD_MAX (__BP_GENL_CMD_MAX - 1)

typedef enum bp_scheme {
  BP_SCHEME_IPN = 1,
  BP_SCHEME_DTN = 2,
} bp_scheme_t;

struct sockaddr_bp {
  sa_family_t bp_family;
  bp_scheme_t bp_scheme;
  union {
    struct {
      uint32_t node_id;
      uint32_t service_id;
    } ipn;
  } bp_addr;
};

#endif