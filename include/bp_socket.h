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
  __BP_GENL_A_MAX,
};

#define BP_GENL_A_MAX (__BP_GENL_A_MAX - 1)

/* Commands */
enum bp_genl_cmds {
  BP_GENL_CMD_UNSPEC,
  BP_GENL_CMD_SEND_BUNDLE,
  BP_GENL_CMD_REQUEST_BUNDLE,
  BP_GENL_CMD_CANCEL_BUNDLE_REQUEST,
  BP_GENL_CMD_DELIVER_BUNDLE,
  BP_GENL_CMD_DESTROY_BUNDLE,
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