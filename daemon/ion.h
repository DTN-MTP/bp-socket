#ifndef ION_H
#define ION_H

#include "../include/bp_socket.h"
#include "bp.h"
#include <pthread.h>
#include <stdbool.h>

extern Sdr sdr;

struct ion_recv_args {
    struct nl_sock *netlink_sock;
    pthread_mutex_t *netlink_mutex;
    int netlink_family;
    struct endpoint_ctx *ctx;
};

struct ion_send_args {
    struct endpoint_ctx *ctx;
};

struct bp_send_flags {
    bool ack_requested;
    unsigned char srr_flags;
    int class_of_service;
    BpCustodySwitch custody_switch;
};

// Helper function to parse flags into structured format
static inline struct bp_send_flags bp_parse_flags(u_int32_t flags) {
    struct bp_send_flags result = {
        .ack_requested = (flags & MSG_ACK_REQUESTED) != 0,
        .srr_flags = 0,
        .class_of_service = BP_STD_PRIORITY,
        .custody_switch = NoCustodyRequested,
    };

    // Status reporting flags
    if (flags & MSG_RECEIVED_RPT) result.srr_flags |= BP_RECEIVED_RPT;
    if (flags & MSG_CUSTODY_RPT) result.srr_flags |= BP_CUSTODY_RPT;
    if (flags & MSG_FORWARDED_RPT) result.srr_flags |= BP_FORWARDED_RPT;
    if (flags & MSG_DELIVERED_RPT) result.srr_flags |= BP_DELIVERED_RPT;
    if (flags & MSG_DELETED_RPT) result.srr_flags |= BP_DELETED_RPT;

    // Priority flags (mutually exclusive)
    if (flags & MSG_BP_BULK_PRIORITY)
        result.class_of_service = BP_BULK_PRIORITY;
    else if (flags & MSG_BP_EXPEDITED_PRIORITY)
        result.class_of_service = BP_EXPEDITED_PRIORITY;

    // Custody flags (mutually exclusive)
    if (flags & MSG_SOURCE_CUSTODY_REQUIRED)
        result.custody_switch = SourceCustodyRequired;
    else if (flags & MSG_SOURCE_CUSTODY_OPTIONAL)
        result.custody_switch = SourceCustodyOptional;

    return result;
}

int ion_open_endpoint(u_int32_t node_id, u_int32_t service_id, struct nl_sock *netlink_sock,
                      pthread_mutex_t *netlink_mutex, int netlink_family);
int ion_close_endpoint(u_int32_t node_id, u_int32_t service_id);
int ion_destroy_bundle(Object adu);
void *ion_receive_thread(void *arg);
void *ion_send_thread(void *arg);

#endif