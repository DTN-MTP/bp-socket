#ifndef ION_H
#define ION_H

#include "bp.h"
#include <stdbool.h>

extern Sdr sdr;

struct ion_recv_args {
    struct nl_sock *netlink_sock;
    int netlink_family;
    u_int32_t node_id;
    u_int32_t service_id;
};

struct ion_send_args {
    struct nl_sock *netlink_sock;
    int netlink_family;
    u_int32_t src_node_id;
    u_int32_t src_service_id;
    char *dest_eid;
    void *payload;
    size_t payload_size;
};

int ion_open_endpoint(u_int32_t node_id, u_int32_t service_id);
int ion_close_endpoint(u_int32_t node_id, u_int32_t service_id);
int ion_destroy_bundle(Object adu);
void *ion_receive_thread(void *arg);
void *ion_send_thread(void *arg);

#endif