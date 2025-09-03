#ifndef ION_H
#define ION_H

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
    struct nl_sock *netlink_sock;
    pthread_mutex_t *netlink_mutex;
    int netlink_family;
    struct endpoint_ctx *ctx;
    char *dest_eid;
    void *payload;
    size_t payload_size;
};

int ion_open_endpoint(u_int32_t node_id, u_int32_t service_id, struct nl_sock *netlink_sock,
                      pthread_mutex_t *netlink_mutex, int netlink_family);
int ion_close_endpoint(u_int32_t node_id, u_int32_t service_id);
int ion_destroy_bundle(Object adu);
void *ion_receive_thread(void *arg);
void *ion_send_thread(void *arg);

#endif