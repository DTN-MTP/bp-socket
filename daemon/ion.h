#ifndef ION_H
#define ION_H

#include "bp.h"
#include <stdbool.h>

struct reply_bundle {
    bool is_present;
    void *payload;
    size_t payload_size;
    u_int32_t src_node_id;
    u_int32_t src_service_id;
};

int destroy_bundle(Sdr sdr, Object adu);
int bp_send_to_eid(Sdr sdr, void *payload, size_t payload_size, const char *dest_eid);
struct reply_bundle bp_recv_once(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id);

#endif