#ifndef ION_H
#define ION_H

#include "bp.h"

struct adu_reference {
    Object adu;
    u_int32_t dest_node_id;
    u_int32_t dest_service_id;
    u_int32_t src_node_id;
    u_int32_t src_service_id;
    struct adu_reference *next;
};

int add_adu(Sdr sdr, Object adu, u_int32_t dest_node_id, u_int32_t dest_service_id,
            u_int32_t src_node_id, u_int32_t src_service_id);
Object find_adu(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id);
int destroy_adu(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id);

int bp_send_to_eid(Sdr sdr, void *payload, size_t payload_size, char *dest_eid);
void *bp_recv_once(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id, size_t *payload_size,
                   u_int32_t *src_node_id, u_int32_t *src_service_id);

#endif