#ifndef ADU_REF_H
#define ADU_REF_H

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
struct adu_reference *find_adu_ref(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id);
Object remove_adu_ref(Sdr sdr, u_int32_t dest_node_id, u_int32_t dest_service_id);

#endif