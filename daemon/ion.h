#ifndef ION_H
#define ION_H

#include <bp.h>

struct sap_node {
    BpSAP sap;
    uint32_t node_id;
    uint32_t service_id;
    struct sap_node *next;
};

void sap_list_add(BpSAP sap, uint32_t node_id, uint32_t service_id);
void sap_list_remove(BpSAP sap);
BpSAP sap_list_find(uint32_t node_id, uint32_t service_id);

int bp_send_to_eid(char *payload, int payload_size, char *eid, int eid_size);
BpIndResult bp_recv_once(int service_id, char **payload);
void bp_cancel_recv_once(uint32_t node_id, uint32_t service_id);

#endif