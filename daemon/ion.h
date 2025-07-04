#ifndef ION_H
#define ION_H

#include <bp.h>

int bp_send_to_eid(char *payload, int payload_size, char *eid, int eid_size);
BpIndResult bp_recv_once(int service_id, char **payload);
void bp_cancel_recv_once(uint32_t node_id, uint32_t service_id);

#endif