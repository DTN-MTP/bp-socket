#ifndef ION_H
#define ION_H

#include <bp.h>

int bp_open_and_register(uint32_t node_id, uint32_t service_id);
int bp_close_and_unregister(uint32_t node_id, uint32_t service_id);
int bp_send_to_eid(char *payload, int payload_size, char *eid, int eid_size);
int bp_recv_once(Sdr sdr, int service_id, char **payload);
void bp_cancel_recv_once(uint32_t node_id, uint32_t service_id);

#endif