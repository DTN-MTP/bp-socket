#ifndef ION_H
#define ION_H

#include "bp.h"

int bp_send_to_eid(Sdr sdr, char *payload, int payload_size, char *dest_eid, int eid_size);
int bp_recv_once(Sdr sdr, int service_id, char **payload);

#endif