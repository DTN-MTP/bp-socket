#ifndef ION_H
#define ION_H

int bp_send_to_eid(char *payload, int payload_size, char *eid, int eid_size);
char *bp_recv_once(int agent_id);

#endif