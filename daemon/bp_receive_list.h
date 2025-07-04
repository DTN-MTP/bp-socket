#ifndef RECEIVE_LIST_H
#define RECEIVE_LIST_H

#include <bp.h>
#include <stdint.h>

void bp_receive_list_add(uint32_t node_id, uint32_t service_id, BpSAP* sap);
BpSAP* bp_receive_list_find(uint32_t node_id, uint32_t service_id);
void bp_receive_list_remove(uint32_t node_id, uint32_t service_id);
void bp_receive_list_clear(void);

#endif