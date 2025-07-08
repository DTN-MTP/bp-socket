#ifndef BP_SAP_REGISTRY_H
#define BP_SAP_REGISTRY_H

#include <bp.h>
#include <stdint.h>

void bp_sap_registry_add(uint32_t node_id, uint32_t service_id, BpSAP sap);
BpSAP bp_sap_registry_find(uint32_t node_id, uint32_t service_id);
void bp_sap_registry_remove(uint32_t node_id, uint32_t service_id);
void bp_sap_registry_clear(void);

#endif