#ifndef SAP_REGISTRY_H
#define SAP_REGISTRY_H

#include "bp.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct sap_key {
    uint32_t node_id;
    uint32_t service_id;
} sap_key_t;

typedef struct sap_node {
    sap_key_t key;
    BpSAP sap;
    bool has_active_receive;
    struct sap_node *next;
} sap_node_t;

bool sap_registry_contains(uint32_t node_id, uint32_t service_id);
int sap_registry_add(uint32_t node_id, uint32_t service_id, BpSAP sap);
BpSAP sap_registry_get(uint32_t node_id, uint32_t service_id);
int sap_registry_remove(uint32_t node_id, uint32_t service_id);

// Helper functions for receive thread tracking
void sap_registry_mark_receive_active(uint32_t node_id, uint32_t service_id);
void sap_registry_mark_receive_inactive(uint32_t node_id, uint32_t service_id);
bool sap_registry_has_active_receive(uint32_t node_id, uint32_t service_id);

#endif
