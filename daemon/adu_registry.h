#ifndef ADU_REGISTRY_H
#define ADU_REGISTRY_H

#include "bp.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct adu_key {
    uint32_t node_id;
    uint32_t service_id;
} adu_key_t;

typedef struct adu_node {
    adu_key_t key;
    uint32_t src_node_id;
    uint32_t src_service_id;
    Object adu;
    struct adu_node *next;
} adu_node_t;

bool adu_registry_contains(uint32_t node_id, uint32_t service_id);
int adu_registry_add(Object adu, uint32_t dest_node_id, uint32_t dest_service_id,
                     uint32_t src_node_id, uint32_t src_service_id);
adu_node_t *adu_registry_get(uint32_t node_id, uint32_t service_id);
Object adu_registry_remove(uint32_t node_id, uint32_t service_id);

#endif
