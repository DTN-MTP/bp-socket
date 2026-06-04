#ifndef UNIX_IPC_H
#define UNIX_IPC_H

#include "daemon.h"
#include <stddef.h>
#include <stdint.h>

int unix_ipc_init(Daemon *daemon);
int unix_ipc_send_bundle(void *payload, size_t payload_size, uint32_t src_node_id,
                         uint32_t src_service_id, uint32_t dst_node_id, uint32_t dst_service_id,
                         uint64_t adu);

#endif