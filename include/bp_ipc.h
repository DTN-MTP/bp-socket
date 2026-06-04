#ifndef BP_IPC_H
#define BP_IPC_H

#include <stdint.h>

typedef enum {
    BP_IPC_OPEN_ENDPOINT  = 1,
    BP_IPC_CLOSE_ENDPOINT = 2,
    BP_IPC_SEND_BUNDLE    = 3,
    BP_IPC_RECV_BUNDLE    = 4,
} bp_ipc_cmd_t;

typedef struct {
    bp_ipc_cmd_t cmd;
    uint32_t     src_node_id;
    uint32_t     src_service_id;
    uint32_t     dst_node_id;
    uint32_t     dst_service_id;
    uint32_t     flags;
    uint32_t     payload_len;
} bp_ipc_msg_t;

typedef enum {
    BP_IPC_OK  = 0,
    BP_IPC_ERR = 1,
} bp_ipc_status_t;

typedef struct {
    bp_ipc_status_t status;
} bp_ipc_response_t;

#define BP_IPC_SOCKET_PATH "/tmp/bp_daemon.sock"

#endif