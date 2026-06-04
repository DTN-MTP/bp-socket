#include "fd_table.h"
#include <stddef.h>

#define MAX_BP_FDS 64

static bp_fd_entry_t table[MAX_BP_FDS];

int fd_table_add(int fd, int unix_fd, uint32_t node_id, uint32_t service_id) {
    for (int i = 0; i < MAX_BP_FDS; i++) {
        if (!table[i].used) {
            table[i].fd         = fd;
            table[i].unix_fd    = unix_fd;
            table[i].node_id    = node_id;
            table[i].service_id = service_id;
            table[i].used       = 1;
            return 0;
        }
    }
    return -1;
}

int is_bp_fd(int fd) {
    for (int i = 0; i < MAX_BP_FDS; i++) {
        if (table[i].used && table[i].fd == fd)
            return 1;
    }
    return 0;
}

bp_fd_entry_t *fd_table_get(int fd) {
    for (int i = 0; i < MAX_BP_FDS; i++) {
        if (table[i].used && table[i].fd == fd)
            return &table[i];
    }
    return NULL;
}

void fd_table_remove(int fd) {
    for (int i = 0; i < MAX_BP_FDS; i++) {
        if (table[i].used && table[i].fd == fd) {
            table[i].used = 0;
            return;
        }
    }
}