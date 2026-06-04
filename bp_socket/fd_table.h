#ifndef FD_TABLE_H
#define FD_TABLE_H

#include <stdint.h>

typedef struct {
    int      fd;
    int      unix_fd;
    uint32_t node_id;
    uint32_t service_id;
    int      used;
} bp_fd_entry_t;

int            fd_table_add(int fd, int unix_fd, uint32_t node_id, uint32_t service_id);
int            is_bp_fd(int fd);
bp_fd_entry_t *fd_table_get(int fd);
void           fd_table_remove(int fd);

#endif