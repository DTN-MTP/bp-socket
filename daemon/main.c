#include "../include/bp_socket.h"
#include "daemon.h"
#include "log.h"
#include <stdlib.h>
#include <unistd.h>

#define NL_PID 8443

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        log_error("This program must be run as root or with CAP_NET_ADMIN (required by "
                  "GENL_ADMIN_PERM).");
        return EXIT_FAILURE;
    }

    Daemon daemon = {
        .genl_bp_sock = NULL,
        .genl_bp_family_name = BP_GENL_NAME,
        .genl_bp_family_id = -1,
        .nl_pid = NL_PID,

        .base = NULL,
        .event_on_sigpipe = NULL,
        .event_on_sigint = NULL,
        .event_on_nl_sock = NULL,
    };

    if (daemon_run(&daemon) < 0) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
