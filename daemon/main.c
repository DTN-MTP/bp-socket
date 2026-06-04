#include "daemon.h"
#include "log.h"
#include <stdlib.h>

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    Daemon daemon = {
        .base = NULL,
        .event_on_sigpipe = NULL,
        .event_on_sigint = NULL,
    };

    if (daemon_run(&daemon) < 0) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}