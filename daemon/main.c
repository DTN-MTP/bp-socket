#include "daemon.h"
#include "log.h"
#include "../include/bp_socket.h"

#define NL_PID 8443

int main(int argc, char *argv[])
{
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

	int ret = daemon_start(&daemon);
	return ret;
}
