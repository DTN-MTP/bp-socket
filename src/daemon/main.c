#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "daemon.h"
#include "log.h"

int main(int argc, char *argv[])
{
	int starting_port = 8443;

	if (log_init(NULL, LOG_DEBUG))
	{
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}

	if (geteuid() != 0)
	{
		log_printf(LOG_ERROR, "Please run as root\n");
		exit(EXIT_FAILURE);
	}

	mainloop(starting_port);

	log_close();
	return 0;
}
