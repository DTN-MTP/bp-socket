#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "../src/include/bp.h"

#define BUFFER_SIZE 1024
#define AF_BP 28 // Custom socket family identifier

void handle_sigint(int sig)
{
    printf("\nInterrupt received, shutting down...\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int sfd;
    struct sockaddr_bp addr_bp;
    char buffer[80];
    struct iovec iov[1];
    struct msghdr *msg;
    unsigned int agent_id;
    int ret = 0;

    if (argc < 2)
    {
        printf("Usage: %s <eid>\n", argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_sigint);

    // Create the socket
    sfd = socket(AF_BP, SOCK_DGRAM, 1);
    if (sfd < 0)
    {
        perror("socket creation failed");
        return EXIT_FAILURE;
    }
    printf("Socket created.\n");
    agent_id = atoi(argv[1]);
    addr_bp.bp_family = AF_BP;

    // Verify that the eid does not surpass the allocated space for it
    // Accepting maximum 125 characters
    if (1+ strlen(argv[1]) >= sizeof(addr_bp.eid_str)) {
        perror("EID is too long") ;
        return EXIT_FAILURE ;
    }

    strcpy(addr_bp.eid_str, argv[1]) ; // Ajoute automatique le \0
    addr_bp.eid_str[sizeof(addr_bp.eid_str)-1 ] = '\0'; // \0 de limite


    if (bind(sfd, (struct sockaddr *)&addr_bp, sizeof(addr_bp)) == -1)
    {
        perror("Failed to bind socket");
        ret = EXIT_FAILURE;
        goto out;
    }

    msg = (struct msghdr *)malloc(sizeof(struct msghdr));
    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer);
    memset(msg, 0, sizeof(struct msghdr));
    msg->msg_iov = iov;
    msg->msg_iovlen = 1;

    printf("Listening for incoming messages...\n");
    if (recvmsg(sfd, msg, 0) < 0)
    {
        perror("Failed to receive message");
        ret = EXIT_FAILURE;
        goto out;
    }
    else
    {
        printf("Message received: %s\n", buffer);
    }

out:
    free(msg);
    close(sfd);
    printf("Socket closed.\n");

    return ret;
}
