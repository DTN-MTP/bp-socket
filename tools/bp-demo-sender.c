#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../src/include/bp.h"

#define PORT 12345

#define AF_BP 28

int main(int argc, char *argv[])
{
    int sockfd, ret;
    // struct sockaddr_in sa; // Standard socket address structure
    if (argc < 2)
    {
        printf("Usage: %s <argument>\n", argv[0]);
        return EXIT_FAILURE;
    }



    // Create a socket
    sockfd = socket(AF_BP, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket creation failed");
        return EXIT_FAILURE;
    }

    // Prepare destination address
    // memset(&sa, 0, sizeof(sa));
    // sa.sin_family = AF_INET;
    // sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Use loopback address
    // sa.sin_port = htons(PORT); // Replace with your port number

    // with plain sockaddr (maybe introduce a struct sockaddr_bp ??)
    struct sockaddr_bp eid_addr;
    eid_addr.bp_family = AF_BP;

    // Verify that the eid does not surpass the allocated space for it
    // Accepting maximum 125 characters + null term
    if (1 + strlen(argv[1]) > sizeof(eid_addr.eid_str)) {
        perror("EID is too long") ;
        return EXIT_FAILURE ;
    }

    strncpy(eid_addr.eid_str, argv[1], sizeof(eid_addr.eid_str));

    // Send a message
    const char *message = "Hello!";

    ret = sendto(sockfd, message, strlen(message) + 1, 0, &eid_addr, sizeof(eid_addr));
    if (ret < 0)
    {
        perror("sendto failed");
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("Message sent successfully: %s\n", message);

    // Clean up
    close(sockfd);

    return EXIT_SUCCESS;
}
