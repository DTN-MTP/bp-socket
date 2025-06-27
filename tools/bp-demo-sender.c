#include "../include/bp_socket.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define AF_BP 28

int main(int argc, char *argv[]) {
  int sockfd, ret;
  uint32_t node_id, service_id;

  if (argc < 3) {
    printf("Usage: %s <node_id> <service_id>\n", argv[0]);
    return EXIT_FAILURE;
  }

  // Parse arguments
  node_id = (uint32_t)atoi(argv[1]);
  service_id = (uint32_t)atoi(argv[2]);

  if (service_id < 1 || service_id > 255) {
    fprintf(stderr, "Invalid service_id (must be in 1-255)\n");
    return EXIT_FAILURE;
  }

  if (node_id == 0) {
    fprintf(stderr, "Invalid node_id (cannot be 0)\n");
    return EXIT_FAILURE;
  }

  // Create a socket
  sockfd = socket(AF_BP, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket creation failed");
    return EXIT_FAILURE;
  }

  // Prepare sockaddr_bp
  struct sockaddr_bp dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.bp_family = AF_BP;
  dest_addr.bp_scheme = BP_SCHEME_IPN;
  dest_addr.bp_addr.ipn.node_id = node_id;
  dest_addr.bp_addr.ipn.service_id = service_id;

  // Message to send
  const char *message = "Hello!";

  ret = sendto(sockfd, message, strlen(message) + 1, 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (ret < 0) {
    perror("sendto failed");
    close(sockfd);
    return EXIT_FAILURE;
  }

  printf("Message sent successfully: %s\n", message);

  // Clean up
  close(sockfd);

  return EXIT_SUCCESS;
}
