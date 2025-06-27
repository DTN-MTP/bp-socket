#include "../include/bp_socket.h"
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define AF_BP 28 // Custom socket family identifier

void handle_sigint(int sig) {
  printf("\nInterrupt received, shutting down...\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  int sfd;
  struct sockaddr_bp addr_bp;
  char buffer[BUFFER_SIZE];
  struct iovec iov[1];
  struct msghdr *msg;
  uint32_t node_id;
  uint32_t service_id;
  int ret = 0;

  if (argc < 3) {
    printf("Usage: %s <node_id> <service_id>\n", argv[0]);
    return EXIT_FAILURE;
  }

  signal(SIGINT, handle_sigint);

  // Parse arguments
  node_id = (uint32_t)atoi(argv[1]);
  service_id = (uint32_t)atoi(argv[2]);

  if (service_id < 1 || service_id > 255) {
    fprintf(stderr, "Invalid service_id (must be in 1-255)\n");
    return EXIT_FAILURE;
  }

  if (node_id < 1) {
    fprintf(stderr, "Invalid node_id (must be > 0)\n");
    return EXIT_FAILURE;
  }

  // Create the socket
  sfd = socket(AF_BP, SOCK_DGRAM, 1);
  if (sfd < 0) {
    perror("socket creation failed");
    return EXIT_FAILURE;
  }
  printf("Socket created.\n");

  // Fill sockaddr_bp
  memset(&addr_bp, 0, sizeof(addr_bp));
  addr_bp.bp_family = AF_BP;
  addr_bp.bp_scheme = BP_SCHEME_IPN;
  addr_bp.bp_addr.ipn.node_id = node_id;
  addr_bp.bp_addr.ipn.service_id = service_id;

  // Bind the socket
  if (bind(sfd, (struct sockaddr *)&addr_bp, sizeof(addr_bp)) == -1) {
    perror("Failed to bind socket");
    ret = EXIT_FAILURE;
    goto out;
  }

  // Prepare for receiving messages
  msg = (struct msghdr *)malloc(sizeof(struct msghdr));
  if (!msg) {
    perror("malloc failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = buffer;
  iov[0].iov_len = sizeof(buffer);

  memset(msg, 0, sizeof(struct msghdr));
  msg->msg_iov = iov;
  msg->msg_iovlen = 1;

  printf("Listening for incoming messages...\n");
  ssize_t n = recvmsg(sfd, msg, 0);
  if (n < 0) {
    perror("Failed to receive message");
    ret = EXIT_FAILURE;
    goto out_free;
  } else {
    printf("Message received (%zd bytes): %s\n", n, buffer);
  }

out_free:
  free(msg);
out:
  close(sfd);
  printf("Socket closed.\n");

  return ret;
}
