#include "include/bp_socket.h"
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
  struct msghdr msg;
  struct iovec iov;
  char buffer[BUFFER_SIZE];
  uint32_t node_id;
  uint32_t service_id;
  int ret = 0;

  if (argc < 3) {
    printf("Usage: %s <node_id> <service_id>\n", argv[0]);
    return EXIT_FAILURE;
  }

  signal(SIGINT, handle_sigint);

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

  sfd = socket(AF_BP, SOCK_DGRAM, 1);
  if (sfd < 0) {
    perror("socket creation failed");
    return EXIT_FAILURE;
  }
  printf("Socket created.\n");

  memset(&addr_bp, 0, sizeof(addr_bp));
  addr_bp.bp_family = AF_BP;
  addr_bp.bp_scheme = BP_SCHEME_IPN;
  addr_bp.bp_addr.ipn.node_id = node_id;
  addr_bp.bp_addr.ipn.service_id = service_id;

  if (bind(sfd, (struct sockaddr *)&addr_bp, sizeof(addr_bp)) == -1) {
    perror("Failed to bind socket");
    ret = EXIT_FAILURE;
    goto out;
  }

  iov.iov_base = buffer;
  iov.iov_len = sizeof(buffer);
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  printf("Listening for incoming messages...\n");
  ssize_t n = recvmsg(sfd, &msg, 0);
  if (n < 0) {
      perror("recvmsg failed");
      ret = EXIT_FAILURE;
      goto out;
  }
  
  printf("Received message (%zd bytes): %.*s\n", n, (int)n, buffer);

out:
  close(sfd);
  printf("Socket closed.\n");

  return ret;
}
