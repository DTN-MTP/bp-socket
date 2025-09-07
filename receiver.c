#include "bp_socket.h"
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define AF_BP 28 // Custom socket family identifier

volatile int running = 1;

void handle_sigint(int sig) {
  printf("\nInterrupt received, shutting down...\n");
  running = 0;
}

int main(int argc, char *argv[]) {
  int fd;
  struct sockaddr_bp addr_bp;
  struct msghdr msg;
  struct iovec iov;
  char buffer[BUFFER_SIZE];
  uint32_t node_id;
  uint32_t service_id;
  struct sockaddr_bp src_addr;
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

  fd = socket(AF_BP, SOCK_DGRAM, 1);
  if (fd < 0) {
    perror("socket creation failed");
    return EXIT_FAILURE;
  }
  printf("Socket created.\n");

  struct timeval tv;
  tv.tv_sec = 3;
  tv.tv_usec = 0;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("Failed to set receive timeout");
    ret = EXIT_FAILURE;
    goto out;
  }
  printf("Receive timeout set to 3 seconds.\n");

  memset(&addr_bp, 0, sizeof(addr_bp));
  addr_bp.bp_family = AF_BP;
  addr_bp.bp_scheme = BP_SCHEME_IPN;
  addr_bp.bp_addr.ipn.node_id = node_id;
  addr_bp.bp_addr.ipn.service_id = service_id;

  if (bind(fd, (struct sockaddr *)&addr_bp, sizeof(addr_bp)) == -1) {
    perror("Failed to bind socket");
    ret = EXIT_FAILURE;
    goto out;
  }

  iov.iov_base = buffer;
  iov.iov_len = sizeof(buffer);
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  memset(&src_addr, 0, sizeof(src_addr));
  msg.msg_name = &src_addr;
  msg.msg_namelen = sizeof(src_addr);

  printf("Listening for incoming messages...\n");
  printf("Press Ctrl+C to exit.\n");

  while (running) {
    ssize_t n = recvmsg(fd, &msg, 0);
    if (n < 0) {
      if (errno == EINTR) {
        // Interrupted by signal, exit gracefully
        printf("\nInterrupted by signal, exiting...\n");
        break;
      }
      if (errno == EAGAIN) {
        // Timeout occurred
        printf("Timeout waiting for message, continuing...\n");
        continue;
      }
      perror("recvmsg failed");
      ret = EXIT_FAILURE;
      goto out;
    }

    printf("Received message (%zd bytes): %.*s\n", n, (int)n, buffer);
    if (msg.msg_namelen >= sizeof(struct sockaddr_bp)) {
      printf("Bundle sent by ipn:%u.%u\n", src_addr.bp_addr.ipn.node_id,
             src_addr.bp_addr.ipn.service_id);
    } else {
      printf("Source address not available\n");
    }

    // Reset message structure for next reception
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    memset(&src_addr, 0, sizeof(src_addr));
    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(src_addr);
  }

out:
  close(fd);
  printf("Socket closed.\n");

  return ret;
}
