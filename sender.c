#include "include/bp_socket.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define AF_BP 28

int main(int argc, char *argv[]) {
  struct sockaddr_bp dest_addr;
  int fd;
  uint32_t node_id, service_id;
  int ret = 0;

  if (argc < 3) {
    printf("Usage: %s <node_id> <service_id>\n", argv[0]);
    return EXIT_FAILURE;
  }

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

  fd = socket(AF_BP, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket creation failed");
    return EXIT_FAILURE;
  }

  dest_addr.bp_family = AF_BP;
  dest_addr.bp_scheme = BP_SCHEME_IPN;
  dest_addr.bp_addr.ipn.node_id = node_id;
  dest_addr.bp_addr.ipn.service_id = service_id;

  char *message = "Hello!";
  ret = sendto(fd, message, strlen(message) + 1, 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (ret < 0) {
    perror("sendto failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  printf("Message sent successfully: %s\n", message);

out:
  close(fd);
  return ret;
}
