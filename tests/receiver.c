#include "../include/bp_socket.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define AF_BP 28
#define BUFFER_SIZE (1024)

void receive_and_check(int sfd) {
  char buf[BUFFER_SIZE];
  ssize_t n = recv(sfd, buf, sizeof(buf), 0);
  if (n < 0) {
    fprintf(stderr, "recv failed: %s\n", strerror(errno));
    abort();
  }

  printf("[+] Received %zd bytes\n", n);
}

int main() {
  int sfd = socket(AF_BP, SOCK_DGRAM, 1);
  if (sfd < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_bp addr = {0};
  addr.bp_family = AF_BP;
  addr.bp_scheme = BP_SCHEME_IPN;
  addr.bp_addr.ipn.node_id = 1;
  addr.bp_addr.ipn.service_id = 42;

  if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }

  printf("Waiting for incoming bundles...\n");

  while (1) {
    receive_and_check(sfd);
  }

  close(sfd);
  return 0;
}
