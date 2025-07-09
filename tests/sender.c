#include "../include/bp_socket.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define AF_BP 28

struct test_payload {
  const char *label;
  const void *data;
  size_t len;
  ssize_t expected_size;
  int expected_errno;
};

void send_payload(int sfd, uint32_t node_id, uint32_t service_id,
                  const void *data, size_t len, const char *label,
                  ssize_t expected_size, int expected_errno) {
  struct sockaddr_bp addr = {0};
  addr.bp_family = AF_BP;
  addr.bp_scheme = BP_SCHEME_IPN;
  addr.bp_addr.ipn.node_id = node_id;
  addr.bp_addr.ipn.service_id = service_id;

  errno = 0;
  ssize_t n = sendto(sfd, data, len, 0, (struct sockaddr *)&addr, sizeof(addr));

  if (n < 0) {
    if (expected_errno == 0) {
      fprintf(stderr, "[%s] Unexpected error: %s\n", label, strerror(errno));
      abort();
    }
    if (errno != expected_errno) {
      fprintf(
          stderr,
          "[%s] Assertion failed: expected errno %d (%s), got errno %d (%s)\n",
          label, expected_errno, strerror(expected_errno), errno,
          strerror(errno));
      abort();
    }
  } else {
    if (expected_errno != 0) {
      fprintf(stderr,
              "[%s] Expected failure with errno %d (%s), but sendto succeeded "
              "with %zd bytes\n",
              label, expected_errno, strerror(expected_errno), n);
      abort();
    }
    if (n != expected_size) {
      fprintf(stderr, "[%s] Assertion failed: expected %zd bytes, got %zd\n",
              label, expected_size, n);
      abort();
    }
  }
}

int main() {
  int sfd = socket(AF_BP, SOCK_DGRAM, 1);
  if (sfd < 0) {
    perror("socket");
    return 1;
  }

  const char *ascii = "Hello world";
  const char *utf8 = "こんにちは世界";
  const char *json = "{\"key\":\"value\"}";

  unsigned char incremental[256];
  for (int i = 0; i < 256; i++)
    incremental[i] = i;

  unsigned char uniform[1024];
  memset(uniform, 0xAA, sizeof(uniform));

  unsigned char random[4096];
  for (int i = 0; i < 4096; i++)
    random[i] = rand() % 256;

  char *big = malloc(10 * 1024 * 1024);
  memset(big, 'X', 10 * 1024 * 1024);

  struct test_payload payloads[] = {
      {"empty", "", 0, 0, 0},
      {"ascii", ascii, strlen(ascii), strlen(ascii), 0},
      {"utf8", utf8, strlen(utf8), strlen(utf8), 0},
      {"json", json, strlen(json), strlen(json), 0},
      {"incremental", incremental, sizeof(incremental), sizeof(incremental), 0},
      {"uniform", uniform, sizeof(uniform), sizeof(uniform), 0},
      {"random", random, sizeof(random), sizeof(random), 0},
      {"small", "small data", 11, 11, 0},
      {"medium", "medium data that is larger than small but smaller than big",
       60, 60, 0},
      {"large",
       "a large payload that is significantly larger than medium but still "
       "manageable",
       1000, 1000, 0},
      {"big", big, 10 * 1024 * 1024, -1, EMSGSIZE},
  };

  for (size_t i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
    send_payload(sfd, 10, 42, payloads[i].data, payloads[i].len,
                 payloads[i].label, payloads[i].expected_size,
                 payloads[i].expected_errno);
  }

  free(big);
  close(sfd);
  return 0;
}
