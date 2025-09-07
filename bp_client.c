#include "bp_socket.h"
#include <errno.h>
#include <pthread.h>
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
#define AF_BP 28

volatile int running = 1;

struct client_data {
  int fd;
  struct sockaddr_bp dest_addr;
  struct sockaddr_bp src_addr;
};

void handle_sigint(int sig) {
  printf("\nInterrupt received, shutting down...\n");
  running = 0;
}

void *send_thread(void *arg) {
  struct client_data *data = (struct client_data *)arg;
  char send_buffer[BUFFER_SIZE];
  int message_count = 0;

  printf("Send thread started\n");

  while (running) {
    message_count++;
    snprintf(send_buffer, sizeof(send_buffer), "Hello from client! Message #%d",
             message_count);

    int flags = 0;
    flags |= MSG_ACK_REQUESTED;

    int ret =
        sendto(data->fd, send_buffer, strlen(send_buffer) + 1, flags,
               (struct sockaddr *)&data->dest_addr, sizeof(data->dest_addr));
    if (ret < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      printf("sendto failed for ipn:%u.%u: %s\n",
             data->dest_addr.bp_addr.ipn.node_id,
             data->dest_addr.bp_addr.ipn.service_id, strerror(errno));
      break;
    }

    printf("Message sent: %s\n", send_buffer);
  }

  printf("Send thread exiting\n");
  return NULL;
}

void *receive_thread(void *arg) {
  struct client_data *data = (struct client_data *)arg;
  struct msghdr msg;
  struct iovec iov;
  char buffer[BUFFER_SIZE];
  struct sockaddr_bp src_addr;

  // Set up message structure for receiving
  iov.iov_base = buffer;
  iov.iov_len = sizeof(buffer);
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  memset(&src_addr, 0, sizeof(src_addr));
  msg.msg_name = &src_addr;
  msg.msg_namelen = sizeof(src_addr);

  printf("Receive thread started\n");

  while (running) {
    ssize_t n = recvmsg(data->fd, &msg, 0);
    if (n < 0) {
      if (errno == EINTR) {
        printf("\nInterrupted by signal, exiting...\n");
        break;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Timeout reached, continue loop to check running flag
        continue;
      }
      perror("recvmsg failed");
      break;
    }

    printf("Received message (%zd bytes): %.*s\n", n, (int)n, buffer);
    if (msg.msg_namelen >= sizeof(struct sockaddr_bp)) {
      printf("Bundle sent by ipn:%u.%u\n", src_addr.bp_addr.ipn.node_id,
             src_addr.bp_addr.ipn.service_id);
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    memset(&src_addr, 0, sizeof(src_addr));
    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(src_addr);
  }

  printf("Receive thread exiting\n");
  return NULL;
}

int main(int argc, char *argv[]) {
  struct sockaddr_bp dest_addr, src_addr;
  int fd;
  uint32_t node_id, service_id;
  int ret = 0;
  pthread_t send_tid, recv_tid;
  struct client_data data;

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

  if (node_id == 0) {
    fprintf(stderr, "Invalid node_id (cannot be 0)\n");
    return EXIT_FAILURE;
  }

  fd = socket(AF_BP, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket creation failed");
    return EXIT_FAILURE;
  }

  src_addr.bp_family = AF_BP;
  src_addr.bp_scheme = BP_SCHEME_IPN;
  src_addr.bp_addr.ipn.node_id = 10;
  src_addr.bp_addr.ipn.service_id = 2;
  if (bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) == -1) {
    perror("Failed to bind socket");
    ret = EXIT_FAILURE;
    goto out;
  }

  struct timeval timeout;
  timeout.tv_sec = 1; // 1 second timeout
  timeout.tv_usec = 0;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    perror("Failed to set socket timeout");
    ret = EXIT_FAILURE;
    goto out;
  }

  dest_addr.bp_family = AF_BP;
  dest_addr.bp_scheme = BP_SCHEME_IPN;
  dest_addr.bp_addr.ipn.node_id = node_id;
  dest_addr.bp_addr.ipn.service_id = service_id;

  data.fd = fd;
  data.dest_addr = dest_addr;
  data.src_addr = src_addr;

  printf("BP Client started - sending messages to ipn:%u.%u\n", node_id,
         service_id);
  printf("Press Ctrl+C to exit.\n");

  if (pthread_create(&send_tid, NULL, send_thread, &data) != 0) {
    perror("Failed to create send thread");
    ret = EXIT_FAILURE;
    goto out;
  }

  if (pthread_create(&recv_tid, NULL, receive_thread, &data) != 0) {
    perror("Failed to create receive thread");
    running = 0;
    pthread_join(send_tid, NULL);
    ret = EXIT_FAILURE;
    goto out;
  }

  pthread_join(send_tid, NULL);
  pthread_join(recv_tid, NULL);

out:
  close(fd);
  printf("Socket closed.\n");
  return ret;
}
