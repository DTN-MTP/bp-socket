# BP Socket Options Documentation

This document describes the socket options available for BP (Bundle Protocol) sockets using `setsockopt()` and `getsockopt()`.

## Overview

BP sockets support standard socket options at the `SOL_SOCKET` level, with specific implementations for timeout handling. All other socket levels are passed through to the common socket implementation.

## Supported Socket Options

### Receive Timeout Options

BP sockets support the standard POSIX receive timeout option:

| Option Name   | Type             | Description                    |
| ------------- | ---------------- | ------------------------------ |
| `SO_RCVTIMEO` | `struct timeval` | Standard POSIX receive timeout |

### Timeout Behavior

- **Default**: No timeout (`MAX_SCHEDULE_TIMEOUT`)
- **Zero timeout**: Immediate timeout (non-blocking behavior)
- **Non-zero timeout**: Block for specified duration before timing out
- **Timeout units**: seconds and microseconds (standard POSIX)

## Usage Examples

### Setting Receive Timeout

```c
#include <sys/socket.h>
#include <sys/time.h>

struct timeval timeout;
timeout.tv_sec = 5;      // 5 seconds
timeout.tv_usec = 0;     // 0 microseconds

if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    perror("setsockopt failed");
    return -1;
}
```

### Getting Current Timeout

```c
struct timeval timeout;
socklen_t len = sizeof(timeout);

if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, &len) < 0) {
    perror("getsockopt failed");
    return -1;
}

printf("Current timeout: %ld.%06ld seconds\n",
       timeout.tv_sec, timeout.tv_usec);
```
