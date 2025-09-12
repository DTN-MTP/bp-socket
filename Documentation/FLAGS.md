# BP Socket Flags Documentation

This document describes the flags available for use with BP (Bundle Protocol) sockets in both `sendmsg()` and `recvmsg()` operations.

## Receive Message Flags

Applications can use the following flags with `recvmsg()`:

| Flag        | Description                                                                                                                                                                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `MSG_PEEK`  | Peeks at the incoming datagram without removing it from the queue. Useful for inspecting message size or content before full reception.                                                                                  |
| `MSG_TRUNC` | Returns the full size of the message, even if the provided buffer is too small. The datagram is consumed from the queue, and only the portion that fits is copied to the buffer. The MSG_TRUNC flag is set in msg_flags. |

### Combined Usage

The most efficient way to determine message size without consuming it:

```c
ssize_t need = recvmsg(fd, &msg, MSG_PEEK | MSG_TRUNC);
```

This combination allows you to:

1. Get the exact message size
2. Keep the message in the queue for later consumption
3. Allocate the proper buffer size dynamically

## Send Message Flags

The following flags can be used with `sendmsg()` to tune message delivery, reporting, priority, and custody:

### Acknowledgment

| Flag                | Description                                |
| ------------------- | ------------------------------------------ |
| `MSG_ACK_REQUESTED` | Requests an acknowledgment for the message |

### Status Reports (combinable)

These flags can be combined using the bitwise OR operator (`|`):

| Flag                | Description                                          |
| ------------------- | ---------------------------------------------------- |
| `MSG_RECEIVED_RPT`  | Request a report when the message is received        |
| `MSG_CUSTODY_RPT`   | Request a report when custody of the message changes |
| `MSG_FORWARDED_RPT` | Request a report when the message is forwarded       |
| `MSG_DELIVERED_RPT` | Request a report when the message is delivered       |
| `MSG_DELETED_RPT`   | Request a report when the message is deleted         |

### Priority (mutually exclusive)

Only one of these priority flags can be used at a time:

| Flag                        | Description                                  |
| --------------------------- | -------------------------------------------- |
| `MSG_BP_BULK_PRIORITY`      | Assigns a bulk priority to the message       |
| `MSG_BP_STD_PRIORITY`       | Assigns a standard priority to the message   |
| `MSG_BP_EXPEDITED_PRIORITY` | Assigns an expedited priority to the message |

### Custody (mutually exclusive)

Only one of these custody flags can be used at a time:

| Flag                          | Description                                          |
| ----------------------------- | ---------------------------------------------------- |
| `MSG_SOURCE_CUSTODY_REQUIRED` | Requires the source to retain custody of the message |
| `MSG_SOURCE_CUSTODY_OPTIONAL` | Source custody is optional                           |
| `MSG_NO_CUSTODY_REQUIRED`     | No custody is required                               |

## Usage Examples

### Receiving Messages with Dynamic Buffer Allocation

```c
// Step 1: Get message size without consuming
ssize_t message_size = recvmsg(fd, &msg, MSG_PEEK | MSG_TRUNC);

// Step 2: Allocate proper buffer and receive
char *buffer = malloc(message_size + 1);
struct iovec iov = { .iov_base = buffer, .iov_len = message_size };
msg.msg_iov = &iov;
msg.msg_iovlen = 1;

ssize_t received = recvmsg(fd, &msg, 0);
buffer[received] = '\0';
```

### Sending Messages with Flags

```c
// Send with acknowledgment request and no custody requirement
ssize_t sent = sendmsg(fd, &msg, MSG_ACK_REQUESTED | MSG_NO_CUSTODY_REQUIRED);

// Send with status reports and expedited priority
ssize_t sent = sendmsg(fd, &msg,
    MSG_RECEIVED_RPT | MSG_DELIVERED_RPT | MSG_BP_EXPEDITED_PRIORITY);
```

## Implementation Notes

- All BP-specific flags are defined in `include/bp_socket.h`
- Standard socket flags (MSG_PEEK, MSG_TRUNC) are available through system headers
- Flag values are designed to avoid conflicts with standard socket flags
- The kernel implementation properly handles all flag combinations
