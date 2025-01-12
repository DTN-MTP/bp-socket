# BP Sockets

The outcome of STINT 2024 Hackathon. Authored by Scott Burleigh (APL), Felix Walter (D3TN), Olivier De Jonckere (LIRMM), Juan Fraire (Inria), Brian Sipos (APL), Samo Grasic (ICTP), Brian Tomko (NASA), and Ricardo Lent (UH).

> 🛈 STINT:
> The Space-Terrestrial Internetworking (STINT) Workshop brings together space networking research and the industrial community's interest in Delay and Disruption-Tolerant Networking (DTN). Sponsored by IPNSIG and D3TN, the 11th edition of STINT was held at the IEEE SMC-IT/SSC conference in Mountain View, California.

## Table of Contents

- [BP Sockets](#bp-sockets)
  - [Table of Contents](#table-of-contents)
  - [Hackathon](#hackathon)
    - [Organization](#organization)
    - [Architecture](#architecture)
    - [Outcome](#outcome)
    - [Code](#code)
      - [BP Sockets Application (`bp-user-app-with-sock.c`)](#bp-sockets-application-bp-user-app-with-sockc)
      - [BP Sockets Kernel Module (`bp-sock` directory)](#bp-sockets-kernel-module-bp-sock-directory)
      - [BP Sockets Daemon (`bp-daemon` directory)](#bp-sockets-daemon-bp-daemon-directory)
  - [Getting started](#getting-started)
    - [Requirements](#requirements)
    - [Overview of Available Commands](#overview-of-available-commands)
    - [Setting Up Virtual Machines](#setting-up-virtual-machines)
      - [VM1 Setup: `ion-node`](#vm1-setup-ion-node)
      - [VM2 Setup: `ud3tn-node`](#vm2-setup-ud3tn-node)
  - [Next Steps](#next-steps)
  - [References](#references)

## Hackathon

Day 3 of STINT 2024 (July 19th) was dedicated to a hackathon organized by Scott Burleigh. The goal was to tackle a core DTN problem: providing a clean, interoperable API to facilitate application developers in sending data using the Bundle Protocol (BP).

The hackathon focused on implementing such an API based on POSIX sockets. This approach has the central advantage that it requires only minimal modifications in existing applications: only the address family passed to the socket() system call plus the addresses themselves (that are replaced with DTN endpoint identifiers) would need to be adapted in existing applications otherwise using datagram (e.g., UDP) sockets.

### Organization

The work was organized into teams:

- Team 1: Infrastructure and Applications. Deployed µD3TN and ION BP nodes on two virtual machines running Debian 12 with Linux kernel version 6.1.0-22-amd64, using the TCPCLv3 convergence layer protocol to send and receive bundles.
  Two members: Juan Fraire (Inria) and Samo Grasic (ICTP).

- Team 2: BP Sockets Daemon. Created the BP Sockets Daemon (deployed in userspace) to manage socket states, handle IPC with the BP Sockets Kernel Module plug-in, and use ION to send the created bundles. Adapted from Mark O’Neill’s Secure Sockets API (SSA), source code at https://github.com/markoneill/ssa-daemon.
  Two members: Scott Burleigh (APL) and Felix Walter (D3TN).

- Team 3: BP Sockets Plug-in Kernel Module. Implemented a custom protocol for BP Sockets Kernel Module (deployed in kernel space) inspired by Mark O'Neill's Secure Socket API (SSA), available in this repository: https://github.com/markoneill/ssa.
  Four members: Olivier De Jonckere (Montpellier University), Brian Sipos (APL), Ricardo Lent (UH) and Brian Tomko (NASA).

### Architecture

The resulting “BP Sockets” interface integrates with bundle protocol stacks in user space. Netlink IPC (Inter-Process Communication) coordinates kernel and user space interactions. The main elements of the architecture are described below.

![Architecture](./img/architecture.png)

<details close>
<summary>BP Sockets Application</summary>
<br>
The user application creates a socket with a newly introduced address family 28, with the datagram (DGRAM) type and protocol number 0. The destination EID is provided via the sockaddr parameter of the sendto() function, and the Application Data Unit (ADU) to be conveyed via BP is provided in the message field.
<br><br>
</details>

<details close>
<summary>BP Sockets Kernel Module</summary>
<br>
A kernel module processes BP Sockets calls. This module uses Netlink to deliver the bundle payload and related metadata to the BP Sockets Daemon. Netlink is a communication protocol between the Linux kernel and userspace processes designed for asynchronous message passing.
<br><br>
</details>

<details close>
<summary>BP Sockets Daemon</summary>
<br>
Upon receiving a message, the BP Sockets Daemon in userspace retrieves the EID and the ADU, creates a bundle with ION, and sends it to the peer. In our case, the destination was running µD3TN on a second virtual machine (VM). This way, we demonstrated interoperability between µD3TN and ION using the BP Sockets interface.  Note that the BP Sockets Daemon is modular and not locked to ION; it could easily be adapted to another Bundle Protocol implementation.
<br><br>
</details>

### Outcome

During the hackathon, we developed a proof-of-concept for BP Sockets. It was demonstrated by transmitting bundles from a minimal user space application through the Linux kernel and ION to µD3TN using BP Sockets. The screenshot below shows the µD3TN log (the receiving BP node) on the top, the BP Sockets App sender on the bottom left, and the BP App receiver output on the bottom right.

![Screenshot](./img/outcome.png)

### Code

The resulting BP Socket code developed during the hackathon is publicly available in this GitHub repository: https://github.com/juanfraire/bp-sockets. Here is a brief explanation of the components:

#### BP Sockets Application (`bp-user-app-with-sock.c`)

This application handles socket operations for sending DTN data. The source code file for the test application is located in the root directory.
`bp-user-app-with-sock.c`: A test application to send custom protocol messages. The main sending process is a standard (simple) socket operation, as shown below.

```
#define AF_BP 28
// [...]
sockfd = socket(AF_BP, SOCK_DGRAM, 0);
// [...]
struct sockaddr eID;
// [...]
ret = sendto(sockfd, msg, strlen(msg)+1, 0, &eID, sizeof(eID));
// [...]
close(sockfd);
```

To deploy the socket app, use the following commands (the kernel module must be deployed, and the socket daemon should be initialized):

- `gcc -o bp-user-app-with-sock bp-user-app-with-sock.c`
- `sudo ./bp-user-app-with-sock`

#### BP Sockets Kernel Module (`bp-sock` directory)

This kernel module supports BP socket operations and communicates with the BP Sockets Daemon. It:

- Implements socket functions (open, sendto, close).
- Opens an IPC connection to the BP sockets daemon.
- Sends messages to the daemon to handle text transmission.

The source code files are located in the `bp-sock` directory. They implement the BP Sockets kernel module. The most relevant files include:

- `bpsock.c`: Core files for implementing the custom protocol for BP sockets. Implements new socket operations (open, sendto, close).
  - Defines `CUSTOM_PROTO_FAMILY` with a value of `28`, representing the custom protocol family.
  - `struct proto` and `struct proto_ops` are used to define the custom protocol operations and socket properties.
  - Main Operations:
    - `custom_create`: Initializes and allocates resources for a new socket.
      - Sets the socket operations.
      - Allocates a new socket (`sk_alloc`).
      - Initializes socket data (`sock_init_data`).
    - `custom_release`: Cleans up and releases resources when a socket is closed.
      - Puts the socket (`sock_put`).
    - `custom_sendmsg`: Handles sending messages through the custom protocol.
      - Allocates memory for the data to be sent.
      - Copies data from user space to kernel space (`copy_from_iter`).
- `netlink.c`: Handle IPC using Netlink.

To deploy the kernel module, use the following commands:

- `apt install linux-headers-$(uname -r)`
- build with `make`
- `insmod bp.ko`

#### BP Sockets Daemon (`bp-daemon` directory)

This daemon manages the state of BP sockets and handles communication with the BP sockets kernel module and the DTN protocol stack (ION, in this case). Specifically, it:

- Opens an IPC connection with the BP sockets kernel module.
- Manages socket state objects.
- Receives messages from the BP sockets plug-in to send text using ION.

The source code files are located in the `bp-daemon` directory. They implement the BP Sockets Daemon. The most relevant files include:

- `daemon.c`: Core functions of the BP sockets daemon.
- `main.c`: Contains the main entry point for the daemon.
- `netlink.c`: Handle IPC using Netlink.
- `hashmap.c`, `hashmap_str.c`: Implement hash maps to manage socket states.
- `log.c`: Logging functionality.

To deploy the B daemon, use the following commands:

- `apt install pkg-config libnl-genl-3-dev libevent-dev`
- build with `make`
- `ionstart -I host1.rc`
- `run ./bp_daemon`

## Getting started

To set up the development environment outlined in the [Architecture](#architecture) section, we are going to prepare two virtual machines (VM1 and VM2). First, download the following image: [debian-12-generic-amd64.qcow2](https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2); Next, skip ahead to the [Setting Up Virtual Machines](#setting-up-virtual-machines) section to follow the instructions.

> ⚠️ IMPORTANT:
> It is highly recommended to use `ion-node` (VM1) as your development environment. This VM already includes the necessary tools and dependencies like `just`, `make`, and `python3-jinja2`. By working directly on VM1, you can simplify testing and avoid additional setup on your local machine.

### Requirements

Here are the tools and packages required for development:

- Local:
  - **Tools**:
    - [Just](https://github.com/casey/just)
  - **Packages**:
    - `python3-jinja2`
- VM1 (`ion-node`):
  - **Tools**:
    - [Just](https://github.com/casey/just)
  - **Packages**:
    - `make`
    - `pkg-config`
    - `libnl-genl-3-dev`
    - `libevent-dev`
    - `build-essential`
    - `python3-jinja2`
- VM2 (`ud3tn-node`):
  - **Packages**:
    - `make`
    - `build-essential`
    - `libsqlite3-dev`
    - `sqlite3`
    - `python3.11-venv`

### Overview of Available Commands

| Action                                        | Command                                                | Note                                                                                                                                                                                            |
| --------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Generate the content of an ION `host.rc` file | `just ion host <ADDRESS_SOURCE> <ADDRESS_DESTINATION>` | This command outputs the content to `stdout`. To save it to a file, append a redirection at the end (e.g., `> host.rc`).                                                                        |
| Generate cloud-init config for `ud3tn-node`   | `just cloud-config ud3tn-node`                         | Before executing this command, ensure the environment variable `SSH_PUBLIC_KEY` is set with your public SSH key. Similar to the previous command, this command outputs the content to `stdout`. |
| Generate cloud-init config for `ion-node`     | `just cloud-config ion-node`                           | Before executing this command, ensure the environment variable `SSH_PUBLIC_KEY` is set with your public SSH key. Similar to the previous command, this command outputs the content to `stdout`. |

### Setting Up Virtual Machines

#### VM1 Setup: `ion-node`

1. [From Local] Automated Installation with QEMU/KVM and cloud-init

```bash
SSH_PUBLIC_KEY="ssh-rsa AAA..." just cloud-config ion-node > ion-node.debian.cfg

virt-install --name ion-node \
	--vcpus 4 --ram 2048 \
	--disk size=10,backing_store=/path/to/debian-12-generic-amd64.qcow2 \
  --cloud-init user-data=./ion-node.debian.cfg,disable=on \
	--network bridge=virbr0 \
	--osinfo debian12
```

2. [From Local] SSH inside `ion-node`

```bash
ssh debian@<ADDRESS>
```

3. [From `ion-node`] Switch to `root` user

```bash
sudo -i
```

4. [From `ion-node`] Set Up ION and bp-sockets

Navigate to the `bp-sockets` project directory and configure as follows:

```bash
cd /home/debian/bp-sockets
export LD_LIBRARY_PATH="/usr/local/lib"

# Start ION
just ion host <ADDRESS_SOURCE> <ADDRESS_DESTINATION> > host.rc
# Example: just ion host 192.168.122.140 192.168.122.182 > host.rc
ionstart -I host.rc

# Set up bp-sockets kernel module
cd bp-sock
make
insmod bp.ko

# Set up bp-daemon
cd ../bp-daemon
make
./bp_daemon
```

5. [From `ion-node`] Build and run user-space demo application

> ⚠️ IMPORTANT:
> You need to open a new shell and wait for setting up µD3TN (VM2 Setup).

<details open>
<summary>Sender</summary>
<br>

```bash
cd /home/debian/bp-sockets

gcc -o demo-app-bp-send demo-app-bp-send.c
./demo-app-bp-send ipn:<HOST_ID_DESTINATION>.<AGENT_ID_DESTINATION>
# Example for '192.168.122.182': ./demo-app-bp-send ipn:182.1
```
</details>

<details close>
<summary>Receiver</summary>
<br>

```bash
cd /home/debian/bp-sockets

gcc -o demo-app-bp-recv demo-app-bp-recv.c
./demo-app-bp-recv <AGENT_ID_SOURCE>
# Example: ./demo-app-bp-recv 1
```
</details>

#### VM2 Setup: `ud3tn-node`

1. [From Local] Automated Installation with QEMU/KVM and cloud-init

```bash
SSH_PUBLIC_KEY="ssh-rsa AAA..." just cloud-config ud3tn-node > ud3tn-node.debian.cfg

virt-install --name ud3tn-node \
	--vcpus 4 --ram 2048 \
	--disk size=10,backing_store=/path/to/debian-12-generic-amd64.qcow2 \
  --cloud-init user-data=./ud3tn-node.debian.cfg,disable=on \
	--network bridge=virbr0 \
	--osinfo debian12
```

2. [From Local] SSH inside `ud3tn-node`

```bash
ssh debian@<ADDRESS>
```

3. [From `ud3tn-node`] Switch to `root` user

```bash
sudo -i
```

4. [From `ud3tn-node`] Start µD3TN

```bash
cd /home/debian/ud3tn

build/posix/ud3tn \
    --allow-remote-config \
    --eid ipn:<HOST_ID_SOURCE>.0 \
    --aap2-socket ./ud3tn.aap2.socket.2 \
    --cla "tcpclv3:*,4556" -L 4
# Example for '192.168.122.140': build/posix/ud3tn \
# --allow-remote-config \
# --eid ipn:140.0 \
# --aap2-socket ./ud3tn.aap2.socket.2 \
# --cla "tcpclv3:*,4556" -L 4
```

5. [From `ud3tn-node`] Send and/or receive message

> ⚠️ IMPORTANT:
> You need to open a new shell.

<details open>
<summary>Run the AAP2 Receiver</summary>
<br>

```bash
cd /home/debian/ud3tn

source .venv/bin/activate
python3 tools/aap2/aap2_receive.py --agentid <AGENT_ID_SOURCE> --socket ./ud3tn.aap2.socket.2
# Example: python3 tools/aap2/aap2_receive.py 
# --agentid 1 \
# --socket ./ud3tn.aap2.socket.2
```
</details>

<details close>
<summary>Run the AAP2 Sender</summary>
<br>

```bash
cd /home/debian/ud3tn

source .venv/bin/activate

# Add outgoing contact to ION node
python3 tools/aap2/aap2_config.py --socket ./ud3tn.aap2.socket.2 --schedule 1 86400 100000 ipn:<HOST_ID_DESTINATION>.0 tcpclv3:<ADDRESS_DESTINATION>:4556
# Example for '192.168.122.182': python3 tools/aap2/aap2_config.py \
# --socket ./ud3tn.aap2.socket.2 \
# --schedule 1 86400 100000 \
# ipn:182.0 tcpclv3:192.168.122.182:4556

# Send payload to ION node
python3 tools/aap2/aap2_send.py --agentid <AGENT_ID_SOURCE> --socket ./ud3tn.aap2.socket.2 ipn:<HOST_ID_DESTINATION>.<AGENT_ID_DESTINATION> "Hello from ud3tn!" -v
# Example for '192.168.122.182': python3 tools/aap2/aap2_send.py \
# --agentid 1 \
# --socket ./ud3tn.aap2.socket.2 \
# ipn:140.1 "Hello from ud3tn!" -v
```
</details>




## Next Steps

The following steps identified at the STINT 2024 hackathon are:

- Design and implement the receiver data flow in BP Sockets. We have only implemented and tested the transmission part.
- Extend the BP Sockets Daemon to support other DTN stacks besides ION (e.g., µD3TN).
- Expose more protocol versions (bpv6, bpv7) and options (QoS, custody transfer, reporting) as optional parameters via the socket options (sockopt) interface.
- Explore a proper binding between SOCK_DGRAM and SOCK_STREAM socket models and expected DTN data handling modes.
- Clean up and stabilize the API and the internal message types and infrastructure.
- Explore the possible performance and memory bottlenecks of the socket interface.

## References

- Useful and related links:
- SSA: https://github.com/markoneill/ssa
- SSA Daemon: https://github.com/markoneill/ssa-daemon
- Unified API for DTN (by University of Bologna): https://gitlab.com/dtnsuite/unified_api/-/tree/master?ref_type=heads
