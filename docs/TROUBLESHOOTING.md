# Troubleshooting Guide

- Recommend tools for debugging configuration and runtime issues.
- Provide solutions for common errors and misconfigurations.
- Offer step-by-step guidance for diagnosing and resolving problems.

## Topic 1 - Network Debugging 

- TCP/IP Monitoring

Observe BP (Bundle Protocol) packet transmission and reception. Port 4556 is defined in `host.rc` for ION and specified as a command parameter in the CLA (Convergence-Layer Adapter) for µD3TN.

```bash
tcpdump -i <iface> port 4556 -n
```

- Check Open UDP/TCP Ports

Use the following command to verify open ports:

```bash
ss -laputn
```

## Topic 2 - [Insert Topic Title]

- ...

## Miscellaneous
- ...