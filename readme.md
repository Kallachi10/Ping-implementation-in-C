# ICMP Ping

A basic implementation of **Ping** using the **ICMP protocol**, built from scratch as a learning project.

### Features
- Raw socket-based ICMP communication
- Basic construction and parsing of **IPv4** and **ICMP** packets
- ICMP Echo Request and Echo Reply handling

### Build & Run

Compile using:

```bash
make
```

Run with:

```bash
sudo ./ping <destination-ip>
```

For example:

```bash
sudo ./ping 8.8.8.8
```

`sudo` is required because the program uses raw sockets.

### Note

This project was primarily built to understand how **Ping works at the network-protocol level**, including raw sockets, packet construction, byte ordering, checksums, and ICMP/IPv4 headers.

It is **not intended to be a production-ready replacement for `ping`**.
