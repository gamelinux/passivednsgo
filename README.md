# PassiveDNS Go

PassiveDNS Go is a high-performance, concurrent network daemon that captures DNS traffic off the wire, reassembles TCP streams, and logs DNS queries and responses in JSON format. It supports both unidirectional (query-only) and bidirectional (query-response correlation) logging.

## Background

The original `gamelinux/passivedns` was written in C and is single-threaded, meaning it couldn't take full advantage of modern multi-core CPUs. Handling large amounts of traffic required using `pf_ring` to split the load among different instances. While that worked, it wasn't optimal.

Wanting to dive into Golang, and inspired by `AF_PACKET` (TPacketVersion3) with fanout and ZeroCopy in late 2018, I started writing proof-of-concept code using `gopacket`. This evolved into a working project by the summer of 2019.

The goal was performance. `passivednsgo` has demonstrated the ability to handle peak DNS traffic at ~1Gbit/sec (averaging 650Mbit/sec) while the process itself remained largely idle—significantly outperforming the original C implementation.

*Note: Check if your kernel and traffic type are suited for `AF_PACKET` fanout. One resource is [can-i-use-afpacket-fanout](https://github.com/JustinAzoff/can-i-use-afpacket-fanout/).*

## Features

* **High Performance**: Uses `AF_PACKET` (Linux) with zero-copy features for efficient packet capture.
* **Protocol Support**: Handles both UDP and TCP DNS traffic (including stream reassembly).
* **Correlation**: Matches DNS queries with responses to log full transaction details (Latency, TTL, etc.).
* **Caching**: In-memory deduplication to reduce log volume for repeated queries.
* **Structured Logging**: Supports JSON (default) or Text format using Go's `slog`.
* **Graceful Shutdown**: Handles signals (`SIGINT`, `SIGTERM`) to flush buffers before exiting.

## Project Structure

* `cmd/`: Entry point for the application.
* `internal/`: Private application logic (Capture, Decoding, Parsing).
* `config/`: Configuration structs and defaults.
* `deploy/`: Deployment assets (Systemd, etc.).

## Getting Started

### Prerequisites

* Go 1.21+
* `libpcap-dev` (Debian/Ubuntu) or `libpcap` (RHEL/CentOS)

### Building

Use the included Makefile:

```bash
make deps
make build

```

The binary will be placed in `bin/passivednsgo`.

### Testing

Run the unit test suite to verify logic and correlation:

```bash
make test

```

### Installation

To install the binary and create the configuration directory:

```bash
sudo make install

```

### Configuration

The default configuration file is located at `/etc/passivednsgo/passivednsgo.yaml`.

```yaml
interface: "any"
bpf: "((ip) or vlan) and port 53"
capturethreads: 1
logfile: "/var/log/passivednsgo.json"
loglevel: "INFO"
logformat: "json"        # "json" or "text"
channelbuffersize: 10000 # Tune for high traffic

```

### Running as a Service

A systemd unit file is provided in `deploy/`.

```bash
sudo cp deploy/passivednsgo.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now passivednsgo

```

## Credits

A lot of credit goes to the authors, maintainers, and contributors of [google/gopacket](https://github.com/google/gopacket) (and akrennmair/gopcap), whose work made this tool possible.

## Feedback

As this was originally just a fun little project for me to poke at Golang, play, and learn, I never got around to pushing it to GitHub. However, with the help of modern LLMs, I have updated, refactored, and polished it for public release. So here it is, for others to play and learn from.

Feedback and enhancements are welcome!

## License

MIT

(c) 2018-2026 - Edward Bjarte Fjellskål
