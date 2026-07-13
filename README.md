# Wireshark MCP Server



## Overview

Wireshark MCP Server bridges AI assistants and network packet analysis by exposing Wireshark/TShark functionality through the Model Context Protocol (MCP).

Instead of manually searching through packet captures, AI clients can interact with PCAP data using natural language and structured MCP tools.

This project enables:

* PCAP investigation
* Protocol discovery
* Packet filtering
* Stream analysis
* Traffic statistics
* Network conversation mapping
* Live packet capture
* AI-assisted network troubleshooting

\---

## ✨ Features

|Feature|Description|
|-|-|
|🔎 Protocol Discovery|Identify all protocols present in a PCAP|
|📦 Packet Search|Search packets using Wireshark display filters|
|🌐 Conversation Analysis|Analyze communications between hosts|
|🔄 Stream Following|Follow TCP and UDP streams|
|📊 Traffic Statistics|Generate protocol and traffic summaries|
|🎯 Interface Discovery|Enumerate available capture interfaces|
|⚡ Live Capture|Capture network traffic in real time|
|🤖 MCP Integration|Compatible with MCP clients and AI agents|
|🌍 HTTP Transport|Expose tools through HTTP|
|💻 STDIO Transport|Native MCP STDIO support|

\---

## 🏗 Architecture

```text
┌──────────────────────┐
│      AI Client       │
│ ( Claude Desktop)   │
└──────────┬───────────┘
           │ MCP
           ▼
┌──────────────────────┐
│  Wireshark MCP Server│
└──────────┬───────────┘
           │
 ┌─────────┴─────────┐
 │                   │
 ▼                   ▼
TShark          Wireshark
 Engine           Engine
 │
 ├── PCAP Files
 ├── Live Capture
 ├── Streams
 ├── Conversations
 └── Statistics
```

\---

## 📁 Project Structure

```text
app/
├── prompts/
│   └── prompts.py
│
├── resources/
│   └── references.py
│
├── tools/
│   ├── behavior.py
│   ├── conversations.py
│   ├── discovery.py
│   ├── interfaces.py
│   ├── live\_capture.py
│   ├── packets.py
│   ├── save\_capture.py
│   ├── statistics.py
│   └── streams.py
│
├── transports/
│   ├── http\_transport.py
│   └── stdio\_transport.py
│
├── utils/
│   └── tshark.py
│
├── config.py
└── server.py
└── .env

run.py
requirements.txt
```

\---

## Requirements

### Software

* Python 3.11+
* Wireshark
* TShark

Verify TShark installation:

```bash
tshark -v
```

\---

## Installation

Clone the repository:

```bash
git clone https://github.com/NathcorpTraining/Wireshark-MCP.git

cd Wireshark-mcp-server
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

Windows:

```bash
venv\\Scripts\\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

\---

## Configuration

Create a `.env` file:

```env
TSHARK\_PATH=C:\\\\Program Files\\\\Wireshark\\\\tshark.exe

MAX\_TIMEOUT=30

MAX\_PACKETS=10000

HTTP\_HOST=0.0.0.0

HTTP\_PORT=8080
```

\---

## Running the Server

### STDIO Transport

```bash
python run.py --transport stdio
```

### HTTP Transport

```bash
python run.py --transport http
```

Server endpoint:

```text
http://localhost:8080
```

\---

## Available MCP Tools

### Protocol Discovery

Discover protocols contained within a packet capture.

### Packet Search

Search packets using Wireshark display filters.

Examples:

```text
http

dns

tcp.port == 443

ip.addr == 192.168.1.10
```

### Conversation Analysis

Analyze communication flows between hosts.

### Stream Analysis

Follow complete TCP or UDP streams.

### Traffic Statistics

Generate protocol and traffic summaries.

### Interface Discovery

List available capture interfaces.

### Live Capture

Capture traffic directly from selected interfaces.

### Save Capture

Persist temporary capture files for later analysis.

### Behavior Analysis

Analyze communication patterns and traffic behavior.

\---

## Example Use Cases

### Incident Response

* Investigate suspicious network activity
* Analyze compromised host communications
* Review attack traffic

### Network Troubleshooting

* Identify connectivity issues
* Analyze protocol failures
* Review packet exchanges

### Security Operations

* Investigate PCAP files
* Review alerts with packet evidence
* Analyze suspicious traffic patterns

### Threat Hunting

* Search for indicators of compromise
* Review communications between hosts
* Identify unusual traffic behavior

\---

## Security Notice

This tool provides packet capture and analysis capabilities.

Only capture or analyze network traffic on systems and networks for which you have explicit authorization.

The maintainers assume no responsibility for misuse of this software.

\---

## Roadmap

### Current

* \[x] Protocol Discovery
* \[x] Packet Search
* \[x] Stream Analysis
* \[x] Conversation Analysis
* \[x] Statistics
* \[x] Live Capture
* \[x] HTTP Transport
* \[x] STDIO Transport

### Planned

* \[ ] IOC Extraction
* \[ ] Threat Detection
* \[ ] Session Reconstruction
* \[ ] AI Investigation Workflows
* \[ ] Protocol Anomaly Detection
* \[ ] Export Reports
* \[ ] MITRE ATT\&CK Mapping

\---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

\---

## 📄 License

Licensed under the MIT License.

See the LICENSE file for details.

\---

## ⭐ Support

If you find this project useful:

* Star the repository
* Share feedback
* Submit feature requests
* Contribute improvements

\---

