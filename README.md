<div align="center">

# 🛡️ AEGIS-X

### The Ultimate Local Security Suite

**Real-time Network Security Monitor & Intrusion Prevention System**

A powerful "Swiss Army Knife" for cybersecurity that combines Go, Python, and React into one desktop application.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Wails](https://img.shields.io/badge/Wails-2.x-DF0000?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

---

## 🎯 Project Concept

**Aegis-X** is an "All-in-One Security Offensive & Monitoring Suite" — a local-first, standalone application that packs multiple security engines into one executable. No Docker, no distributed systems, just one powerful desktop app.

Instead of deploying multiple agents across servers, Aegis-X runs **Modular Agents** internally:

| Engine | Language | Purpose |
|--------|----------|---------|
| **The Sniffer** | Go | Real-time packet capture & analysis |
| **The Scanner** | Go | Network device & port scanning |
| **The Analyzer** | Python | Deep packet inspection & threat detection |
| **Command Center** | React/TS | Modern desktop UI with Wails |

---

## ✨ Key Features

### 1. 🔫 Intrusion Kill Chain (Network Blocking)

Don't just observe attacks — **stop them**.

- **How it works:** When the analyzer detects suspicious activity from an external IP (port scanning, brute force attempts), click **"KILL"** to block it instantly.
- **Implementation:** Go executes Windows Firewall rules via `netsh` with UAC elevation.
- **Real-world equivalent:** This is a core feature of **IPS (Intrusion Prevention System)**.

```
User clicks KILL → Go calls netsh → IP blocked in Windows Firewall
```

### 2. 🔐 Credential Leak Monitor (Deep Packet Inspection)

Protect your passwords from being exposed.

- **How it works:** Python performs regex analysis on HTTP traffic (port 80) looking for patterns like `user=`, `password=`, `login=`, `token=`.
- **Alert:** If you login on an insecure site, Aegis-X shows a **RED ALERT**: *"CREDENTIAL LEAK DETECTED!"*
- **Mind-blowing demo:** Login to any HTTP site and watch the alert trigger in real-time.

### 3. 🌍 Geo-IP Mapping (Visualization)

Know where your data is going.

- **How it works:** Every public IP captured by the sniffer is enriched with country location using IP-API.
- **Visualization:** Country codes displayed next to each traffic row.
- **Eye-opener:** See which countries your laptop is secretly communicating with.

---

## 🖥️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         AEGIS-X                              │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │   SNIFFER   │  │   SCANNER   │  │      ANALYZER       │   │
│  │    (Go)     │  │    (Go)     │  │      (Python)       │   │
│  │             │  │             │  │                     │   │
│  │ • Packet    │  │ • Port Scan │  │ • Threat Detection  │   │
│  │   Capture   │  │ • Device    │  │ • Credential Leak   │   │
│  │ • Protocol  │  │   Discovery │  │ • Geo-IP Lookup     │   │
│  │   Analysis  │  │             │  │                     │   │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘   │
│         │                │                    │              │
│         └────────────────┼────────────────────┘              │
│                          │                                   │
│                    ┌─────▼─────┐                             │
│                    │  WAILS    │                             │
│                    │  BRIDGE   │                             │
│                    └─────┬─────┘                             │
│                          │                                   │
│                    ┌─────▼─────┐                             │
│                    │  REACT    │                             │
│                    │    UI     │                             │
│                    │           │                             │
│                    │ Dashboard │                             │
│                    │ Controls  │                             │
│                    │ Alerts    │                             │
│                    └───────────┘                             │
└──────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
aegis-x/
├── app.go                    # Main Wails application & API
├── main.go                   # Entry point
├── internal/
│   ├── bridge/               # Go ↔ Python communication
│   │   └── bridge.go
│   ├── scanner/              # Network & port scanning
│   │   └── scanner.go
│   └── sniffer/              # Packet capture engine
│       └── sniffer.go
├── scripts/
│   └── analyzer.py           # Python threat analyzer
├── frontend/
│   └── src/
│       ├── App.tsx           # React UI
│       └── style.css         # Modern CSS
└── build/
    └── bin/                  # Production executable
```

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| **Go** | 1.21+ | Backend engine |
| **Node.js** | 18+ | Frontend build |
| **Python** | 3.10+ | Threat analysis |
| **Npcap** | Latest | Packet capture ([Download](https://npcap.com/)) |
| **Wails CLI** | 2.x | Desktop framework |

### Installation

```bash
# Install Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# Clone repository
git clone https://github.com/JullMol/aegis-x.git
cd aegis-x

# Install frontend dependencies
cd frontend && npm install && cd ..

# Run in development mode
wails dev
```

### Production Build

```bash
# Build for Windows (as Administrator)
wails build -platform windows/amd64

# Output: build/bin/aegis-x.exe
```

---

## 📦 Distribution

To share Aegis-X with others, create a portable bundle:

```
Aegis-X-Release/
├── aegis-x.exe        # Main executable
├── scripts/
│   └── analyzer.py    # Python analyzer
└── README.txt         # Instructions
```

> ⚠️ **Note:** Users must install [Npcap](https://npcap.com/) with WinPcap compatibility mode for the sniffer to work.

---

## 🔧 Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Desktop Framework | Wails v2 | Go + Web bundling |
| Backend | Go 1.21+ | High-performance core |
| Frontend | React 18 + TypeScript | Modern UI |
| Packet Capture | gopacket + Npcap | Network sniffing |
| Analysis | Python 3 | Threat detection |
| Charts | Recharts | Data visualization |

---

## ⚠️ Requirements

- **Windows 10/11** (primary support)
- **Administrator privileges** for:
  - Packet capture (Npcap)
  - Firewall rule creation
- **Npcap** with WinPcap API-compatible mode

---

## 🎬 Demo

1. **Launch Aegis-X**
2. Click **ACTIVATE SHIELD** to start monitoring
3. Browse any website — traffic appears in real-time
4. Visit an HTTP site — watch the **HIGH RISK** warning appear
5. Click **KILL** on any suspicious IP — immediately blocked!

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

<div align="center">

**Built with ❤️ for network security**

*Combining the power of Go, Python, and React in one desktop application*

</div>
