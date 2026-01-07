# 🛡️ AEGIS-X

**Real-time Network Security Monitor & Intrusion Prevention System**

A powerful desktop application built with Go and React that monitors network traffic, detects security threats, and enables instant IP blocking.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat&logo=react)
![Wails](https://img.shields.io/badge/Wails-2.x-DF0000?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## ✨ Features

### 🔍 Real-time Traffic Monitoring
- Live packet capture using Npcap
- TCP/UDP/ICMP protocol detection
- Source & destination port tracking
- Geo-IP location enrichment

### 🚨 Threat Detection
- **HTTP Traffic Warning** - Detects unencrypted port 80 connections
- **Credential Leak Detection** - Alerts when passwords are transmitted
- **External Connection Tracking** - Monitors outbound traffic

### ⚡ Instant Response
- One-click IP blocking via Windows Firewall
- UAC elevation support for admin actions
- Real-time threat advisory panel

### 📊 Security Dashboard
- Dynamic security score (0-100)
- Protocol distribution chart
- Color-coded risk indicators
- Pause/Filter traffic controls

---

## 🖥️ Screenshots

| Security Dashboard | Threat Detection |
|-------------------|------------------|
| Modern glassmorphism UI with live traffic | Red Alert modal for critical threats |

---

## 🚀 Quick Start

### Prerequisites
- **Go** 1.21+
- **Node.js** 18+
- **Npcap** (Windows) - [Download](https://npcap.com/)
- **Wails CLI** - `go install github.com/wailsapp/wails/v2/cmd/wails@latest`

### Installation

```bash
# Clone the repository
git clone https://github.com/JullMol/aegis-x.git
cd aegis-x

# Install frontend dependencies
cd frontend && npm install && cd ..

# Run in development mode
wails dev

# Build for production
wails build
```

### Usage

1. Launch **Aegis-X**
2. Click **ACTIVATE SHIELD** to start monitoring
3. Browse the web - traffic will appear in real-time
4. View threats in **THREAT ADVISORY** panel
5. Click **KILL** to block suspicious IPs

---

## 🏗️ Architecture

```
aegis-x/
├── app.go                    # Main Wails application
├── main.go                   # Entry point
├── internal/
│   ├── bridge/               # Go-Python communication
│   ├── scanner/              # Network & port scanning
│   └── sniffer/              # Packet capture engine
├── scripts/
│   └── analyzer.py           # Security analysis & Geo-IP
└── frontend/
    └── src/
        └── App.tsx           # React UI
```

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|------------|
| Desktop Framework | Wails v2 |
| Backend | Go 1.21+ |
| Frontend | React 18 + TypeScript |
| Packet Capture | gopacket + Npcap |
| Security Analysis | Python 3 |
| Charts | Recharts |

---

## ⚠️ Requirements

- **Windows 10/11** (primary support)
- **Administrator privileges** required for:
  - Packet capture (Npcap)
  - Firewall rule creation
- **Npcap** must be installed with WinPcap compatibility mode

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

<p align="center">
  <b>Built with ❤️ for network security</b>
</p>
