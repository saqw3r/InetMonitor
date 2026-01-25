# Internet Monitor Tool 🛰️🌐🏎️

A high-performance Windows application built with **C++20**, **ImGui**, and **DirectX 11** for real-time internet traffic monitoring.

**Note on Development**: This project was written completely using **Vibe Coding**. While the AI laid the foundation, it was successfully navigated to its stable, "Bulletproof" state through persistent human-led navigation and expert guidance during complex system-level error handling. 💎🤖🤝

This tool provides a "Premium" monitoring experience by tapping into deep system kernel events (ETW) to track every byte leaving or entering your machine.

---

## 🌟 Key Features

- 🏎️ **Live Traffic Dashboard**: Real-time charts for upload and download speeds.
- 🕵️‍♂️ **Process Identification**: See exactly which application is consuming your bandwidth (Processes, PIDs).
- 🌍 **GeoIP Mapping**: Automatically resolves remote IPs to countries.
- 🔍 **Protocol Discovery**: Displays remote domains resolved via DNS sniffing.
- 📈 **Historical Consumption**: Persistent database (SQLite) for tracking app usage over time.
- 📉 **Anomaly Detection**: Intelligent log correlation to identify system events related to traffic peaks.
- 🛡️ **Stable & Bulletproof**: Built with thread-safe diagnostic engines and hardened ETW parsers.
- 📥 **CSV Export**: Export your traffic history for external reporting.

---

## 📸 Screenshots

_(Add your screenshots here!)_

---

## 🚀 Getting Started

### Prerequisites

- **Windows 10/11** (Required for ETW Kernel Providers)
- **Visual Studio 2022** (with C++ Desktop development)
- **CMake** (3.20 or higher)

### Build Instructions

1. Clone this repository (once you've pushed it!):

   ```bash
   git clone https://github.com/YOUR_USERNAME/InetMonitor.git
   cd InetMonitor
   ```

2. Build using CMake:

   ```powershell
   cmake -B build
   cmake --build build --config Release
   ```

3. **Run as Administrator**:
   The app requires administrative privileges to listen to the Windows Kernel Network events.
   ```powershell
   ./build/Release/InetMonitor.exe
   ```

---

## 🛡️ Stability & Security

This tool uses **Thread-Safe** access to its SQLite database and features a **Hardened ETW Parser** with recursive-protection logic to handle high-frequency network events without crashing.

## 📜 License

MIT License. Feel free to use and contribute!
