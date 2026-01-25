# Internet Monitor Tool - Implementation Plan

## Goal Description
Implement a Windows desktop application to monitor real-time and historical internet usage (upload/download). The tool will group traffic by application, provide statistical breakdowns over time (1h, 4h, 24h, 1w, 1m), and correlate high-usage peaks with Windows Event Logs to identify triggers (e.g., Windows Updates, Steam downloads).

## User Review Required
> [!IMPORTANT]
> **Admin Privileges**: The application requires Administrator privileges to run because it uses **Event Tracing for Windows (ETW)** to capture kernel-level network traffic and access System Event Logs.

> [!NOTE]
> **UI Choice**: I am proposing **Dear ImGui** for the user interface. It provides a highly responsive, developer-centric visualization (charts/tables) and is easy to integrate with C++.

## Proposed Architecture

### Tech Stack
- **Language**: C++20
- **Build System**: CMake
- **Network Monitoring**: Windows ETW (Kernel Mode Provider)
- **Database**: SQLite3 (for historical data persistence)
- **UI Framework**: Dear ImGui (with DX11 or OpenGL backend)
- **Event Logs**: Windows Event Log API (`Wevtapi.lib`)

### Component Breakdown

#### [Core] Network Monitor (`src/monitor`)
- **ETWController**: Manages the Kernel Trace Session.
- **TraceConsumer**: Consumes `TcpIp` and `UdpIp` events.
    - Captures `Send`/`Recv` events to calculate bytes.
    - Captures `Connect`/`Disconnect` to identify streams.
- **ProcessTracker**: resolving specific PIDs to executable names (e.g., `chrome.exe`).

#### [Core] Database Layer (`src/db`)
- **Schema**:
    - `Process_Log`: Maps PID + StartTime -> AppName.
    - `Traffic_Samples`: Timestamp, ProcessID, BytesUp, BytesDown.
- **Aggregator**: Methods to specific queries like "Top Apps by Usage in last 4h".

#### [Core] Analyzer (`src/analyzer`)
- **PeakDetector**: Scans the database for traffic spikes exceeding a threshold.
- **LogCorrelator**: Queries Windows Event Logs (`System`, `Application`) for events occurring +/- 2 minutes around a peak.
- **ConclusionGenerator**: Simple heuristic engine (e.g., if "WindowsUpdateClient" event found -> "System Update").

#### [UI] Dashboard (`src/ui`)
- **LiveView**: Real-time scrolling plot of Upload/Download speed.
- **StatsView**: Tables showing GB usage per App for selected time range.
- **EventView**: List of triggered events and conclusions.

## Verification Plan

### Automated Verification
- **Unit Tests**: Test DB insertion/retrieval logic.
- **Bandwidth Benchmark**: Run a scheduled download (e.g., `curl`) of a known file size and verify the monitor reports the correct volume (+/- 5%).

### Manual Verification
- **Live Test**: Open a browser, watch a 4K video, and ensure the "Browser" process shows high download usage.
- **Event Test**: Trigger a Windows Update or Stream download and check if the "Conclusion" section picks it up.
