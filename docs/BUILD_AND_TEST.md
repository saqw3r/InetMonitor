# Build, Run, Debug, and Test Guide

This document provides instructions on how to work with the **Internet Monitor** project.

## Prerequisites

- **CMake** (Version 3.20 or later)
- **C++ Compiler**: A C++20 compatible compiler.
  - **Windows**: Visual Studio 2019/2022 (MSVC) is recommended.
- **Git**: To fetch dependencies (ImGui, SQLite).

## 1. Building the Project

We use CMake to manage the build process.

### Command Line (shell/PowerShell)

1.  **Configure**: Generate the build files.

    ```powershell
    # Run from the project root (d:\CppSources\InetMonitor)
    cmake -S . -B build
    ```

2.  **Build**: Compile the application.
    ```powershell
    cmake --build build --config Debug
    ```

    - _Note_: Use `--config Release` for an optimized build.

### Visual Studio

1.  Open Visual Studio.
2.  Select **"Open a local folder"** and choose the `InetMonitor` directory.
3.  Visual Studio should automatically detect the `CMakeLists.txt` and configure the project.
4.  Select `InetMonitor.exe` from the startup item dropdown (top toolbar) and press **F7** (Build Solution).

## 2. Running the Application

### Admin Privileges Required

> [!IMPORTANT]
> Because this tool uses **Event Tracing for Windows (ETW)** to capture kernel network traffic, it **MUST be run as Administrator**.

1.  **From Command Line**:

    ```powershell
    # Navigate to the output directory (exact path depends on generator)
    # Typically:
    .\build\Debug\InetMonitor.exe
    ```

    - _Tip_: If you get an "Access Denied" error or no traffic data, ensure your terminal is running as Administrator.

2.  **From Visual Studio**:
    - You must start Visual Studio **as Administrator** for the debugger to launch the application with the necessary privileges.

## 3. Debugging

### Visual Studio (Recommended)

1.  **Run VS as Administrator**.
2.  Set breakpoints in `src/main.cpp` or other source files.
3.  Press **F5** (Start Debugging).
4.  The application will launch, and you can inspect variables, call stacks, and memory.

### VS Code

1.  Ensure you have the **C/C++ Extension** and **CMake Tools** extension installed.
2.  Open the folder in VS Code.
3.  Configure the project (`Ctrl+Shift+P` -> `CMake: Configure`).
4.  Build (`F7` or status bar).
5.  To debug, you may need to launch VS Code as Administrator or configure a launch.json that attaches to the process.

## 4. Testing

### Manual Verification (Current Phase) to verify basic functionality:

Since the project is in early stages, testing is primarily manual.

1.  **Project Setup Test**:
    - Build and Run.
    - Verify the window appears with the "Hello, world!" (or similar) ImGui status text.
    - Verify `SQLite Version` is printed in the console output.

2.  **Monitor Test** (When implemented):
    - Start a large download (e.g., a Linux ISO or 4K video).
    - Check if the tool reports high "Download" bandwidth.
    - Verify the process name matches (e.g., `chrome.exe`).

### Automated Tests (Planned)

- **Unit Tests**: Will be added using CTest.
- **Logic Tests**: verifying that 1024 bytes = 1 KB in the stats calculator.
