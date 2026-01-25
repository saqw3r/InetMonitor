#include "ProcessTracker.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// Must come after windows.h
#include <tlhelp32.h>

#include <filesystem>

namespace monitor {

ProcessTracker::ProcessTracker() { RefreshAllProcesses(); }

void ProcessTracker::RefreshAllProcesses() {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
    return;

  PROCESSENTRY32W pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32W);

  if (Process32FirstW(hSnapshot, &pe32)) {
    do {
      std::lock_guard<std::mutex> lock(m_mutex);
      if (m_cache.find(pe32.th32ProcessID) == m_cache.end()) {
        m_cache[pe32.th32ProcessID] = pe32.szExeFile;
      }
    } while (Process32NextW(hSnapshot, &pe32));
  }

  CloseHandle(hSnapshot);
}

std::wstring ProcessTracker::GetProcessName(uint32_t pid) {
  std::lock_guard<std::mutex> lock(m_mutex);

  auto it = m_cache.find(pid);
  if (it != m_cache.end()) {
    return it->second;
  }

  std::wstring name = ResolveName(pid);
  m_cache[pid] = name;
  return name;
}

std::wstring ProcessTracker::ResolveName(uint32_t pid) {
  if (pid == 0)
    return L"System Idle";
  if (pid == 4)
    return L"System";

  // Try to get full path
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (hProcess) {
    wchar_t buffer[MAX_PATH * 2];
    DWORD size = MAX_PATH * 2;

    if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
      CloseHandle(hProcess);
      try {
        std::filesystem::path p(buffer);
        return p.filename().wstring();
      } catch (...) {
        return buffer;
      }
    }
    CloseHandle(hProcess);
  }

  // Fallback: search snapshot
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
      do {
        if (pe32.th32ProcessID == pid) {
          CloseHandle(hSnapshot);
          return pe32.szExeFile;
        }
      } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
  }

  return L"[PID:" + std::to_wstring(pid) + L"]";
}

} // namespace monitor
