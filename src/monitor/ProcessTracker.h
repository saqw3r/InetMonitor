#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

namespace monitor {

class ProcessTracker {
public:
  ProcessTracker();
  std::wstring GetProcessName(uint32_t pid);
  void RefreshAllProcesses();

private:
  std::wstring ResolveName(uint32_t pid);

  std::unordered_map<uint32_t, std::wstring> m_cache;
  std::mutex m_mutex;
};

} // namespace monitor
