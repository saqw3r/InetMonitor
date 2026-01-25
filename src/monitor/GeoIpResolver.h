#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>


namespace monitor {

// Resolves IP addresses to country codes using a web API
class GeoIpResolver {
public:
  GeoIpResolver();
  ~GeoIpResolver();

  // Returns country code (e.g., "US", "UA") if known, else ".." or "Local"
  std::wstring GetCountryCode(const std::wstring &ipAddress);

private:
  void WorkerLoop();
  std::wstring FetchFromApi(const std::wstring &ip);
  bool IsLocal(const std::wstring &ip);

  std::mutex m_mutex;
  std::unordered_map<std::wstring, std::wstring> m_cache;

  std::queue<std::wstring> m_pendingIps;
  std::unordered_map<std::wstring, bool>
      m_requested; // To avoid duplicate requests

  std::condition_variable m_cv;
  std::thread m_workerThread;
  std::atomic<bool> m_stop{false};
};

} // namespace monitor
