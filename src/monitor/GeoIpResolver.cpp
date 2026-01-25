#include "GeoIpResolver.h"
#include "../utils/Logger.h"
#include <iostream>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace monitor {

GeoIpResolver::GeoIpResolver() {
  LOG("GeoIpResolver initializing");
  m_workerThread = std::thread(&GeoIpResolver::WorkerLoop, this);
}

GeoIpResolver::~GeoIpResolver() {
  LOG("GeoIpResolver shutting down");
  m_stop = true;
  m_cv.notify_all();
  if (m_workerThread.joinable()) {
    LOG("Joining GeoIp worker thread");
    m_workerThread.join();
    LOG("GeoIp worker thread joined");
  }
}

std::wstring GeoIpResolver::GetCountryCode(const std::wstring &ipAddress) {
  if (ipAddress.empty() || IsLocal(ipAddress)) {
    return L"Local";
  }

  std::lock_guard<std::mutex> lock(m_mutex);
  auto it = m_cache.find(ipAddress);
  if (it != m_cache.end()) {
    return it->second;
  }

  // Not in cache, queue for lookup if not already requested
  if (m_requested.find(ipAddress) == m_requested.end()) {
    m_requested[ipAddress] = true;
    m_pendingIps.push(ipAddress);
    m_cv.notify_one();
  }

  return L".."; // Indicates lookup in progress
}

bool GeoIpResolver::IsLocal(const std::wstring &ip) {
  if (ip == L"127.0.0.1" || ip == L"::1")
    return true;
  if (ip.find(L"192.168.") == 0)
    return true;
  if (ip.find(L"10.") == 0)
    return true;
  if (ip.find(L"172.") == 0 && ip.length() >= 7) {
    // Very basic check for 172.16.x.x - 172.31.x.x
    try {
      int second = std::stoi(ip.substr(4, 2));
      if (second >= 16 && second <= 31)
        return true;
    } catch (...) {
    }
  }
  return false;
}

void GeoIpResolver::WorkerLoop() {
  LOG("GeoIpResolver::WorkerLoop starting");
  try {
    while (!m_stop) {
      std::wstring ip;
      {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this] { return m_stop || !m_pendingIps.empty(); });
        if (m_stop)
          break;
        ip = m_pendingIps.front();
        m_pendingIps.pop();
      }

      std::wstring code = FetchFromApi(ip);

      {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cache[ip] = code;
      }

      // Slow down to respect API limits (ip-api.com is 45 req/min)
      std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
  } catch (const std::exception &e) {
    LOG("Error: Exception in GeoIpResolver::WorkerLoop: " +
        std::string(e.what()));
  } catch (...) {
    LOG("Error: Unknown exception in GeoIpResolver::WorkerLoop");
  }
  LOG("GeoIpResolver::WorkerLoop exiting");
}

std::wstring GeoIpResolver::FetchFromApi(const std::wstring &ip) {
  HINTERNET hSession =
      WinHttpOpen(L"InetMonitor/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  std::wstring result = L"??";

  if (hSession) {
    HINTERNET hConnect =
        WinHttpConnect(hSession, L"ip-api.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (hConnect) {
      std::wstring path = L"/line/" + ip + L"?fields=countryCode";
      HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
                                              nullptr, WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
      if (hRequest) {
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
          if (WinHttpReceiveResponse(hRequest, nullptr)) {
            DWORD dwSize = 0;
            if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
              std::vector<char> buffer(dwSize + 1, 0);
              DWORD dwRead = 0;
              if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwRead)) {
                std::string s(buffer.data(), dwRead);
                // Remove newline
                while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
                  s.pop_back();

                if (!s.empty()) {
                  result = std::wstring(s.begin(), s.end());
                }
              }
            }
          }
        }
        WinHttpCloseHandle(hRequest);
      }
      WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
  }

  return result;
}

} // namespace monitor
