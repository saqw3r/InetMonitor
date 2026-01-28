#include "AppMonitor.h"
#include "ETWHeaders.h"
#include "utils/Logger.h"
#include <iostream>
#include <sstream>


namespace monitor {

AppMonitor::AppMonitor(db::Database &db) : m_db(db) {}

AppMonitor::~AppMonitor() { Stop(); }

bool AppMonitor::Start() {
  LOG("AppMonitor::Start called");
  m_stopFlush = false;
  try {
    m_flushThread = std::thread(&AppMonitor::FlushLoop, this);
  } catch (const std::exception &e) {
    LOG("Error: Flush thread failed: " + std::string(e.what()));
    return false;
  }

  return m_controller.Start(L"InetMonitorAppSession",
                            [this](PEVENT_RECORD pEvent) {
                              try {
                                this->OnEvent(pEvent);
                              } catch (...) {
                              }
                            });
}

void AppMonitor::Stop() {
  m_controller.Stop();
  m_stopFlush = true;
  if (m_flushThread.joinable())
    m_flushThread.join();
}

void AppMonitor::OnEvent(PEVENT_RECORD pEvent) {
  m_totalEventsReceived++;

  static const GUID TcpipGuid = {
      0x2f07e239,
      0x2db3,
      0x40ab,
      {0x99, 0x2f, 0xb9, 0x33, 0x06, 0x91, 0x23, 0xa1}};
  static const GUID DnsGuid = {
      0x1c95126e,
      0x7eea,
      0x49a9,
      {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
  static const GUID KernelNetGuid = {
      0x7dd42a49,
      0x5329,
      0x4832,
      {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

  std::wstring providerName = L"Unknown";
  bool isWellKnown = true;
  if (memcmp(&pEvent->EventHeader.ProviderId, &TcpipGuid, sizeof(GUID)) == 0)
    providerName = L"TCPIP";
  else if (memcmp(&pEvent->EventHeader.ProviderId, &DnsGuid, sizeof(GUID)) == 0)
    providerName = L"DNS";
  else if (memcmp(&pEvent->EventHeader.ProviderId, &KernelNetGuid,
                  sizeof(GUID)) == 0)
    providerName = L"K-NET";
  else
    isWellKnown = false;

  {
    std::lock_guard<std::mutex> lock(m_debugMutex);
    if (!isWellKnown) {
      RPC_WSTR guidStr = nullptr;
      if (UuidToStringW(&pEvent->EventHeader.ProviderId, &guidStr) ==
          RPC_S_OK) {
        providerName = (wchar_t *)guidStr;
        RpcStringFreeW(&guidStr);
      }
    }

    if (m_lastEvents.size() >= 10)
      m_lastEvents.erase(m_lastEvents.begin());
    m_lastEvents.push_back(
        {pEvent->EventHeader.EventDescriptor.Id, providerName});

    std::string kA = "Unknown";
    if (providerName == L"TCPIP")
      kA = "TCPIP";
    else if (providerName == L"DNS")
      kA = "DNS";
    else if (providerName == L"K-NET")
      kA = "K-NET";
    else {
      int sz = WideCharToMultiByte(CP_UTF8, 0, providerName.c_str(),
                                   (int)providerName.length(), nullptr, 0,
                                   nullptr, nullptr);
      if (sz > 0) {
        kA.resize(sz);
        WideCharToMultiByte(CP_UTF8, 0, providerName.c_str(),
                            (int)providerName.length(), &kA[0], sz, nullptr,
                            nullptr);
      }
    }
    kA += ":" + std::to_string(pEvent->EventHeader.EventDescriptor.Id);
    m_eventCounts[kA]++;
  }

  std::wstring parseError;
  DnsEvent dns;
  if (m_parser.ParseDns(pEvent, dns, parseError)) {
    m_dnsEventsCount++;
    m_dnsResolver.AddMapping(dns.ResultIP, dns.QueryName);
    return;
  }

  TrafficEvent te;
  if (m_parser.Parse(pEvent, te, parseError)) {
    m_parsedEventsReceived++;
    std::lock_guard<std::mutex> lock(m_statsMutex);
    StatsKey skey{te.ProcessId, te.RemoteIP};
    if (te.IsUpload) {
      m_bufferedStats[skey].BytesUp += te.Bytes;
      m_cumulativeStats[skey].BytesUp += te.Bytes;
    } else {
      m_bufferedStats[skey].BytesDown += te.Bytes;
      m_cumulativeStats[skey].BytesDown += te.Bytes;
    }
  } else if (!parseError.empty()) {
    std::lock_guard<std::mutex> lock(m_debugMutex);
    m_lastParsingError = parseError;
  }
}

uint64_t AppMonitor::GetTotalEventsCount() const {
  return m_totalEventsReceived;
}
uint64_t AppMonitor::GetParsedEventsCount() const {
  return m_parsedEventsReceived;
}

std::vector<AppMonitor::DebugEvent> AppMonitor::GetLastEvents() {
  std::lock_guard<std::mutex> lock(m_debugMutex);
  return m_lastEvents;
}
std::map<std::string, uint64_t> AppMonitor::GetEventCounts() {
  std::lock_guard<std::mutex> lock(m_debugMutex);
  return m_eventCounts;
}
std::wstring AppMonitor::GetLastParsingError() const {
  std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(m_debugMutex));
  return m_lastParsingError;
}

std::vector<AppMonitor::AppStatsSnapshot> AppMonitor::GetCumulativeSnapshot() {
  std::vector<AppStatsSnapshot> snapshot;
  std::lock_guard<std::mutex> lock(m_statsMutex);
  for (auto const &[key, stats] : m_cumulativeStats) {
    std::wstring procName = m_tracker.GetProcessName(key.Pid);
    std::wstring domain = m_dnsResolver.GetDomain(key.RemoteIP);
    std::wstring country = m_geoIp.GetCountryCode(key.RemoteIP);
    snapshot.push_back({key.Pid, procName, key.RemoteIP, domain, country,
                        stats.BytesUp, stats.BytesDown});
  }
  return snapshot;
}

void AppMonitor::FlushLoop() {
  while (!m_stopFlush) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    if (m_stopFlush)
      break;

    try {
      std::map<StatsKey, AccumulatedStats> toFlush;
      {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        toFlush.swap(m_bufferedStats);
      }
      if (toFlush.empty())
        continue;

      for (auto const &[key, stats] : toFlush) {
        std::wstring procName = m_tracker.GetProcessName(key.Pid);
        std::wstring domain = m_dnsResolver.GetDomain(key.RemoteIP);
        std::wstring country = m_geoIp.GetCountryCode(key.RemoteIP);
        std::wstring displayName = procName;
        if (!domain.empty())
          displayName += L" -> " + domain;
        else if (!key.RemoteIP.empty())
          displayName += L" -> " + key.RemoteIP;
        if (!country.empty() && country != L".." && country != L"Local")
          displayName += L" [" + country + L"]";

        int appId = m_db.GetOrAddApp(displayName);
        if (appId != -1)
          m_db.LogTraffic(appId, stats.BytesUp, stats.BytesDown);
      }
    } catch (...) {
    }
  }
}

} // namespace monitor
