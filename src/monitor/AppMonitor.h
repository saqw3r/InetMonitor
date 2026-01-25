#pragma once

#include "../db/Database.h"
#include "DnsResolver.h"
#include "ETWController.h"
#include "GeoIpResolver.h"
#include "ProcessTracker.h"
#include "TraceParser.h"

#include <atomic>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

namespace monitor {

// Key for aggregating stats by process + remote IP
struct StatsKey {
  uint32_t Pid;
  std::wstring RemoteIP;

  bool operator<(const StatsKey &other) const {
    if (Pid != other.Pid)
      return Pid < other.Pid;
    return RemoteIP < other.RemoteIP;
  }
};

struct AccumulatedStats {
  uint64_t BytesUp = 0;
  uint64_t BytesDown = 0;
};

class AppMonitor {
public:
  AppMonitor(db::Database &db);
  ~AppMonitor();

  bool Start();
  void Stop();

  uint64_t GetTotalEventsCount() const;
  uint64_t GetParsedEventsCount() const;

  struct ETWStatus {
    unsigned long StartTraceError;
    unsigned long EnableError;
    unsigned long OpenTraceError;
    unsigned long ProcessTraceError;
  };
  ETWStatus GetETWStatus() const;

  struct AppStatsSnapshot {
    uint32_t Pid;
    std::wstring ProcessName;
    std::wstring RemoteIP;
    std::wstring Domain;  // Resolved from DNS cache
    std::wstring Country; // Resolved from GeoIP
    uint64_t Up;
    uint64_t Down;

    AppStatsSnapshot(uint32_t pid, std::wstring pname, std::wstring rip,
                     std::wstring dom, std::wstring count, uint64_t u,
                     uint64_t d)
        : Pid(pid), ProcessName(pname), RemoteIP(rip), Domain(dom),
          Country(count), Up(u), Down(d) {}
  };
  std::vector<AppStatsSnapshot> GetRawBufferSnapshot();

  struct DebugEvent {
    uint16_t Id;
    std::wstring Provider;
  };
  std::vector<DebugEvent> GetLastEvents();
  std::map<std::string, uint64_t> GetEventCounts();
  uint64_t GetDnsEventsCount() const { return m_dnsEventsCount; }
  std::wstring GetLastParsingError() const;

private:
  void OnEvent(PEVENT_RECORD pEvent);
  void FlushLoop();

  db::Database &m_db;
  ETWController m_controller;
  TraceParser m_parser;
  ProcessTracker m_tracker;
  DnsResolver m_dnsResolver;
  GeoIpResolver m_geoIp;

  std::mutex m_statsMutex;
  std::map<StatsKey, AccumulatedStats> m_bufferedStats;
  std::vector<DebugEvent> m_lastEvents; // Rotating buffer for debug
  std::mutex m_debugMutex;
  std::wstring m_lastParsingError;
  std::map<std::string, uint64_t> m_eventCounts;

  std::atomic<uint64_t> m_totalEventsReceived{0};
  std::atomic<uint64_t> m_parsedEventsReceived{0};
  std::atomic<uint64_t> m_dnsEventsCount{0};

  std::atomic<bool> m_stopFlush{false};
  std::thread m_flushThread;
};

} // namespace monitor
