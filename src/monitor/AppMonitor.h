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

  struct AppStatsSnapshot {
    uint32_t Pid;
    std::wstring ProcessName;
    std::wstring RemoteIP;
    std::wstring Domain;
    std::wstring Country;
    uint64_t TotalUp;   // Persistent total
    uint64_t TotalDown; // Persistent total

    AppStatsSnapshot(uint32_t pid, std::wstring pname, std::wstring rip,
                     std::wstring dom, std::wstring count, uint64_t tu,
                     uint64_t td)
        : Pid(pid), ProcessName(pname), RemoteIP(rip), Domain(dom),
          Country(count), TotalUp(tu), TotalDown(td) {}
  };

  // NEW: Returns cumulative statistics since start
  std::vector<AppStatsSnapshot> GetCumulativeSnapshot();

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
  std::map<StatsKey, AccumulatedStats> m_cumulativeStats; // NEW: Never cleared

  std::vector<DebugEvent> m_lastEvents;
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
