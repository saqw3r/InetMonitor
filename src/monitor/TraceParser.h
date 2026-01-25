#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

typedef struct _EVENT_RECORD EVENT_RECORD, *PEVENT_RECORD;

namespace monitor {

struct TrafficEvent {
  uint64_t Timestamp;
  uint32_t ProcessId;
  uint64_t Bytes;
  bool IsUpload;
  std::wstring RemoteIP;
};

struct DnsEvent {
  std::wstring QueryName;
  std::wstring ResultIP;
};

class TraceParser {
public:
  TraceParser();
  ~TraceParser();

  bool Parse(PEVENT_RECORD pEvent, TrafficEvent &outEvent, std::wstring &error);
  bool ParseDns(PEVENT_RECORD pEvent, DnsEvent &outEvent, std::wstring &error);

private:
  static std::mutex s_cacheMutex;
  static std::mutex s_tdhMutex;
};

} // namespace monitor
