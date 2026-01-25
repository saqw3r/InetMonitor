#pragma once

#include <cstdint>
#include <string>
#include <vector>


namespace analyzer {

struct LogEntry {
  std::wstring ProviderName;
  std::wstring Message;
  uint64_t Timestamp;
  uint32_t EventId;
};

class EventLogReader {
public:
  EventLogReader();
  ~EventLogReader();

  std::vector<LogEntry> QueryEvents(const std::wstring &channel,
                                    uint64_t startTime, uint64_t endTime);

private:
  // Helper to format event message
  std::wstring GetEventMessage(void *hEvent);
};

} // namespace analyzer
