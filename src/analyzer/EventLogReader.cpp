#include "EventLogReader.h"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

namespace analyzer {

EventLogReader::EventLogReader() = default;
EventLogReader::~EventLogReader() = default;

std::vector<LogEntry> EventLogReader::QueryEvents(const std::wstring &channel,
                                                  uint64_t startTime,
                                                  uint64_t endTime) {
  std::vector<LogEntry> results;

  // Convert epoch seconds to ISO8601 for XPath
  auto ToISO8601 = [](uint64_t epoch) -> std::wstring {
    FILETIME ft;
    SYSTEMTIME st;
    ULARGE_INTEGER ull;
    ull.QuadPart = (epoch + 11644473600ULL) * 10000000ULL;
    ft.dwLowDateTime = ull.LowPart;
    ft.dwHighDateTime = ull.HighPart;
    FileTimeToSystemTime(&ft, &st);

    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02dT%02d:%02d:%02d.000Z", st.wYear, st.wMonth,
               st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
  };

  std::wstring query = L"*[System[TimeCreated[@SystemTime >= '" +
                       ToISO8601(startTime) + L"' and @SystemTime <= '" +
                       ToISO8601(endTime) + L"']]]";

  EVT_HANDLE hResults =
      EvtQuery(nullptr, channel.c_str(), query.c_str(),
               EvtQueryChannelPath | EvtQueryReverseDirection);
  if (hResults == nullptr) {
    return results;
  }

  EVT_HANDLE hEvents[50];
  DWORD returned = 0;
  while (EvtNext(hResults, 50, hEvents, INFINITE, 0, &returned)) {
    for (DWORD i = 0; i < returned; i++) {
      LogEntry entry;

      // Render basic system info
      DWORD bufferSize = 0;
      DWORD propertyCount = 0;
      if (!EvtRender(nullptr, hEvents[i], EvtRenderEventValues, 0, nullptr,
                     &bufferSize, &propertyCount) &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buffer(bufferSize);
        if (EvtRender(nullptr, hEvents[i], EvtRenderEventValues, bufferSize,
                      buffer.data(), &bufferSize, &propertyCount)) {
          PEVT_VARIANT values = reinterpret_cast<PEVT_VARIANT>(buffer.data());

          if (propertyCount > EvtSystemProviderName &&
              values[EvtSystemProviderName].Type == EvtVarTypeString) {
            entry.ProviderName = values[EvtSystemProviderName].StringVal;
          }
          if (propertyCount > EvtSystemEventID &&
              values[EvtSystemEventID].Type == EvtVarTypeUInt16) {
            entry.EventId = values[EvtSystemEventID].UInt16Val;
          }
          if (propertyCount > EvtSystemTimeCreated &&
              values[EvtSystemTimeCreated].Type == EvtVarTypeFileTime) {
            entry.Timestamp = (values[EvtSystemTimeCreated].FileTimeVal -
                               116444736000000000ULL) /
                              10000000ULL;
          }
        }
      }

      // Render actual message
      EVT_HANDLE hMetadata =
          EvtOpenPublisherMetadata(nullptr, entry.ProviderName.c_str(), nullptr,
                                   GetUserDefaultLCID(), 0);
      if (hMetadata) {
        DWORD msgBufferSize = 0;
        if (!EvtFormatMessage(hMetadata, hEvents[i], 0, 0, nullptr,
                              EvtFormatMessageEvent, 0, nullptr,
                              &msgBufferSize) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
          std::vector<wchar_t> msgBuffer(msgBufferSize);
          if (EvtFormatMessage(hMetadata, hEvents[i], 0, 0, nullptr,
                               EvtFormatMessageEvent, msgBufferSize,
                               msgBuffer.data(), &msgBufferSize)) {
            entry.Message = msgBuffer.data();
          }
        }
        EvtClose(hMetadata);
      }

      if (entry.Message.empty()) {
        entry.Message = L"Event from " + entry.ProviderName +
                        L" (Detailed message unavailable)";
      }

      results.push_back(entry);
      EvtClose(hEvents[i]);
    }
  }

  EvtClose(hResults);
  return results;
}

} // namespace analyzer
