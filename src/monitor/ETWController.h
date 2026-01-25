#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

// Forward declarations
typedef struct _EVENT_RECORD EVENT_RECORD, *PEVENT_RECORD;
typedef unsigned __int64 TRACEHANDLE;

namespace monitor {

// Callback for handling raw events
using EventCallback = std::function<void(PEVENT_RECORD)>;

class ETWController {
public:
  ETWController();
  ~ETWController();

  bool Start(const std::wstring &sessionName, EventCallback callback);
  void Stop();
  bool IsRunning() const { return m_isRunning; }

  // Internal use for static callback
  void OnEvent(PEVENT_RECORD pEvent);

  // Diagnostics
  unsigned long GetLastStartTraceError() const { return m_lastStartTraceError; }
  unsigned long GetLastEnableError() const { return m_lastEnableError; }
  unsigned long GetLastOpenTraceError() const { return m_lastOpenTraceError; }
  unsigned long GetLastProcessTraceError() const {
    return m_lastProcessTraceError;
  }

private:
  void ProcessTraceLoop();
  bool SetupSession();
  bool EnableProviders();

private:
  std::wstring m_sessionName;
  EventCallback m_callback;

  TRACEHANDLE m_sessionHandle = 0;
  TRACEHANDLE m_traceHandle = 0;

  std::thread m_workerThread;
  std::atomic<bool> m_isRunning{false};

  std::vector<uint8_t> m_propertiesBuffer;

  // Error tracking
  std::atomic<unsigned long> m_lastStartTraceError{0};
  std::atomic<unsigned long> m_lastEnableError{0};
  std::atomic<unsigned long> m_lastOpenTraceError{0};
  std::atomic<unsigned long> m_lastProcessTraceError{0};
};

} // namespace monitor
