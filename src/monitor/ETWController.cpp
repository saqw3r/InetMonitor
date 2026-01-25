#include "ETWHeaders.h"
#include <initguid.h>

#include "../utils/Logger.h"
#include "ETWController.h"
#include <iostream>


// {9e814aad-3204-11d2-9a82-006008a86939}
DEFINE_GUID(MySystemTraceControlGuid, 0x9e814aad, 0x3204, 0x11d2, 0x9a, 0x82,
            0x00, 0x60, 0x08, 0xa8, 0x69, 0x39);

#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE) - 1)
#endif

namespace monitor {

static VOID WINAPI ProcessEventThunk(PEVENT_RECORD pEvent) {
  if (pEvent->UserContext) {
    auto *pController = reinterpret_cast<ETWController *>(pEvent->UserContext);
    pController->OnEvent(pEvent);
  }
}

ETWController::ETWController() : m_traceHandle(INVALID_PROCESSTRACE_HANDLE) {}

ETWController::~ETWController() { Stop(); }

void ETWController::OnEvent(PEVENT_RECORD pEvent) {
  if (m_callback) {
    m_callback(pEvent);
  }
}

bool ETWController::Start(const std::wstring &sessionName,
                          EventCallback callback) {
  if (m_isRunning)
    return false;

  m_sessionName = sessionName;
  m_callback = callback;

  if (!SetupSession()) {
    return false;
  }

  LOG("ETWController::Start called");
  m_isRunning = true;
  m_workerThread = std::thread(&ETWController::ProcessTraceLoop, this);
  LOG("ETW worker thread launched");
  return true;
}

void ETWController::Stop() {
  LOG("ETWController::Stop called");
  if (!m_isRunning) {
    LOG("ETWController already stopped");
    return;
  }

  m_isRunning = false;

  LOG("Closing ETW trace handle");
  if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
    CloseTrace(m_traceHandle);
    m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
  }

  LOG("Stopping ETW session handle");
  if (m_sessionHandle) {
    EVENT_TRACE_PROPERTIES *pProps =
        reinterpret_cast<EVENT_TRACE_PROPERTIES *>(m_propertiesBuffer.data());
    ControlTraceW(m_sessionHandle, m_sessionName.c_str(), pProps,
                  EVENT_TRACE_CONTROL_STOP);
    m_sessionHandle = 0;
  }

  if (m_workerThread.joinable()) {
    LOG("Joining ETW worker thread");
    m_workerThread.join();
    LOG("ETW worker thread joined");
  }
}

bool ETWController::SetupSession() {
  size_t buffSize = sizeof(EVENT_TRACE_PROPERTIES) +
                    (m_sessionName.length() + 1) * sizeof(wchar_t) + 1024;
  m_propertiesBuffer.assign(buffSize, 0);

  EVENT_TRACE_PROPERTIES *pProps =
      reinterpret_cast<EVENT_TRACE_PROPERTIES *>(m_propertiesBuffer.data());
  pProps->Wnode.BufferSize = static_cast<ULONG>(buffSize);
  pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  pProps->Wnode.ClientContext = 1; // QPC clock
  pProps->Wnode.Guid = {0};

  pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  wchar_t *pName = reinterpret_cast<wchar_t *>(m_propertiesBuffer.data() +
                                               pProps->LoggerNameOffset);
  wcscpy_s(pName, m_sessionName.length() + 1, m_sessionName.c_str());

  // Stop previous session
  ControlTraceW(0, m_sessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);

  // Start new
  ULONG status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), pProps);
  m_lastStartTraceError = status;

  if (status != ERROR_SUCCESS)
    return false;

  return EnableProviders();
}

bool ETWController::EnableProviders() {
  // Microsoft-Windows-TCPIP
  static const GUID TcpipGuid = {
      0x2f07e239,
      0x2db3,
      0x40ab,
      {0x99, 0x2f, 0xb9, 0x33, 0x06, 0x91, 0x23, 0xa1}};
  // Microsoft-Windows-DNS-Client
  static const GUID DnsGuid = {
      0x1c95126e,
      0x7eea,
      0x49a9,
      {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
  // Microsoft-Windows-Kernel-Network
  static const GUID KernelNetGuid = {
      0x7dd42a49,
      0x5329,
      0x4832,
      {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

  EnableTraceEx2(m_sessionHandle, &TcpipGuid,
                 EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                 0xFFFFFFFFFFFFFFFF, 0, 0, nullptr);
  EnableTraceEx2(m_sessionHandle, &DnsGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                 TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF, 0, 0, nullptr);
  EnableTraceEx2(m_sessionHandle, &KernelNetGuid,
                 EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                 0xFFFFFFFFFFFFFFFF, 0, 0, nullptr);

  return true;
}

void ETWController::ProcessTraceLoop() {
  LOG("ETWController::ProcessTraceLoop starting");
  EVENT_TRACE_LOGFILEW logFile = {0};
  logFile.LoggerName = const_cast<LPWSTR>(m_sessionName.c_str());
  logFile.ProcessTraceMode =
      PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  logFile.Context = this;
  logFile.EventRecordCallback = ProcessEventThunk;

  LOG("Opening ETW trace");
  m_traceHandle = OpenTraceW(&logFile);
  if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
    m_lastOpenTraceError = GetLastError();
    LOG("Error: OpenTraceW failed: " + std::to_string(m_lastOpenTraceError));
    return;
  }

  LOG("Entering ProcessTrace blocking call");
  ULONG status = ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
  m_lastProcessTraceError = status;
  LOG("ProcessTrace returned: " + std::to_string(status));

  if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
    LOG("Closing trace handle in loop exit");
    CloseTrace(m_traceHandle);
    m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
  }
  LOG("ETWController::ProcessTraceLoop exiting");
}

} // namespace monitor
