#include "TraceParser.h"
#include "DnsResolver.h"
#include "ETWHeaders.h"
#include <map>
#include <vector>


#pragma comment(lib, "tdh.lib")

namespace monitor {

struct EventSchema {
  bool IsRelevant = false;
  bool IsUpload = false;
  std::wstring SizePropName;
  std::wstring AddrPropName;
};

static std::map<uint64_t, EventSchema> g_cache;
std::mutex TraceParser::s_cacheMutex;
std::mutex TraceParser::s_tdhMutex;

TraceParser::TraceParser() = default;
TraceParser::~TraceParser() = default;

// Safe wide-string reader from aligned buffer
static std::wstring SafeGetWStr(PTRACE_EVENT_INFO pInfo, ULONG offset,
                                ULONG totalSize) {
  if (!offset || offset >= totalSize)
    return L"";
  wchar_t *pStr = (wchar_t *)((BYTE *)pInfo + offset);
  // Remaining bytes in buffer
  ULONG remainingBytes = totalSize - offset;
  ULONG maxChars = remainingBytes / sizeof(wchar_t);
  if (maxChars == 0)
    return L"";

  // Scan for null terminator within remaining buffer
  size_t len = 0;
  while (len < maxChars && pStr[len] != L'\0') {
    len++;
  }
  return std::wstring(pStr, len);
}

bool TraceParser::Parse(PEVENT_RECORD pEv, TrafficEvent &out,
                        std::wstring &err) {
  uint16_t id = pEv->EventHeader.EventDescriptor.Id;
  uint64_t key = ((uint64_t)pEv->EventHeader.ProviderId.Data1 << 16) | id;

  EventSchema s;
  bool found = false;
  {
    std::lock_guard<std::mutex> lock(s_cacheMutex);
    if (g_cache.count(key)) {
      if (!g_cache[key].IsRelevant)
        return false;
      s = g_cache[key];
      found = true;
    }
  }

  if (found) {
    PROPERTY_DATA_DESCRIPTOR d;
    d.PropertyName = (ULONGLONG)s.SizePropName.c_str();
    d.ArrayIndex = ULONG_MAX;
    d.Reserved = 0;
    DWORD pSize = 0;
    uint64_t bytes = 0;

    std::lock_guard<std::mutex> tdhLock(s_tdhMutex);
    if (TdhGetPropertySize(pEv, 0, nullptr, 1, &d, &pSize) == ERROR_SUCCESS) {
      if (pSize == 4) {
        uint32_t b32 = 0;
        if (TdhGetProperty(pEv, 0, nullptr, 1, &d, 4, (BYTE *)&b32) ==
            ERROR_SUCCESS)
          bytes = b32;
      } else if (pSize == 8) {
        TdhGetProperty(pEv, 0, nullptr, 1, &d, 8, (BYTE *)&bytes);
      }
    }
    if (bytes == 0)
      return false;

    out.Bytes = bytes;
    out.IsUpload = s.IsUpload;
    out.ProcessId = pEv->EventHeader.ProcessId;
    out.Timestamp = pEv->EventHeader.TimeStamp.QuadPart;
    out.RemoteIP = L"";

    if (!s.AddrPropName.empty()) {
      d.PropertyName = (ULONGLONG)s.AddrPropName.c_str();
      if (TdhGetPropertySize(pEv, 0, nullptr, 1, &d, &pSize) == ERROR_SUCCESS) {
        if (pSize == 4) {
          uint32_t v4 = 0;
          TdhGetProperty(pEv, 0, nullptr, 1, &d, 4, (BYTE *)&v4);
          out.RemoteIP = DnsResolver::IPv4ToString(v4);
        } else if (pSize == 16) {
          uint8_t v6[16];
          TdhGetProperty(pEv, 0, nullptr, 1, &d, 16, v6);
          out.RemoteIP = DnsResolver::IPv6ToString(v6);
        }
      }
    }
    return true;
  }

  // Schema resolution
  std::vector<uint64_t> buffer(512);
  DWORD buffSize = (DWORD)(buffer.size() * 8);
  PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)buffer.data();

  std::unique_lock<std::mutex> tdhLock(s_tdhMutex);
  ULONG status = TdhGetEventInformation(pEv, 0, nullptr, pInfo, &buffSize);
  if (status == ERROR_INSUFFICIENT_BUFFER) {
    buffer.resize((buffSize + 7) / 8);
    pInfo = (PTRACE_EVENT_INFO)buffer.data();
    status = TdhGetEventInformation(pEv, 0, nullptr, pInfo, &buffSize);
  }
  if (status != ERROR_SUCCESS)
    return false;

  std::wstring task = SafeGetWStr(pInfo, pInfo->TaskNameOffset, buffSize);
  std::wstring opcode = SafeGetWStr(pInfo, pInfo->OpcodeNameOffset, buffSize);
  std::wstring combined = task + L" " + opcode;

  bool send = (id == 10 || id == 12 || id == 26 || id == 28 ||
               combined.find(L"Send") != std::wstring::npos ||
               combined.find(L"Tx") != std::wstring::npos);
  bool recv = (id == 11 || id == 13 || id == 27 || id == 29 ||
               combined.find(L"Recv") != std::wstring::npos ||
               combined.find(L"Rx") != std::wstring::npos ||
               combined.find(L"Receive") != std::wstring::npos);

  if (send || recv) {
    s.IsUpload = send;
    for (ULONG i = 0; i < pInfo->PropertyCount; i++) {
      std::wstring n = SafeGetWStr(
          pInfo, pInfo->EventPropertyInfoArray[i].NameOffset, buffSize);
      if (s.SizePropName.empty() &&
          (n == L"size" || n == L"Size" || n == L"datalen" ||
           n.find(L"Bytes") != std::wstring::npos))
        s.SizePropName = n;
      if (s.AddrPropName.empty() && (n.find(L"Addr") != std::wstring::npos ||
                                     n == L"daddr" || n == L"RemoteAddress"))
        s.AddrPropName = n;
    }
    if (!s.SizePropName.empty())
      s.IsRelevant = true;
  }
  tdhLock.unlock();

  {
    std::lock_guard<std::mutex> lock(s_cacheMutex);
    g_cache[key] = s;
  }
  return false;
}

bool TraceParser::ParseDns(PEVENT_RECORD pEv, DnsEvent &out,
                           std::wstring &err) {
  static const GUID DnsGuid = {
      0x1c95126e,
      0x7eea,
      0x49a9,
      {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
  if (memcmp(&pEv->EventHeader.ProviderId, &DnsGuid, sizeof(GUID)) != 0)
    return false;
  uint16_t id = pEv->EventHeader.EventDescriptor.Id;
  if (id < 3000 || id > 3020)
    return false;

  std::vector<uint64_t> buffer(512);
  DWORD buffSize = (DWORD)(buffer.size() * 8);
  PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)buffer.data();

  std::lock_guard<std::mutex> tdhLock(s_tdhMutex);
  if (TdhGetEventInformation(pEv, 0, nullptr, pInfo, &buffSize) !=
      ERROR_SUCCESS) {
    if (buffSize > buffer.size() * 8) {
      buffer.resize((buffSize + 7) / 8);
      pInfo = (PTRACE_EVENT_INFO)buffer.data();
      if (TdhGetEventInformation(pEv, 0, nullptr, pInfo, &buffSize) !=
          ERROR_SUCCESS)
        return false;
    } else
      return false;
  }

  for (ULONG i = 0; i < pInfo->PropertyCount; i++) {
    std::wstring n = SafeGetWStr(
        pInfo, pInfo->EventPropertyInfoArray[i].NameOffset, buffSize);
    PROPERTY_DATA_DESCRIPTOR d;
    d.PropertyName = (ULONGLONG)n.c_str();
    d.ArrayIndex = ULONG_MAX;
    d.Reserved = 0;
    DWORD psz = 0;
    if (TdhGetPropertySize(pEv, 0, nullptr, 1, &d, &psz) != ERROR_SUCCESS ||
        psz == 0)
      continue;
    std::vector<wchar_t> b(psz / 2 + 1, 0);
    TdhGetProperty(pEv, 0, nullptr, 1, &d, psz, (BYTE *)b.data());
    if (n == L"QueryName")
      out.QueryName = b.data();
    else if (n == L"QueryResults" || n == L"Address") {
      if (out.ResultIP.empty())
        out.ResultIP = b.data();
    }
  }
  return !out.QueryName.empty() && !out.ResultIP.empty();
}

} // namespace monitor
