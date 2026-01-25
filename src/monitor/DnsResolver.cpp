#include "DnsResolver.h"
#include <iomanip>
#include <sstream>


namespace monitor {

void DnsResolver::AddMapping(const std::wstring &ipAddress,
                             const std::wstring &domainName) {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_cache[ipAddress] = domainName;
}

std::wstring DnsResolver::GetDomain(const std::wstring &ipAddress) const {
  std::lock_guard<std::mutex> lock(m_mutex);
  auto it = m_cache.find(ipAddress);
  if (it != m_cache.end()) {
    return it->second;
  }
  return L""; // Not found
}

std::wstring DnsResolver::IPv4ToString(uint32_t ip) {
  std::wstringstream ss;
  ss << ((ip >> 0) & 0xFF) << L"." << ((ip >> 8) & 0xFF) << L"."
     << ((ip >> 16) & 0xFF) << L"." << ((ip >> 24) & 0xFF);
  return ss.str();
}

std::wstring DnsResolver::IPv6ToString(const uint8_t *ip) {
  std::wstringstream ss;
  for (int i = 0; i < 16; i += 2) {
    if (i > 0)
      ss << L":";
    ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)ip[i]
       << std::setw(2) << std::setfill(L'0') << (int)ip[i + 1];
  }
  return ss.str();
}

} // namespace monitor
