#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>


namespace monitor {

// Caches IP address to domain name mappings from DNS queries
class DnsResolver {
public:
  DnsResolver() = default;

  // Called when a DNS query result is observed
  void AddMapping(const std::wstring &ipAddress,
                  const std::wstring &domainName);

  // Lookup domain name for an IP address
  std::wstring GetDomain(const std::wstring &ipAddress) const;

  // Convert IPv4 bytes to string
  static std::wstring IPv4ToString(uint32_t ip);

  // Convert IPv6 bytes to string
  static std::wstring IPv6ToString(const uint8_t *ip);

private:
  mutable std::mutex m_mutex;
  std::unordered_map<std::wstring, std::wstring> m_cache; // IP -> Domain
};

} // namespace monitor
