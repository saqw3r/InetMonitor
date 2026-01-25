#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3;

namespace db {

struct AppUsage {
  std::wstring AppName;
  uint64_t TotalBytesUp;
  uint64_t TotalBytesDown;
};

class Database {
public:
  Database();
  ~Database();

  bool Open(const std::string &dbPath);
  void Close();

  bool InitSchema();

  // App ID cache
  int GetOrAddApp(const std::wstring &appName);

  // Recording
  bool LogTraffic(int appId, uint64_t bytesUp, uint64_t bytesDown);

  // Querying
  std::vector<AppUsage> GetUsage(int secondsBack);

  bool ExportToCSV(const std::string &filename, int secondsBack);

  sqlite3 *GetHandle() { return m_db; }

private:
  std::string WToUTF8(const std::wstring &w);
  std::wstring UTF8ToW(const std::string &s);

  sqlite3 *m_db = nullptr;
  std::recursive_mutex m_mutex;
};

} // namespace db
