#include "Database.h"
#include "../utils/Logger.h"
#include <ctime>
#include <iostream>
#include <sqlite3.h>
#include <windows.h>


namespace db {

Database::Database() = default;
Database::~Database() { Close(); }

bool Database::Open(const std::string &dbPath) {
  LOG("Database::Open called for: " + dbPath);
  std::lock_guard<std::recursive_mutex> lock(m_mutex);
  if (sqlite3_open(dbPath.c_str(), &m_db) != SQLITE_OK) {
    if (m_db) {
      LOG("Error: Failed to open database: " +
          std::string(sqlite3_errmsg(m_db)));
    }
    return false;
  }
  LOG("Database opened successfully");
  return InitSchema();
}

void Database::Close() {
  std::lock_guard<std::recursive_mutex> lock(m_mutex);
  if (m_db) {
    sqlite3_close(m_db);
    m_db = nullptr;
  }
}

bool Database::InitSchema() {
  LOG("Database::InitSchema starting");
  const char *sql =
      "CREATE TABLE IF NOT EXISTS apps (id INTEGER PRIMARY KEY, name TEXT "
      "UNIQUE);"
      "CREATE TABLE IF NOT EXISTS traffic_log (timestamp INTEGER, app_id "
      "INTEGER, bytes_up INTEGER, bytes_down INTEGER);"
      "CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON "
      "traffic_log(timestamp);"
      "CREATE INDEX IF NOT EXISTS idx_traffic_app ON traffic_log(app_id);";

  char *errMsg = nullptr;
  if (sqlite3_exec(m_db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
    if (errMsg) {
      LOG("Error: Failed to init schema: " + std::string(errMsg));
      sqlite3_free(errMsg);
    }
    return false;
  }
  LOG("Database::InitSchema successful");
  return true;
}

std::string Database::WToUTF8(const std::wstring &w) {
  if (w.empty())
    return "";
  int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.length(), nullptr,
                               0, nullptr, nullptr);
  if (sz <= 0)
    return "";
  std::string s(sz, 0);
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.length(), &s[0], sz,
                      nullptr, nullptr);
  return s;
}

std::wstring Database::UTF8ToW(const std::string &s) {
  if (s.empty())
    return L"";
  int sz =
      MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.length(), nullptr, 0);
  if (sz <= 0)
    return L"";
  std::wstring w(sz, 0);
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.length(), &w[0], sz);
  return w;
}

int Database::GetOrAddApp(const std::wstring &appName) {
  std::string utf8Name = WToUTF8(appName);
  std::lock_guard<std::recursive_mutex> lock(m_mutex);
  if (!m_db)
    return -1;

  sqlite3_stmt *stmt;
  const char *query = "SELECT id FROM apps WHERE name = ?;";
  if (sqlite3_prepare_v2(m_db, query, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;
  sqlite3_bind_text(stmt, 1, utf8Name.c_str(), -1, SQLITE_TRANSIENT);

  int id = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW)
    id = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);
  if (id != -1)
    return id;

  const char *ins = "INSERT INTO apps (name) VALUES (?);";
  if (sqlite3_prepare_v2(m_db, ins, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;
  sqlite3_bind_text(stmt, 1, utf8Name.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_step(stmt) == SQLITE_DONE)
    id = (int)sqlite3_last_insert_rowid(m_db);
  sqlite3_finalize(stmt);
  return id;
}

bool Database::LogTraffic(int appId, uint64_t bytesUp, uint64_t bytesDown) {
  std::lock_guard<std::recursive_mutex> lock(m_mutex);
  if (!m_db)
    return false;

  sqlite3_stmt *stmt;
  const char *query = "INSERT INTO traffic_log (timestamp, app_id, bytes_up, "
                      "bytes_down) VALUES (?, ?, ?, ?);";
  if (sqlite3_prepare_v2(m_db, query, -1, &stmt, nullptr) != SQLITE_OK)
    return false;

  sqlite3_bind_int64(stmt, 1, (sqlite3_int64)std::time(nullptr));
  sqlite3_bind_int(stmt, 2, appId);
  sqlite3_bind_int64(stmt, 3, (sqlite3_int64)bytesUp);
  sqlite3_bind_int64(stmt, 4, (sqlite3_int64)bytesDown);

  bool success = (sqlite3_step(stmt) == SQLITE_DONE);
  sqlite3_finalize(stmt);
  return success;
}

std::vector<AppUsage> Database::GetUsage(int secondsBack) {
  std::vector<AppUsage> results;
  std::lock_guard<std::recursive_mutex> lock(m_mutex);
  if (!m_db)
    return results;

  sqlite3_stmt *stmt;
  const char *query =
      "SELECT a.name, SUM(t.bytes_up), SUM(t.bytes_down) FROM apps a "
      "JOIN traffic_log t ON a.id = t.app_id WHERE t.timestamp >= ? "
      "GROUP BY a.id ORDER BY (SUM(t.bytes_up) + SUM(t.bytes_down)) DESC;";

  if (sqlite3_prepare_v2(m_db, query, -1, &stmt, nullptr) != SQLITE_OK)
    return results;
  sqlite3_bind_int64(stmt, 1,
                     (sqlite3_int64)(std::time(nullptr) - secondsBack));

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    AppUsage usage;
    const char *name = (const char *)sqlite3_column_text(stmt, 0);
    usage.AppName = UTF8ToW(name ? name : "");
    usage.TotalBytesUp = (uint64_t)sqlite3_column_int64(stmt, 1);
    usage.TotalBytesDown = (uint64_t)sqlite3_column_int64(stmt, 2);
    results.push_back(usage);
  }
  sqlite3_finalize(stmt);
  return results;
}

bool Database::ExportToCSV(const std::string &filename, int secondsBack) {
  FILE *f = nullptr;
  if (fopen_s(&f, filename.c_str(), "w") != 0)
    return false;
  fprintf(f, "Timestamp,Application,BytesUp,BytesDown\n");

  std::lock_guard<std::recursive_mutex> lock(m_mutex);
  if (!m_db) {
    fclose(f);
    return false;
  }

  sqlite3_stmt *stmt;
  const char *query =
      "SELECT t.timestamp, a.name, t.bytes_up, t.bytes_down FROM traffic_log t "
      "JOIN apps a ON t.app_id = a.id WHERE t.timestamp >= ? ORDER BY "
      "t.timestamp ASC;";
  if (sqlite3_prepare_v2(m_db, query, -1, &stmt, nullptr) != SQLITE_OK) {
    fclose(f);
    return false;
  }
  sqlite3_bind_int64(stmt, 1,
                     (sqlite3_int64)(std::time(nullptr) - secondsBack));

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    long long ts = sqlite3_column_int64(stmt, 0);
    const char *name = (const char *)sqlite3_column_text(stmt, 1);
    long long up = sqlite3_column_int64(stmt, 2);
    long long down = sqlite3_column_int64(stmt, 3);
    fprintf(f, "%lld,%s,%lld,%lld\n", ts, name ? name : "", up, down);
  }
  sqlite3_finalize(stmt);
  fclose(f);
  return true;
}

} // namespace db
