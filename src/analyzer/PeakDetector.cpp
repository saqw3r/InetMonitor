#include "PeakDetector.h"
#include <ctime>
#include <iostream>
#include <sqlite3.h>


namespace analyzer {

PeakDetector::PeakDetector(db::Database &db) : m_db(db) {}

std::vector<TrafficPeak> PeakDetector::FindPeaks(int secondsBack,
                                                 uint64_t thresholdBytes) {
  std::vector<TrafficPeak> peaks;
  sqlite3_stmt *stmt;

  // Group traffic by minute buckets and find those exceeding threshold
  // timestamp is in seconds
  const char *query = "SELECT (timestamp / 60) * 60 as bucket, app_id, "
                      "SUM(bytes_up + bytes_down) as total "
                      "FROM traffic_log "
                      "WHERE timestamp >= ? "
                      "GROUP BY bucket, app_id "
                      "HAVING total >= ? "
                      "ORDER BY bucket DESC;";

  if (sqlite3_prepare_v2(m_db.GetHandle(), query, -1, &stmt, nullptr) !=
      SQLITE_OK) {
    return peaks;
  }

  sqlite3_bind_int64(stmt, 1, std::time(nullptr) - secondsBack);
  sqlite3_bind_int64(stmt, 2, thresholdBytes);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    TrafficPeak peak;
    peak.Timestamp = sqlite3_column_int64(stmt, 0);
    peak.AppId = sqlite3_column_int(stmt, 1);
    peak.TotalBytes = sqlite3_column_int64(stmt, 2);
    peaks.push_back(peak);
  }

  sqlite3_finalize(stmt);
  return peaks;
}

} // namespace analyzer
