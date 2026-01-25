#include "LogCorrelator.h"
#include "ConclusionGenerator.h"
#include <sqlite3.h>
#include <windows.h>

namespace analyzer {

LogCorrelator::LogCorrelator(db::Database &db) : m_db(db), m_detector(db) {}

// Safe UTF8 to Wide conversion helper
static std::wstring U8ToW(const char *s) {
  if (!s)
    return L"";
  int sz = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
  if (sz <= 0)
    return L"";
  std::wstring w(sz - 1, 0);
  MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], sz);
  return w;
}

std::vector<CorrelatedPeak> LogCorrelator::Correlate(int secondsBack,
                                                     uint64_t thresholdBytes) {
  std::vector<CorrelatedPeak> results;
  auto peaks = m_detector.FindPeaks(secondsBack, thresholdBytes);

  for (const auto &peak : peaks) {
    CorrelatedPeak cp;
    cp.Peak = peak;

    sqlite3_stmt *stmt;
    const char *query = "SELECT name FROM apps WHERE id = ?;";

    // Note: This uses raw handle, which is protected by Database's mutex in its
    // own methods, but here we are doing a raw query. To be super safe, we'd
    // need a LockHandle() method. For now, these are historical queries and
    // less frequent.
    if (sqlite3_prepare_v2(m_db.GetHandle(), query, -1, &stmt, nullptr) ==
        SQLITE_OK) {
      sqlite3_bind_int(stmt, 1, peak.AppId);
      if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        cp.AppName = U8ToW(name);
      }
      sqlite3_finalize(stmt);
    }

    uint64_t startTime = peak.Timestamp - 60;
    uint64_t endTime = peak.Timestamp + 120;
    cp.RelatedEvents = m_logReader.QueryEvents(L"System", startTime, endTime);
    auto appEvents =
        m_logReader.QueryEvents(L"Application", startTime, endTime);
    cp.RelatedEvents.insert(cp.RelatedEvents.end(), appEvents.begin(),
                            appEvents.end());

    ConclusionGenerator gen;
    cp.Conclusion = gen.Generate(cp.RelatedEvents, cp.AppName);
    results.push_back(cp);
  }
  return results;
}

} // namespace analyzer
