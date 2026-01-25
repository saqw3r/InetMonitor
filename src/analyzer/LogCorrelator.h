#pragma once

#include "ConclusionGenerator.h"
#include "EventLogReader.h"
#include "PeakDetector.h"
#include <string>
#include <vector>

namespace analyzer {

struct CorrelatedPeak {
  TrafficPeak Peak;
  std::wstring AppName;
  std::vector<LogEntry> RelatedEvents;
  AnalysisConclusion Conclusion;
};

class LogCorrelator {
public:
  LogCorrelator(db::Database &db);

  std::vector<CorrelatedPeak> Correlate(int secondsBack,
                                        uint64_t thresholdBytes);

private:
  db::Database &m_db;
  PeakDetector m_detector;
  EventLogReader m_logReader;
};

} // namespace analyzer
