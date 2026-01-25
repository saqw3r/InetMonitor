#pragma once

#include "../db/Database.h"
#include <cstdint>
#include <vector>


namespace analyzer {

struct TrafficPeak {
  uint64_t Timestamp;
  int AppId;
  uint64_t TotalBytes;
};

class PeakDetector {
public:
  PeakDetector(db::Database &db);

  // Finds peaks in the last 'secondsBack' where total usage in a 1-minute
  // window exceeds 'thresholdBytes'
  std::vector<TrafficPeak> FindPeaks(int secondsBack, uint64_t thresholdBytes);

private:
  db::Database &m_db;
};

} // namespace analyzer
