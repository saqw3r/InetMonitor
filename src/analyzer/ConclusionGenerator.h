#pragma once

#include "EventLogReader.h"
#include <string>
#include <vector>

namespace analyzer {

struct AnalysisConclusion {
  std::wstring Summary;
  std::wstring Detail;
  float Confidence = 0.0f; // 0.0 to 1.0
};

class ConclusionGenerator {
public:
  ConclusionGenerator();

  // Analyzes a set of events and returns a conclusion
  AnalysisConclusion Generate(const std::vector<LogEntry> &events,
                              const std::wstring &appName);

private:
  // Heuristic rules
  bool IsWindowsUpdate(const std::vector<LogEntry> &events);
  bool IsSteamDownload(const std::wstring &appName);
  bool IsWebBrowser(const std::wstring &appName);
};

} // namespace analyzer
