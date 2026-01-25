#include "ConclusionGenerator.h"
#include <algorithm>

namespace analyzer {

ConclusionGenerator::ConclusionGenerator() = default;

AnalysisConclusion
ConclusionGenerator::Generate(const std::vector<LogEntry> &events,
                              const std::wstring &appName) {
  AnalysisConclusion conclusion;
  conclusion.Summary = L"Unknown Traffic Cause";
  conclusion.Detail =
      L"No specific triggers could be identified for this peak.";
  conclusion.Confidence = 0.1f;

  std::wstring loweredApp = appName;
  std::transform(loweredApp.begin(), loweredApp.end(), loweredApp.begin(),
                 ::towlower);

  if (IsWindowsUpdate(events)) {
    conclusion.Summary = L"Windows Update";
    conclusion.Detail = L"Detected activity from Windows Update Client in "
                        L"system logs concurrent with this traffic peak.";
    conclusion.Confidence = 0.9f;
  } else if (IsSteamDownload(loweredApp)) {
    conclusion.Summary = L"Steam Game Download/Update";
    conclusion.Detail = L"Identified Steam (steam.exe or steamwebhelper.exe) "
                        L"as the primary consumer during this peak.";
    conclusion.Confidence = 0.85f;
  } else if (IsWebBrowser(loweredApp)) {
    conclusion.Summary = L"Web Browsing / Streaming";
    conclusion.Detail = L"Identified a major web browser as the consumer. "
                        L"Likely video streaming or a large download.";
    conclusion.Confidence = 0.7f;
  } else if (loweredApp.find(L"system") != std::wstring::npos) {
    conclusion.Summary = L"System Process Activity";
    conclusion.Detail = L"System-level processes were active. Could be "
                        L"background synchronization or telemetry.";
    conclusion.Confidence = 0.5f;
  }

  return conclusion;
}

bool ConclusionGenerator::IsWindowsUpdate(const std::vector<LogEntry> &events) {
  for (const auto &ev : events) {
    if (ev.ProviderName.find(L"WindowsUpdateClient") != std::wstring::npos ||
        ev.ProviderName.find(L"UpdateOrchestrator") != std::wstring::npos) {
      return true;
    }
  }
  return false;
}

bool ConclusionGenerator::IsSteamDownload(const std::wstring &appName) {
  return appName.find(L"steam.exe") != std::wstring::npos ||
         appName.find(L"steamwebhelper.exe") != std::wstring::npos;
}

bool ConclusionGenerator::IsWebBrowser(const std::wstring &appName) {
  return appName.find(L"chrome.exe") != std::wstring::npos ||
         appName.find(L"msedge.exe") != std::wstring::npos ||
         appName.find(L"firefox.exe") != std::wstring::npos ||
         appName.find(L"brave.exe") != std::wstring::npos;
}

} // namespace analyzer
