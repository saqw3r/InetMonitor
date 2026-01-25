#include <algorithm>
#include <cstdio>
#include <d3d11.h>
#include <functional>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <windows.h>


#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "sqlite3.h"

#include "analyzer/LogCorrelator.h"
#include "db/Database.h"
#include "monitor/AppMonitor.h"
#include "utils/Logger.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd,
                                                             UINT msg,
                                                             WPARAM wParam,
                                                             LPARAM lParam);

static ID3D11Device *g_pDevice = nullptr;
static ID3D11DeviceContext *g_pContext = nullptr;
static IDXGISwapChain *g_pSwapChain = nullptr;
static ID3D11RenderTargetView *g_pRtv = nullptr;
static bool g_uReady = false;

static std::string WToA_Final(const std::wstring &w) {
  if (w.empty())
    return "";
  int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.length(), nullptr,
                               0, nullptr, nullptr);
  if (sz <= 0)
    return "";
  std::string s;
  try {
    s.resize(sz);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.length(), &s[0], sz,
                        nullptr, nullptr);
  } catch (...) {
    return "";
  }
  return s;
}

bool glob_match_core(const char *pat, const char *str) {
  const char *p = pat, *s = str, *cp = nullptr, *cs = nullptr;
  while (*s) {
    if (*p == '*') {
      if (!*++p)
        return true;
      cp = p;
      cs = s + 1;
    } else if (*p == '?' || tolower(*p) == tolower(*s)) {
      p++;
      s++;
    } else if (cp) {
      p = cp;
      s = cs++;
    } else
      return false;
  }
  while (*p == '*')
    p++;
  return !*p;
}

bool CreateD3D(HWND hWnd);
void CleanupD3D();
void CreateRtv();
void CleanupRtv();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

int main(int, char **) {
  LOG("Entering main - MAX SPEED FEATURE");
  try {
    db::Database database;
    if (!database.Open("inet_monitor.db")) {
      LOG("DB Open failed");
      return 1;
    }

    monitor::AppMonitor appMonitor(database);
    if (!appMonitor.Start()) {
      LOG("Monitor failed to start");
    }

    analyzer::LogCorrelator correlator(database);

    WNDCLASSEXW wc = {sizeof(wc),
                      CS_CLASSDC,
                      WndProc,
                      0L,
                      0L,
                      GetModuleHandle(nullptr),
                      nullptr,
                      nullptr,
                      nullptr,
                      nullptr,
                      L"InetMonitor",
                      nullptr};
    if (!::RegisterClassExW(&wc)) {
      if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return 1;
    }

    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Internet Monitor Tool",
                                WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800,
                                nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd)
      return 1;

    if (!CreateD3D(hwnd)) {
      CleanupD3D();
      return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags |=
        ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pDevice, g_pContext);

    g_uReady = true;

    bool done = false;
    static double lastHistUpdate = 0, lastSecUpdate = 0;
    static int unitMode = 1;
    static std::vector<db::AppUsage> cachedUsage;
    static std::vector<analyzer::CorrelatedPeak> analysisResults;

    struct Row {
      uint32_t Pid = 0;
      std::string Proc = "", IP = "", Dom = "", Cnt = "";
      uint64_t SUp = 0, SDown = 0;
      uint64_t MaxUp = 0, MaxDown = 0; // NEW: Peak tracking
      uint64_t TUp = 0, TDown = 0;
    };
    static std::map<std::string, Row> tableData;

    while (!done) {
      MSG msg;
      while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
        ::TranslateMessage(&msg);
        ::DispatchMessage(&msg);
        if (msg.message == WM_QUIT)
          done = true;
      }
      if (done)
        break;

      ImGui_ImplDX11_NewFrame();
      ImGui_ImplWin32_NewFrame();
      ImGui::NewFrame();
      double now = ImGui::GetTime();

      ImGui::SetNextWindowPos(ImVec2(0, 0));
      ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
      ImGui::Begin("Dashboard", nullptr,
                   ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize |
                       ImGuiWindowFlags_NoMove);

      if (ImGui::BeginTabBar("MainTabs")) {
        if (ImGui::BeginTabItem("Monitor")) {
          static float pU = 0, pD = 0, uD[120] = {0}, dD[120] = {0};
          static int off = 0;

          if (now - lastSecUpdate >= 1.0) {
            lastSecUpdate = now;
            float cU = 0, cD = 0;
            try {
              auto snap = appMonitor.GetRawBufferSnapshot();
              for (auto const &s : snap) {
                cU += (float)s.Up;
                cD += (float)s.Down;
                std::string key =
                    std::to_string(s.Pid) + "_" + WToA_Final(s.RemoteIP);
                auto &r = tableData[key];
                r.Pid = s.Pid;
                r.Proc = WToA_Final(s.ProcessName);
                r.IP = WToA_Final(s.RemoteIP);
                r.Dom = WToA_Final(s.Domain);
                r.Cnt = WToA_Final(s.Country);
                r.SUp = s.Up;
                r.SDown = s.Down;

                // Track Maxima
                if (s.Up > r.MaxUp)
                  r.MaxUp = s.Up;
                if (s.Down > r.MaxDown)
                  r.MaxDown = s.Down;

                r.TUp += s.Up;
                r.TDown += s.Down;
              }
            } catch (...) {
            }
            if (cU > pU)
              pU = cU;
            if (cD > pD)
              pD = cD;
            uD[off] = cU;
            dD[off] = cD;
            off = (off + 1) % 120;
          }

          float div =
              (unitMode == 0) ? 1048576.0f : (unitMode == 1 ? 1024.0f : 1.0f);
          const char *us =
              (unitMode == 0) ? "MB" : (unitMode == 1 ? "KB" : "B");
          ImGui::RadioButton("MB/s", &unitMode, 0);
          ImGui::SameLine();
          ImGui::RadioButton("KB/s", &unitMode, 1);
          ImGui::SameLine();
          ImGui::RadioButton("B/s", &unitMode, 2);

          ImGui::Text("Up: %.1f %s/s (Peak: %.1f)", uD[(off + 119) % 120] / div,
                      us, pU / div);
          ImGui::PlotLines("##U", uD, 120, off, nullptr, 0, pU * 1.1f + 1.0f,
                           ImVec2(-1, 60));
          ImGui::Text("Dn: %.1f %s/s (Peak: %.1f)", dD[(off + 119) % 120] / div,
                      us, pD / div);
          ImGui::PlotLines("##D", dD, 120, off, nullptr, 0, pD * 1.1f + 1.0f,
                           ImVec2(-1, 60));

          static char flt[128] = "";
          ImGui::InputText("Filter", flt, 128);

          // 11 columns: PID, Proc, IP, Dom, Cnt, SUp, SDown, MaxUp, MaxDown,
          // TUp, TDown
          if (ImGui::BeginTable(
                  "MonTable", 11,
                  ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                      ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                  ImVec2(0, 300))) {
            ImGui::TableSetupColumn("PID", 0, 50.0f);
            ImGui::TableSetupColumn("Process", 0, 150.0f);
            ImGui::TableSetupColumn("IP", 0, 110.0f);
            ImGui::TableSetupColumn("Domain", 0, 150.0f);
            ImGui::TableSetupColumn("Cnt", 0, 40.0f);
            ImGui::TableSetupColumn("Up", 0, 75.0f);
            ImGui::TableSetupColumn("Dn", 0, 75.0f);
            ImGui::TableSetupColumn("Max Up", 0, 75.0f);
            ImGui::TableSetupColumn("Max Dn", 0, 75.0f);
            ImGui::TableSetupColumn("Total Up", 0, 80.0f);
            ImGui::TableSetupColumn("Total Dn", 0, 80.0f);
            ImGui::TableHeadersRow();
            for (auto &rowPair : tableData) {
              auto &r = rowPair.second;
              if (flt[0] != '\0' &&
                  !glob_match_core(flt,
                                   (r.Proc + " " + r.IP + " " + r.Dom).c_str()))
                continue;
              ImGui::TableNextRow();
              ImGui::TableSetColumnIndex(0);
              ImGui::Text("%u", r.Pid);
              ImGui::TableSetColumnIndex(1);
              ImGui::Text("%s", r.Proc.c_str());
              ImGui::TableSetColumnIndex(2);
              ImGui::Text("%s", r.IP.c_str());
              ImGui::TableSetColumnIndex(3);
              ImGui::Text("%s", r.Dom.c_str());
              ImGui::TableSetColumnIndex(4);
              ImGui::Text("%s", r.Cnt.c_str());
              ImGui::TableSetColumnIndex(5);
              ImGui::Text("%.1f", (float)r.SUp / div);
              ImGui::TableSetColumnIndex(6);
              ImGui::Text("%.1f", (float)r.SDown / div);
              ImGui::TableSetColumnIndex(7);
              ImGui::Text("%.1f", (float)r.MaxUp / div);
              ImGui::TableSetColumnIndex(8);
              ImGui::Text("%.1f", (float)r.MaxDown / div);
              ImGui::TableSetColumnIndex(9);
              ImGui::Text("%.1f", (float)r.TUp / div);
              ImGui::TableSetColumnIndex(10);
              ImGui::Text("%.1f", (float)r.TDown / div);
              r.SUp = r.SDown = 0;
            }
            ImGui::EndTable();
          }
          if (ImGui::Button("Reset View Stats"))
            tableData.clear();
          ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("History")) {
          if (now - lastHistUpdate >= 5.0) {
            lastHistUpdate = now;
            try {
              cachedUsage = database.GetUsage(3600);
            } catch (...) {
            }
          }
          if (ImGui::BeginTable("Hist", 3,
                                ImGuiTableFlags_Borders |
                                    ImGuiTableFlags_RowBg |
                                    ImGuiTableFlags_SizingFixedFit)) {
            ImGui::TableSetupColumn("Application", 0, 400.0f);
            ImGui::TableSetupColumn("Up (MB)", 0, 100.0f);
            ImGui::TableSetupColumn("Dn (MB)", 0, 100.0f);
            ImGui::TableHeadersRow();
            for (auto const &item : cachedUsage) {
              ImGui::TableNextRow();
              ImGui::TableSetColumnIndex(0);
              ImGui::Text("%s", WToA_Final(item.AppName).c_str());
              ImGui::TableSetColumnIndex(1);
              ImGui::Text("%.1f", item.TotalBytesUp / 1048576.0f);
              ImGui::TableSetColumnIndex(2);
              ImGui::Text("%.1f", item.TotalBytesDown / 1048576.0f);
            }
            ImGui::EndTable();
          }
          static char csv[128] = "traffic_export.csv";
          ImGui::InputText("CSV File", csv, 128);
          ImGui::SameLine();
          if (ImGui::Button("Export (1hr)")) {
            database.ExportToCSV(csv, 3600);
          }
          ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Analyze")) {
          if (ImGui::Button("Run Analysis")) {
            analysisResults = correlator.Correlate(3600, 1024 * 1024);
          }
          if (analysisResults.empty()) {
            ImGui::Text("No significant peaks found.");
          }
          for (auto const &res : analysisResults) {
            std::string header = WToA_Final(res.AppName) + " | Peak: " +
                                 std::to_string(res.Peak.TotalBytes / 1024) +
                                 " KB";
            if (ImGui::CollapsingHeader(header.c_str())) {
              ImGui::TextWrapped("Summary: %s",
                                 WToA_Final(res.Conclusion.Summary).c_str());
              ImGui::TextWrapped("Detail: %s",
                                 WToA_Final(res.Conclusion.Detail).c_str());
              ImGui::Separator();
              ImGui::Text("Log Context:");
              for (auto const &evt : res.RelatedEvents) {
                ImGui::TextDisabled("[%llu] %s (ID %u): %s", evt.Timestamp,
                                    WToA_Final(evt.ProviderName).c_str(),
                                    evt.EventId,
                                    WToA_Final(evt.Message).c_str());
              }
            }
          }
          ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Debug")) {
          ImGui::Text("Events Captured: %llu",
                      appMonitor.GetTotalEventsCount());
          ImGui::Text("Valid Data Pkts: %llu",
                      appMonitor.GetParsedEventsCount());
          ImGui::Text("DNS Cache Size: %llu", appMonitor.GetDnsEventsCount());

          std::wstring pErr = appMonitor.GetLastParsingError();
          if (!pErr.empty())
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "Last System Error: %s",
                               WToA_Final(pErr).c_str());

          ImGui::Separator();
          ImGui::Text("Event Freq (Crucial):");
          if (ImGui::BeginTable("DebugF", 2,
                                ImGuiTableFlags_Borders |
                                    ImGuiTableFlags_RowBg |
                                    ImGuiTableFlags_SizingFixedFit)) {
            ImGui::TableSetupColumn("Identifier", 0, 300.0f);
            ImGui::TableSetupColumn("Count", 0, 100.0f);
            ImGui::TableHeadersRow();
            auto counts = appMonitor.GetEventCounts();
            for (auto const &c : counts) {
              ImGui::TableNextRow();
              ImGui::TableSetColumnIndex(0);
              ImGui::Text("%s", c.first.c_str());
              ImGui::TableSetColumnIndex(1);
              ImGui::Text("%llu", c.second);
            }
            ImGui::EndTable();
          }
          ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
      }
      ImGui::End();

      ImGui::Render();
      const float clear_color[4] = {0.1f, 0.1f, 0.1f, 1.0f};
      g_pContext->OMSetRenderTargets(1, &g_pRtv, nullptr);
      g_pContext->ClearRenderTargetView(g_pRtv, clear_color);
      ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
      g_pSwapChain->Present(1, 0);
    }

    appMonitor.Stop();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
  } catch (const std::exception &e) {
    LOG("FATAL: " + std::string(e.what()));
    MessageBoxA(nullptr, e.what(), "Error", MB_ICONERROR);
  } catch (...) {
    MessageBoxA(nullptr, "Panic", "Error", MB_ICONERROR);
  }
  return 0;
}

bool CreateD3D(HWND hWnd) {
  DXGI_SWAP_CHAIN_DESC sd;
  ZeroMemory(&sd, sizeof(sd));
  sd.BufferCount = 2;
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = hWnd;
  sd.SampleDesc.Count = 1;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
  UINT fl = 0;
  D3D_FEATURE_LEVEL lvl;
  const D3D_FEATURE_LEVEL lvls[2] = {D3D_FEATURE_LEVEL_11_0,
                                     D3D_FEATURE_LEVEL_10_0};
  HRESULT res = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, fl, lvls, 2,
      D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pDevice, &lvl, &g_pContext);
  if (res != S_OK)
    res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_WARP, nullptr, fl, lvls, 2, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pDevice, &lvl, &g_pContext);
  if (res != S_OK)
    return false;
  CreateRtv();
  return true;
}
void CleanupD3D() {
  CleanupRtv();
  if (g_pSwapChain)
    g_pSwapChain->Release();
  if (g_pContext)
    g_pContext->Release();
  if (g_pDevice)
    g_pDevice->Release();
}
void CreateRtv() {
  ID3D11Texture2D *pB = nullptr;
  g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pB));
  if (pB) {
    g_pDevice->CreateRenderTargetView(pB, nullptr, &g_pRtv);
    pB->Release();
  }
}
void CleanupRtv() {
  if (g_pRtv) {
    g_pRtv->Release();
    g_pRtv = nullptr;
  }
}

LRESULT WINAPI WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  if (g_uReady && ImGui_ImplWin32_WndProcHandler(h, m, w, l))
    return true;
  switch (m) {
  case WM_SIZE:
    if (g_pDevice && w != SIZE_MINIMIZED) {
      CleanupRtv();
      g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(l), (UINT)HIWORD(l),
                                  DXGI_FORMAT_UNKNOWN, 0);
      CreateRtv();
    }
    return 0;
  case WM_SYSCOMMAND:
    if ((w & 0xfff0) == SC_KEYMENU)
      return 0;
    break;
  case WM_DESTROY:
    ::PostQuitMessage(0);
    return 0;
  }
  return ::DefWindowProcW(h, m, w, l);
}
