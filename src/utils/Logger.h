#pragma once

#include <fstream>
#include <mutex>
#include <string>
#include <windows.h>


namespace utils {

class Logger {
public:
  static Logger &GetInstance() {
    static Logger instance;
    return instance;
  }

  void Log(const std::string &message) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string formatted = "[" + GetTimestamp() + "] " + message + "\n";

    // Output to file
    if (m_file.is_open()) {
      m_file << formatted;
      m_file.flush();
    }

    // Output to Debugger
    OutputDebugStringA(formatted.c_str());
  }

private:
  Logger() {
    m_file.open("app_log.txt", std::ios::out | std::ios::app);
    Log("--- Session Started ---");
  }

  ~Logger() {
    Log("--- Session Ended ---");
    if (m_file.is_open()) {
      m_file.close();
    }
  }

  std::string GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[64];
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth,
              st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
  }

  std::ofstream m_file;
  std::mutex m_mutex;
};

#define LOG(msg) utils::Logger::GetInstance().Log(msg)

} // namespace utils
