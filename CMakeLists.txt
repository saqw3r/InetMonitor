cmake_minimum_required(VERSION 3.20)

project(InetMonitor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Dependencies ---
include(FetchContent)

# 1. Dear ImGui
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui
    GIT_TAG        docking # Use docking branch for multi-viewport support
)
FetchContent_GetProperties(imgui)
if(NOT imgui_POPULATED)
    FetchContent_Populate(imgui)
endif()

# Create the imgui library manually
add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
)
target_include_directories(imgui PUBLIC ${imgui_SOURCE_DIR})

# 2. SQLite3
# Using a CMake-friendly mirror of the SQLite amalgamation
FetchContent_Declare(
    sqlite3
    GIT_REPOSITORY https://github.com/azadkuh/sqlite-amalgamation
    GIT_TAG        master
)
FetchContent_MakeAvailable(sqlite3)

# --- Source Files ---
file(GLOB_RECURSE SOURCES 
    "src/*.cpp" 
    "src/*.h"
)

# --- Executable ---
add_executable(${PROJECT_NAME} ${SOURCES})

# --- Include Directories ---
target_include_directories(${PROJECT_NAME} PRIVATE
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
    ${sqlite3_SOURCE_DIR}
    src
)

# --- ImGui Backends (DX11 + Win32) ---
# We need to manually add the implementation files as ImGui doesn't built them by default
target_sources(${PROJECT_NAME} PRIVATE
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
)

# --- Linking ---
target_link_libraries(${PROJECT_NAME} PRIVATE
    imgui
    SQLite3
    d3d11
    d3dcompiler
    dwmapi
    tdh        # For ETW
    ws2_32     # For Winsock
    wevtapi    # For Event Log
    winhttp    # For GeoIP API
    rpcrt4     # For UuidToStringW
)

# --- Definitions ---
target_compile_definitions(${PROJECT_NAME} PRIVATE 
    UNICODE _UNICODE 
    _WIN32_WINNT=0x0A00 
)

# Copy assets if needed (placeholder)
