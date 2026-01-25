
#define _WIN32_WINNT 0x0A00
#include <objbase.h>
#include <windows.h>


#ifndef NTAPI
#define NTAPI __stdcall
#endif

#ifndef LPCGUID
typedef const GUID *LPCGUID;
#endif

#include <evntprov.h>
#include <evntrace.h>

void test_main() {}
