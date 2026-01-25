#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#undef WIN32_LEAN_AND_MEAN

#include <objbase.h>
#include <rpcdce.h>
#include <windows.h>

// SAL macros workaround if they are missing
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _Inout_opt_
#define _Inout_opt_
#endif

// GUID types workaround
#ifndef LPCGUID
typedef const GUID *LPCGUID;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#include <evntcons.h>
#include <evntprov.h>
#include <evntrace.h>
#include <tdh.h>
