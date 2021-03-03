#pragma once
#include <map>
#include "pin.H"
#include "state.h"

namespace W {
	#define WIN32_LEAN_AND_MEAN
	#include <Windows.h>
	#include <WinUser.h>
	#include <Ws2tcpip.h>
	#include <tlhelp32.h>
}

// libdft
#include "libdft/libdft_config.h"
#include "libdft/bridge.h"
#include "libdft/libdft_api.h"
#include "libdft/tagmap.h"

namespace W {
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinUser.h>
#include <Ws2tcpip.h>
#include <tlhelp32.h>
}

namespace Functions {
	/* ===================================================================== */
	/* Initialization function to define hook/API map and define taint hooks */
	/* ===================================================================== */
	void Init();
	/* ===================================================================== */
	/* Function to iterate over APIs that we want to hook/replace            */
	/* ===================================================================== */
	void AddHooks(IMG img);
};

/* ===================================================================== */
/* API HOOKS (taint sources)                                             */
/* ===================================================================== */
VOID IsDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax);
VOID CheckRemoteDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax);
VOID EnumProcessesEntry(ADDRINT* pointerToProcessesArray, ADDRINT* pointerToBytesProcessesArray);
VOID EnumProcessesExit(ADDRINT eax);
VOID Process32FirstNextEntry(ADDRINT* processInformations);
VOID GetDiskFreeSpaceEntry(ADDRINT* pointerToLpFreeBytesAvailableToCaller, ADDRINT* pointerToLpTotalNumberOfBytes, ADDRINT* pointerToLpTotalNumberOfFreeBytes);
VOID GlobalMemoryStatusEntry(ADDRINT* pointerToLpBuffer);
VOID GetSystemInfoEntry(ADDRINT* pointerToLpSystemInfo);
VOID GetTickCountExit(CONTEXT* ctx, ADDRINT eax);
VOID GetCursorPosEntry(ADDRINT* pointerToLpPoint);

/* ===================================================================== */
/* INSTRUCTION HOOKS (taint sinks)                                       */
/* ===================================================================== */
// ACTUALLY DEFINED FOR EACH INSTRUCTION IN LIBDFT_API
// static void dta_instrument_jmp_call(INS ins);

/* ===================================================================== */
/* Define max number of hooks and other parameters                       */
/* ===================================================================== */
#define MAX_HOOK_FUNCTIONS_INDEX	128
#define MAX_MAC_ADDRESS_SIZE		50
#define MAX_GETPROCADDR_ORDINAL		0x200

/* ===================================================================== */
/* Function hooking identifiers                                          */
/* ===================================================================== */
enum {
	ISDEBUGGERPRESENT_INDEX,
	CHECKREMOTEDEBUGGERPRESENT_INDEX,
	ENUMPROCESSES_INDEX,
	PROCESS32FIRSTNEXT_INDEX,
	GETDISKFREESPACE_INDEX,
	GLOBALMEMORYSTATUS_INDEX,
	GETSYSTEMINFO_INDEX,
	GETTICKCOUNT_INDEX,
	GETUSERNAME_INDEX,
	GETCURSORPOS_INDEX
};