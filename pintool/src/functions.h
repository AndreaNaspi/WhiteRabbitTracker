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
	#include <debugapi.h> 
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
#include <debugapi.h> 
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
VOID IsDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp);
VOID CheckRemoteDebuggerPresentEntry(ADDRINT* pbDebuggerPresent);
VOID CheckRemoteDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp);
VOID EnumProcessesEntry(ADDRINT* pointerToProcessesArray, ADDRINT* pointerToBytesProcessesArray);
VOID EnumProcessesExit(ADDRINT eax, ADDRINT esp);
VOID Process32FirstNextEntry(ADDRINT hSnapshot, ADDRINT pointerToProcessInformations);
VOID Process32FirstNextExit(CONTEXT* ctx, ADDRINT esp);
VOID Process32FirstNextWExit(CONTEXT* ctx, ADDRINT esp);
VOID GetDiskFreeSpaceEntry(ADDRINT* pointerToLpFreeBytesAvailableToCaller, ADDRINT* pointerToLpTotalNumberOfBytes, ADDRINT* pointerToLpTotalNumberOfFreeBytes);
VOID GetDiskFreeSpaceExit(CONTEXT* ctx, ADDRINT esp);
VOID GlobalMemoryStatusEntry(ADDRINT* pointerToLpBuffer);
VOID GlobalMemoryStatusExit(CONTEXT* ctx, ADDRINT esp);
VOID GetSystemInfoEntry(ADDRINT* pointerToLpSystemInfo);
VOID GetSystemInfoExit(CONTEXT* ctx, ADDRINT esp);
VOID GetTickCountExit(CONTEXT* ctx, W::DWORD* ret, ADDRINT esp);
VOID GetCursorPosEntry(ADDRINT* pointerToLpPoint);
VOID GetCursorPosExit(CONTEXT* ctx, ADDRINT esp);
VOID SetTimerEntry(W::UINT* time);
VOID SetTimerExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp);
VOID WaitForSingleObjectEntry(W::DWORD *time);
VOID WaitForSingleObjectExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp);
VOID IcmpSendEchoEntry(ADDRINT* replyBuffer, ADDRINT* replySize, W::DWORD *time);
VOID IcmpSendEchoExit(CONTEXT* ctx, ADDRINT esp);

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
#define BP_NUMCORES		            4
#define BP_MINDISKGB                1073741824000 // 1000 GB
#define BP_MINRAMGB                 4294967296 // 4 GB
#define BP_TIMER                    150 // milliseconds
#define BP_ICMP_ECHO	            200 // milliseconds

/* ===================================================================== */
/* Function hooking identifiers                                          */
/* ===================================================================== */
enum {
	ISDEBUGGERPRESENT_INDEX,
	CHECKREMOTEDEBUGGERPRESENT_INDEX,
	ENUMPROCESSES_INDEX,
	PROCESS32FIRSTNEXT_INDEX,
	PROCESS32FIRSTNEXTW_INDEX,
	GETDISKFREESPACE_INDEX,
	GLOBALMEMORYSTATUS_INDEX,
	GETSYSTEMINFO_INDEX,
	GETCURSORPOS_INDEX, 
	GETTICKCOUNT_INDEX,
	SETTIMER_INDEX,
	WAITOBJ_INDEX,
	ICMPECHO_INDEX
};