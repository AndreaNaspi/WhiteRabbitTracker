#pragma once
#include <map>
#include "pin.H"
#include "state.h"
#include "LoggingInfo.h"
#include "wmi.h"

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
	void Init(LoggingInfo* logInfoParameter);
	/* ===================================================================== */
	/* Function to iterate over APIs that we want to hook/replace            */
	/* ===================================================================== */
	void AddHooks(IMG img);
};

/* ===================================================================== */
/* API HOOKS (taint sources)                                             */
/* ===================================================================== */
VOID IsDebuggerPresentExit(CONTEXT* ctx, ADDRINT* ret, ADDRINT esp);
VOID BlockInputExit(CONTEXT* ctx, ADDRINT* ret, ADDRINT esp);
VOID CheckRemoteDebuggerPresentEntry(ADDRINT* pbDebuggerPresent);
VOID CheckRemoteDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp);
VOID EnumProcessesEntry(ADDRINT* pointerToProcessesArray, ADDRINT* pointerToBytesProcessesArray);
VOID EnumProcessesExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp);
VOID Process32FirstNextEntry(ADDRINT hSnapshot, ADDRINT pointerToProcessInformations);
VOID Process32FirstNextExit(CONTEXT* ctx, ADDRINT esp);
VOID Process32FirstNextWEntry(ADDRINT hSnapshot, ADDRINT pointerToProcessInformations);
VOID Process32FirstNextWExit(CONTEXT* ctx, ADDRINT esp);
VOID GetDiskFreeSpaceAEntry(ADDRINT retAddr, ADDRINT* pointerToLpFreeBytesAvailableToCaller, ADDRINT* pointerToLpTotalNumberOfBytes, ADDRINT* pointerToLpTotalNumberOfFreeBytes);
VOID GetDiskFreeSpaceAExit(CONTEXT* ctx, ADDRINT esp);
VOID GetDiskFreeSpaceWEntry(ADDRINT retAddr, ADDRINT* pointerToLpFreeBytesAvailableToCaller, ADDRINT* pointerToLpTotalNumberOfBytes, ADDRINT* pointerToLpTotalNumberOfFreeBytes);
VOID GetDiskFreeSpaceWExit(CONTEXT* ctx, ADDRINT esp);
VOID GlobalMemoryStatusEntry(ADDRINT* pointerToLpBuffer);
VOID GlobalMemoryStatusExit(CONTEXT* ctx, ADDRINT esp);
VOID GetSystemInfoEntry(ADDRINT* pointerToLpSystemInfo);
VOID GetSystemInfoExit(CONTEXT* ctx, ADDRINT esp);
VOID GetTickCountExit(CONTEXT* ctx, W::DWORD* ret, ADDRINT esp);
VOID GetCursorPosEntry(ADDRINT* pointerToLpPoint);
VOID GetCursorPosExit(CONTEXT* ctx, ADDRINT esp);
VOID GetModuleFileNameHookEntry(W::LPTSTR* moduleName, W::DWORD* nSize);
VOID GetModuleFileNameHookExit(CONTEXT* ctx, ADDRINT esp);
VOID GetDeviceDriverBaseNameHookEntry(W::LPTSTR* lpBaseName, W::DWORD* nSize);
VOID GetDeviceDriverBaseNameHookExit(CONTEXT* ctx, ADDRINT esp);
VOID GetAdaptersInfoEntry(PIP_ADAPTER_INFO* adapInfo, W::PULONG* size);
VOID GetAdaptersInfoExit(CONTEXT* ctx, ADDRINT ret, ADDRINT esp);
VOID EnumDisplaySettingsEntry(W::LPCTSTR* devName, CONTEXT* ctx);
VOID SetupDiGetDeviceRegistryPropertyHookEntry(W::PBYTE* buffer);
VOID SetupDiGetDeviceRegistryPropertyHookExit(ADDRINT ret);
VOID SetTimerEntry(W::UINT* time);
VOID WaitForSingleObjectEntry(W::DWORD *time);
VOID IcmpSendEchoEntry(ADDRINT* replyBuffer, ADDRINT* replySize, W::DWORD *time);
VOID IcmpSendEchoExit(CONTEXT* ctx, ADDRINT esp);
VOID LoadLibraryAHook(const char** lib);
VOID LoadLibraryWHook(const wchar_t** lib);
VOID LoadLibraryExit(CONTEXT* ctx, ADDRINT esp);
VOID GetUsernameEntry(W::LPTSTR* lpBuffer, W::LPDWORD* nSize);
VOID GetUsernameExit(CONTEXT* ctx, ADDRINT esp);
VOID FindWindowHookEntry(W::LPCTSTR* path1, W::LPCTSTR* path2);
VOID FindWindowHookExit(CONTEXT* ctx, W::BOOL* ret, ADDRINT esp);
VOID CloseHandleHookEntry(W::HANDLE* handle);
VOID CloseHandleHookExit(W::BOOL* ret, ADDRINT esp);
VOID WMIQueryHookEntry(W::LPCWSTR* query, W::VARIANT** var);
VOID WMIQueryHookExit();

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
#define MAX_POSSIBLE_SIZE_MAC       50
#define PATH_BUFSIZE                512
#define BP_NUMCORES		            4
#define BP_MINDISKGB                1073741824000 // 1000 GB
#define BP_MINRAMGB                 4294967296 // 4 GB
#define BP_TIMER                    150 // milliseconds
#define BP_ICMP_ECHO	            200 // milliseconds
#define BP_FAKEPROCESS              "abc.exe"
#define BP_FAKEPROCESSW             L"abc.exe"
#define BP_MUTEX                    "suppli"	
#define BP_FAKEDRV		            "vga.sys"
#define BP_FAKEDRV_W	            L"vga.sys"
#define BP_FAKEDLL		            "sup.dll"
#define BP_FAKEDLL_W	            L"sup.dll"
#define BP_FAKEUSERNAME	            "sup"
#define BP_FAKEUSERNAME_W	        L"sup"
#define STR_GUI_1A	                "W" 
#define STR_GUI_1B	                "a"
#define STR_GUI_2	                "WantSuppli"
#define STR_GUI_2B	                "s"
#define CHAR_EDS	                'd'
#define CHAR_SDI                	's'



/* ===================================================================== */
/* Function hooking identifiers                                          */
/* ===================================================================== */
enum {
	ISDEBUGGERPRESENT_INDEX,
	BLOCKINPUT_INDEX,
	CHECKREMOTEDEBUGGERPRESENT_INDEX,
	ENUMPROCESSES_INDEX,
	PROCESS32FIRSTNEXT_INDEX,
	PROCESS32FIRSTNEXTW_INDEX,
	REGOPENKEYA_INDEX,
	REGOPENKEYW_INDEX,
	GETDISKSPACEA_INDEX,
	GETDISKSPACEW_INDEX,
	GLOBALMEMORYSTATUS_INDEX,
	GETSYSTEMINFO_INDEX,
	GETCURSORPOS_INDEX = 32, 
	GETMODULE_INDEX,
	DEVICEBASE_INDEX,
	GETADAPTER_INDEX,
	ENUMDIS_INDEX,
	SETUPDEV_INDEX,
	GETTICKCOUNT_INDEX,
	SETTIMER_INDEX,
	WAITOBJ_INDEX,
	ICMPECHO_INDEX,
	LOADLIBA_INDEX,
	LOADLIBW_INDEX,
	GETUSERNAME_INDEX,
	FINDWINDOW_INDEX,
	CLOSEH_INDEX,
	WMI_INDEX
};