#pragma once
#include "functions.h"
#include "types.h"
#include "process.h"
#include "helper.h"
#include "HiddenElements.h"
#include "LoggingInfo.h"
#include "taint.h"
#include <string>
#include <iostream>

/* ============================================================================= */
/* Define macro to check the return address in ESP and check if is program code  */
/* ============================================================================= */
#define CHECK_ESP_RETURN_ADDRESS(esp_pointer) do { \
ADDRINT espValue = *((ADDRINT*) esp_pointer); \
State::globalState* gs = State::getGlobalState(); \
itreenode_t* node = itree_search(gs->dllRangeITree, espValue); \
if(node != NULL) return; \
} while (0)

/* =========================================================================== */
/* Instruction description for instruction tainting and modules inizialization */
/* =========================================================================== */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];
LoggingInfo* logInfo;

namespace Functions {
	/* ===================================================================== */
	/* Hook/API map and other modules (internal use)                         */
	/* ===================================================================== */
	static std::map<std::string, int> fMap;

	/* ===================================================================== */
	/* Initialization function to define API map                             */
	/* ===================================================================== */
	void Init(LoggingInfo* logInfoParameter) {
		// Setup modules
		logInfo = logInfoParameter;
		// Debugger API hooks
		fMap.insert(std::pair<std::string, int>("IsDebuggerPresent", ISDEBUGGERPRESENT_INDEX));
		fMap.insert(std::pair<std::string, int>("CheckRemoteDebuggerPresent", CHECKREMOTEDEBUGGERPRESENT_INDEX));
		// Processes API hooks
		fMap.insert(std::pair<std::string, int>("EnumProcesses", ENUMPROCESSES_INDEX));
		fMap.insert(std::pair<std::string, int>("K32EnumProcesses", ENUMPROCESSES_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32First", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32Next", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32FirstW", PROCESS32FIRSTNEXTW_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32NextW", PROCESS32FIRSTNEXTW_INDEX));
		// Hardware API hooks (disk/memory information, CPU tick count, mouse cursor position)
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceEx", GETDISKSPACEW_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceExW", GETDISKSPACEW_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceExA", GETDISKSPACEA_INDEX));
		fMap.insert(std::pair<std::string, int>("GlobalMemoryStatusEx", GLOBALMEMORYSTATUS_INDEX));
		fMap.insert(std::pair<std::string, int>("GetSystemInfo", GETSYSTEMINFO_INDEX));
		fMap.insert(std::pair<std::string, int>("GetCursorPos", GETCURSORPOS_INDEX));
		fMap.insert(std::pair<std::string, int>("GetModuleFileName", GETMODULE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetModuleFileNameA", GETMODULE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetModuleFileNameW", GETMODULE_INDEX));
		fMap.insert(std::pair<std::string, int>("K32GetDeviceDriverBaseName", DEVICEBASE_INDEX));
		fMap.insert(std::pair<std::string, int>("K32GetDeviceDriverBaseNameA", DEVICEBASE_INDEX));
		fMap.insert(std::pair<std::string, int>("K32GetDeviceDriverBaseNameW", DEVICEBASE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetAdaptersInfo", GETADAPTER_INDEX));
		fMap.insert(std::pair<std::string, int>("EnumDisplaySettings", ENUMDIS_INDEX));
		fMap.insert(std::pair<std::string, int>("EnumDisplaySettingsA", ENUMDIS_INDEX));
		fMap.insert(std::pair<std::string, int>("EnumDisplaySettingsW", ENUMDIS_INDEX));
		// Time API hooks
		fMap.insert(std::pair<std::string, int>("GetTickCount", GETTICKCOUNT_INDEX));
		fMap.insert(std::pair<std::string, int>("SetTimer", SETTIMER_INDEX));
		fMap.insert(std::pair<std::string, int>("WaitForSingleObject", WAITOBJ_INDEX));
		fMap.insert(std::pair<std::string, int>("IcmpSendEcho", ICMPECHO_INDEX));
		// Other hooks
		fMap.insert(std::pair<std::string, int>("LoadLibraryA", LOADLIBA_INDEX));
		fMap.insert(std::pair<std::string, int>("LoadLibraryW", LOADLIBW_INDEX));
		fMap.insert(std::pair<std::string, int>("LoadLibraryExA", LOADLIBA_INDEX));
		fMap.insert(std::pair<std::string, int>("LoadLibraryExW", LOADLIBW_INDEX));
		fMap.insert(std::pair<std::string, int>("GetUserNameA", GETUSERNAME_INDEX));
		fMap.insert(std::pair<std::string, int>("GetUserNameW", GETUSERNAME_INDEX));
		fMap.insert(std::pair<std::string, int>("FindWindow", FINDWINDOW_INDEX));
		fMap.insert(std::pair<std::string, int>("FindWindowW", FINDWINDOW_INDEX));
		fMap.insert(std::pair<std::string, int>("FindWindowA", FINDWINDOW_INDEX));
		fMap.insert(std::pair<std::string, int>("NtClose", CLOSEH_INDEX)); 

	}


	// Scan the image and try to hook any found function specified in the API map
	void AddHooks(IMG img) {
		// Iterate over functions that we want to hook/replace
		for (std::map<std::string, int>::iterator it = fMap.begin(), end = fMap.end(); it != end; ++it) {
			// Get the function name 
			const char* func_name = it->first.c_str();
			// Get a pointer to the function
			RTN rtn = RTN_FindByName(img, func_name);
			// Check if the routine (function) is valid
			if (rtn != RTN_Invalid()) {
				int index = it->second;
				// Open the routine
				RTN_Open(rtn);

				// Switch-case over possible APIs described in the API map
				switch (index) {
					case(ISDEBUGGERPRESENT_INDEX):
						// Add hooking with IPOINT_AFTER to taint the EAX register on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)IsDebuggerPresentExit,
							IARG_CONTEXT,
							IARG_FUNCRET_EXITPOINT_REFERENCE,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(CHECKREMOTEDEBUGGERPRESENT_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve pbDebuggerPresent)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CheckRemoteDebuggerPresentEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the nemory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CheckRemoteDebuggerPresentExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_EAX,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(ENUMPROCESSES_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve process array and returned bytes)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)EnumProcessesEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the stored values
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)EnumProcessesExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_EAX,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(PROCESS32FIRSTNEXT_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve process informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Process32FirstNextEntry,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)Process32FirstNextExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(PROCESS32FIRSTNEXTW_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve process informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Process32FirstNextWEntry,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)Process32FirstNextWExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(GETDISKSPACEA_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve disk informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetDiskFreeSpaceAEntry,
							IARG_RETURN_IP,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetDiskFreeSpaceAExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(GETDISKSPACEW_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve disk informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetDiskFreeSpaceWEntry,
							IARG_RETURN_IP,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetDiskFreeSpaceWExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(GLOBALMEMORYSTATUS_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve memory informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GlobalMemoryStatusEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GlobalMemoryStatusExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(GETSYSTEMINFO_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve system informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetSystemInfoEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetSystemInfoExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(GETCURSORPOS_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve pointer informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetCursorPosEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetCursorPosExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(GETMODULE_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve module informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetModuleFileNameHookEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetModuleFileNameHookExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(DEVICEBASE_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve driver informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetDeviceDriverBaseNameHookEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetDeviceDriverBaseNameHookExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(GETADAPTER_INDEX):
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve adapter informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetAdaptersInfoEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetAdaptersInfoExit,
							IARG_CONTEXT,
							IARG_FUNCRET_EXITPOINT_VALUE,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(ENUMDIS_INDEX):
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)EnumDisplaySettingsEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_CONTEXT, IARG_END);
						break;
					case(GETTICKCOUNT_INDEX):
						// Add hooking with IPOINT_AFTER to taint the EAX register on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetTickCountExit,
							IARG_CONTEXT,
							IARG_FUNCRET_EXITPOINT_REFERENCE,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(SETTIMER_INDEX):
						// Add hooking with IPOINT_BEFORE to bypass the timer initialization
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetTimerEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_END);
						break;
					case(WAITOBJ_INDEX):
						// Add hooking with IPOINT_BEFORE to bypass the time-out interval
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)WaitForSingleObjectEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_END);
						break;
					case(ICMPECHO_INDEX):
						// Add hooking with IPOINT_BEFORE to bypass the time-out interval
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)IcmpSendEchoEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 5,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 6,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 7,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)IcmpSendEchoExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(LOADLIBA_INDEX):
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)LoadLibraryAHook,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_INST_PTR,
							IARG_END);
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)LoadLibraryExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(LOADLIBW_INDEX):
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)LoadLibraryWHook,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_INST_PTR,
							IARG_END);
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)LoadLibraryExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(GETUSERNAME_INDEX):
						// Add hooking with IPOINT_BEFORE to bypass the username parameters
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetUsernameEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetUsernameExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(FINDWINDOW_INDEX):
						// Add hooking with IPOINT_BEFORE to bypass the window parameters
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FindWindowHookEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the registry on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FindWindowHookExit,
							IARG_CONTEXT,
							IARG_FUNCRET_EXITPOINT_REFERENCE,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					case(CLOSEH_INDEX):
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CloseHandleHookEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_END);
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CloseHandleHookExit,
							IARG_FUNCRET_EXITPOINT_REFERENCE,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					default:
						break;
				}
				// Close the routine
				RTN_Close(rtn);
			}
		}
	}
}

/* API HOOKS (taint sources) begin here */

VOID taintRegisterEax(CONTEXT* ctx) {
	TAINT_TAG_REG(ctx, GPR_EAX, 1, 1, 1, 1);
}

VOID IsDebuggerPresentExit(CONTEXT* ctx, ADDRINT* ret, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	if (_knobBypass) {
		// Bypass API return value
		*ret = 0;
		logInfo->logBypass("IsDebuggerPresent");
	}
	// Taint source: API return value
#if TAINT_ISDEBUGGERPRESENT
	taintRegisterEax(ctx);
#endif
}

VOID CheckRemoteDebuggerPresentEntry(ADDRINT* pbDebuggerPresent) {
	// Store the pbDebuggerPresent into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	apiOutputs->lpbDebuggerPresent = pbDebuggerPresent;
}

VOID CheckRemoteDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	W::PBOOL debuggerPresent = (W::PBOOL)*apiOutputs->lpbDebuggerPresent;
	if (_knobBypass) {
		*debuggerPresent = 0;
		logInfo->logBypass("CheckRemoteDebuggerPresent");
	}
	// Taint source: API return value
#if TAINT_CHECKREMOTEDEBUGGER
	logHookId(ctx, "CheckRemoteDebuggerPresent", *apiOutputs->lpbDebuggerPresent, sizeof(W::BOOL));
	addTaintMemory(ctx, *apiOutputs->lpbDebuggerPresent, sizeof(W::BOOL), TAINT_COLOR_1, true, "CheckRemoteDebuggerPresent");
#endif
}

VOID EnumProcessesEntry(ADDRINT* pointerToProcessesArray, ADDRINT* pointerToBytesProcessesArray) {
	// Store the lpProcessesArray and bytes variable into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::enumProcessesInformations *pc = &apiOutputs->_enumProcessesInformations;
	pc->lpidProcesses = pointerToProcessesArray;
	pc->bytesLpidProcesses = pointerToBytesProcessesArray;
}

VOID EnumProcessesExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Taint source: API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::enumProcessesInformations *pc = &apiOutputs->_enumProcessesInformations;
	ADDRINT* bytesProcesses = (ADDRINT*)*pc->bytesLpidProcesses;
	logInfo->logBypass("EnumProcesses");
#if TAINT_ENUMPROCESSES
	logHookId(ctx, "EnumProcesses", *pc->lpidProcesses, *bytesProcesses);
	addTaintMemory(ctx, *pc->lpidProcesses, *bytesProcesses, TAINT_COLOR_1, true, "EnumProcesses");
#endif
}

VOID Process32FirstNextEntry(ADDRINT hSnapshot, ADDRINT pointerToProcessInformations) {
	// store processes array into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	apiOutputs->lpProcessInformations = pointerToProcessInformations;
}

VOID Process32FirstNextExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	// Bypass EXE file name
	W::LPPROCESSENTRY32 processInfoStructure = (W::LPPROCESSENTRY32) apiOutputs->lpProcessInformations;
	W::CHAR* szExeFile = processInfoStructure->szExeFile;
	if (_knobBypass) {
		char outputExeFileName[MAX_PATH];
		GET_STR_TO_UPPER(szExeFile, outputExeFileName, MAX_PATH);
		if (HiddenElements::shouldHideProcessStr(outputExeFileName)) {
			const char** _path = (const char**)processInfoStructure->szExeFile;
			*_path = BP_FAKEPROCESS;
		}
		logInfo->logBypass("Process32FirstA/Process32NextA");
	}
	// taint source: API return value
#if TAINT_PROCESS32FIRSTNEXT
	logHookId(ctx, "Process32FirstA/Process32NextA", apiOutputs->lpProcessInformations, sizeof(W::PROCESSENTRY32));
	addTaintMemory(ctx, apiOutputs->lpProcessInformations, sizeof(W::PROCESSENTRY32), TAINT_COLOR_1, true, "Process32FirstA/Process32NextA");
#endif
}

VOID Process32FirstNextWEntry(ADDRINT hSnapshot, ADDRINT pointerToProcessInformations) {
	// Store processes array into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	apiOutputs->lpProcessInformationsW = pointerToProcessInformations;
}

VOID Process32FirstNextWExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	// Bypass EXE file name
	W::LPPROCESSENTRY32W processInfoStructure = (W::LPPROCESSENTRY32W) apiOutputs->lpProcessInformationsW;
	W::WCHAR* szExeFile = processInfoStructure->szExeFile;
	if (_knobBypass) {
		char outputExeFileName[MAX_PATH];
		GET_WSTR_TO_UPPER((char*)szExeFile, outputExeFileName, MAX_PATH);
		if (HiddenElements::shouldHideProcessStr(outputExeFileName)) {
			const wchar_t** _path = (const wchar_t**)processInfoStructure->szExeFile;
			*_path = BP_FAKEPROCESSW;
		}
		logInfo->logBypass("Process32FirstW/Process32NextW");
	}
	// taint source: API return value
#if TAINT_PROCESS32FIRSTNEXT
	logHookId(ctx, "Process32FirstW/Process32NextW", apiOutputs->lpProcessInformationsW, sizeof(W::PROCESSENTRY32W));
	addTaintMemory(ctx, apiOutputs->lpProcessInformationsW, sizeof(W::PROCESSENTRY32W), TAINT_COLOR_1, true, "Process32FirstW/Process32NextW");
#endif
}

VOID GetDiskFreeSpaceAEntry(ADDRINT retAddr, ADDRINT* pointerToLpFreeBytesAvailableToCaller, ADDRINT* pointerToLpTotalNumberOfBytes, ADDRINT* pointerToLpTotalNumberOfFreeBytes) {
	// store disk informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::diskFreeSpaceInformations *pc = &apiOutputs->_diskFreeSpaceInformations;
	pc->freeBytesAvailableToCaller = pointerToLpFreeBytesAvailableToCaller;
	pc->totalNumberOfBytes = pointerToLpTotalNumberOfBytes;
	pc->totalNumberOfFreeBytes = pointerToLpTotalNumberOfFreeBytes;
}

VOID GetDiskFreeSpaceAExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::diskFreeSpaceInformations *pc = &apiOutputs->_diskFreeSpaceInformations;
	W::PULARGE_INTEGER freeBytesAvailableToCaller = (W::PULARGE_INTEGER)*pc->freeBytesAvailableToCaller;
	W::PULARGE_INTEGER totalNumberOfBytes = (W::PULARGE_INTEGER)*pc->totalNumberOfBytes;
	W::PULARGE_INTEGER totalNumberOfFreeBytes = (W::PULARGE_INTEGER)*pc->totalNumberOfFreeBytes;
	if (_knobBypass) {
		if (freeBytesAvailableToCaller != NULL) {
			freeBytesAvailableToCaller->QuadPart = BP_MINDISKGB;
		}
		if (totalNumberOfBytes != NULL) {
			totalNumberOfBytes->QuadPart = BP_MINDISKGB;
		}
		if (totalNumberOfFreeBytes != NULL) {
			totalNumberOfFreeBytes->QuadPart = BP_MINDISKGB;
		}
		logInfo->logBypass("GetDiskFreeSpaceA");
	}
	// taint source: API return value
#if TAINT_GETDISKFREESPACE
	if (*pc->freeBytesAvailableToCaller != NULL) {
		logHookId(ctx, "GetDiskFreeSpaceA-freeBytesAvailableToCaller", *pc->freeBytesAvailableToCaller, sizeof(W::ULARGE_INTEGER));
		addTaintMemory(ctx, *pc->freeBytesAvailableToCaller, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpaceA");
	}
	if (*pc->totalNumberOfBytes != NULL) {
		logHookId(ctx, "GetDiskFreeSpaceA-totalNumberOfBytes", *pc->totalNumberOfBytes, sizeof(W::ULARGE_INTEGER));
		addTaintMemory(ctx, *pc->totalNumberOfBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpaceA");
	}
	if (*pc->totalNumberOfFreeBytes != NULL) {
		logHookId(ctx, "GetDiskFreeSpaceA-totalNumberOfFreeBytes", *pc->totalNumberOfFreeBytes, sizeof(W::ULARGE_INTEGER));
		addTaintMemory(ctx, *pc->totalNumberOfFreeBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpaceA");
	}
#endif
}

VOID GetDiskFreeSpaceWEntry(ADDRINT retAddr, ADDRINT* pointerToLpFreeBytesAvailableToCaller, ADDRINT* pointerToLpTotalNumberOfBytes, ADDRINT* pointerToLpTotalNumberOfFreeBytes) {
	// store disk informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::diskFreeSpaceInformationsW *pc = &apiOutputs->_diskFreeSpaceInformationsW;
	pc->freeBytesAvailableToCaller = pointerToLpFreeBytesAvailableToCaller;
	pc->totalNumberOfBytes = pointerToLpTotalNumberOfBytes;
	pc->totalNumberOfFreeBytes = pointerToLpTotalNumberOfFreeBytes;
}

VOID GetDiskFreeSpaceWExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::diskFreeSpaceInformationsW *pc = &apiOutputs->_diskFreeSpaceInformationsW;
	W::PULARGE_INTEGER freeBytesAvailableToCaller = (W::PULARGE_INTEGER)*pc->freeBytesAvailableToCaller;
	W::PULARGE_INTEGER totalNumberOfBytes = (W::PULARGE_INTEGER)*pc->totalNumberOfBytes;
	W::PULARGE_INTEGER totalNumberOfFreeBytes = (W::PULARGE_INTEGER)*pc->totalNumberOfFreeBytes;
	if (_knobBypass) {
		if (freeBytesAvailableToCaller != NULL) {
			freeBytesAvailableToCaller->QuadPart = BP_MINDISKGB;
		}
		if (totalNumberOfBytes != NULL) {
			totalNumberOfBytes->QuadPart = BP_MINDISKGB;
		}
		if (totalNumberOfFreeBytes != NULL) {
			totalNumberOfFreeBytes->QuadPart = BP_MINDISKGB;
		}
		logInfo->logBypass("GetDiskFreeSpaceW");
	}
	// taint source: API return value
#if TAINT_GETDISKFREESPACE
	if (*pc->freeBytesAvailableToCaller != NULL) {
		logHookId(ctx, "GetDiskFreeSpaceW-freeBytesAvailableToCaller", *pc->freeBytesAvailableToCaller, sizeof(W::ULARGE_INTEGER));
		addTaintMemory(ctx, *pc->freeBytesAvailableToCaller, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpaceW");
	}
	if (*pc->totalNumberOfBytes != NULL) {
		logHookId(ctx, "GetDiskFreeSpaceW-totalNumberOfBytes", *pc->totalNumberOfBytes, sizeof(W::ULARGE_INTEGER));
		addTaintMemory(ctx, *pc->totalNumberOfBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpaceW");
	}
	if (*pc->totalNumberOfFreeBytes != NULL) {
		logHookId(ctx, "GetDiskFreeSpaceW-totalNumberOfFreeBytes", *pc->totalNumberOfFreeBytes, sizeof(W::ULARGE_INTEGER));
		addTaintMemory(ctx, *pc->totalNumberOfFreeBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpaceW");
	}
#endif
}

VOID GlobalMemoryStatusEntry(ADDRINT* pointerToLpBuffer) {
	// store memory informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	apiOutputs->lpMemoryInformations = pointerToLpBuffer;
}

VOID GlobalMemoryStatusExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	W::LPMEMORYSTATUSEX memoryInformations = (W::LPMEMORYSTATUSEX)*apiOutputs->lpMemoryInformations;
	if (_knobBypass) {
		memoryInformations->ullTotalPhys = BP_MINRAMGB;
		logInfo->logBypass("GlobalMemoryStatus");
	}
	// Taint source: API return value
#if TAINT_GLOBALMEMORYSTATUS
	logHookId(ctx, "GlobalMemoryStatus", *apiOutputs->lpMemoryInformations, sizeof(W::MEMORYSTATUSEX));
	addTaintMemory(ctx, *apiOutputs->lpMemoryInformations, sizeof(W::MEMORYSTATUSEX), TAINT_COLOR_1, true, "GlobalMemoryStatus");
#endif
}

VOID GetSystemInfoEntry(ADDRINT* pointerToLpSystemInfo) {
	// Store system informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	apiOutputs->lpSystemInformations = pointerToLpSystemInfo;
}

VOID GetSystemInfoExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	W::LPSYSTEM_INFO systemInfoStructure = (W::LPSYSTEM_INFO) *apiOutputs->lpSystemInformations;
	W::DWORD_PTR* dwActiveProcessorMask = &systemInfoStructure->dwActiveProcessorMask; // inner-pointer dwActiveProcessorMask
	if (_knobBypass) {
		systemInfoStructure->dwNumberOfProcessors = BP_NUMCORES;
		logInfo->logBypass("GetSystemInfo");
	}
	// Taint source: API return value
#if TAINT_GETSYSTEMINFO
	logHookId(ctx, "GetSystemInfo", *apiOutputs->lpSystemInformations, sizeof(W::SYSTEM_INFO));
	addTaintMemory(ctx, *apiOutputs->lpSystemInformations, sizeof(W::SYSTEM_INFO), TAINT_COLOR_1, true, "GetSystemInfo");
	addTaintMemory(ctx, (ADDRINT)dwActiveProcessorMask, sizeof(W::DWORD), TAINT_COLOR_1, true, "GetSystemInfo dwActiveProcessorMask");
#endif
}

VOID GetCursorPosEntry(ADDRINT* pointerToLpPoint) {
	// Store mouse pointer informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	apiOutputs->lpCursorPointerInformations = *pointerToLpPoint;
}

VOID GetCursorPosExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	W::LPPOINT point = (W::LPPOINT)apiOutputs->lpCursorPointerInformations;
	if (point == NULL)
		return;
	if (_knobBypass) {
		if(point->x)
			point->x = rand() % 500;
		if(point->y)
			point->y = rand() % 500;
		logInfo->logBypass("GetCursorPos");
	}
	// Taint source: API return value
#if TAINT_GETCURSORPOS
	logHookId(ctx, "GetCursorPos", apiOutputs->lpCursorPointerInformations, sizeof(W::POINT));
	addTaintMemory(ctx, apiOutputs->lpCursorPointerInformations, sizeof(W::POINT), TAINT_COLOR_1, true, "GetCursorPos");
#endif
}

VOID GetModuleFileNameHookEntry(W::LPTSTR* moduleName, W::DWORD* nSize) {
	// Store module informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::moduleFileNameInformations* pc = &apiOutputs->_moduleFileNameInformations;
	pc->lpModuleName = *moduleName;
	pc->lpNSize = *nSize;
}

VOID GetModuleFileNameHookExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);

	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::moduleFileNameInformations* pc = &apiOutputs->_moduleFileNameInformations;

	if (pc->lpModuleName == NULL || *pc->lpModuleName == NULL) 
		return;

	char value[PATH_BUFSIZE];
	char logName[256] = "GetModuleFileName ";

	GET_STR_TO_UPPER(pc->lpModuleName, value, PATH_BUFSIZE);
	if (_knobBypass) {
		// Bypass API return value
		if (strstr(value, "VBOX") != NULL) {
			memcpy(pc->lpModuleName, BP_FAKEDRV, sizeof(BP_FAKEDRV));
			strcat(logName, value);
			logModule->logBypass(logName);
		}
	}

	memset(value, 0, sizeof(value));
	GET_WSTR_TO_UPPER(pc->lpModuleName, value, PATH_BUFSIZE);

	if (_knobBypass) {
		// Bypass API return value
		if (strstr(value, "VBOX") != NULL) {
			memcpy(pc->lpModuleName, BP_FAKEDRV_W, sizeof(BP_FAKEDRV_W));
			strcat(logName, value);
			logModule->logBypass(logName);
		}
	}

	// Taint source: API return value (very high load)
#if TAINT_GETMODULEFILENAME
	logHookId(ctx, "GetModuleFileName", (ADDRINT)pc->lpModuleName, pc->lpNSize);
	addTaintMemory(ctx, (ADDRINT)pc->lpModuleName, pc->lpNSize, TAINT_COLOR_1, true, "GetModuleFileName");
#endif
	return;
}

VOID GetDeviceDriverBaseNameHookEntry(W::LPTSTR* lpBaseName, W::DWORD* nSize) {
	// Store driver informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::driverBaseNameInformations* pc = &apiOutputs->_driverBaseNameInformations;
	pc->lpDriverBaseName = *lpBaseName;
	pc->lpNSize = *nSize;
}

VOID GetDeviceDriverBaseNameHookExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);

	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::driverBaseNameInformations* pc = &apiOutputs->_driverBaseNameInformations;
	if (pc->lpDriverBaseName == NULL || *pc->lpDriverBaseName == NULL)
		return;

	char value[PATH_BUFSIZE];
	char logName[256] = "GetDeviceDriverBaseName ";

	GET_STR_TO_UPPER(pc->lpDriverBaseName, value, PATH_BUFSIZE);
	// Bypass API return value
	if (_knobBypass) {
		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			memcpy(pc->lpDriverBaseName, BP_FAKEDRV, sizeof(BP_FAKEDRV));
			strcat(logName, value);
			logModule->logBypass(logName);
		}
	}

	memset(value, 0, sizeof(value));
	GET_WSTR_TO_UPPER(pc->lpDriverBaseName, value, PATH_BUFSIZE);
	// Bypass API return value
	if (_knobBypass) {
		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			memcpy(pc->lpDriverBaseName, BP_FAKEDRV_W, sizeof(BP_FAKEDRV_W));
			strcat(logName, value);
			logModule->logBypass(logName);
		}
	}
	// Taint source: API return value
#if TAINT_GETDEVICEDRIVERNAME
	logHookId(ctx, "GetDeviceDriverBaseName", (ADDRINT)pc->lpDriverBaseName, pc->lpNSize);
	addTaintMemory(ctx, (ADDRINT)pc->lpDriverBaseName, pc->lpNSize, TAINT_COLOR_1, true, "GetDeviceDriverBaseName");
#endif
	return;
}

VOID GetAdaptersInfoEntry(PIP_ADAPTER_INFO* adapInfo, W::PULONG* size) {
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::adapterInformations* pc = &apiOutputs->_adapterInformations;
	pc->macStruct = *adapInfo;
	pc->macSizeStruct = *size;
	pc->macSizeStructInitial = **size;
}

VOID GetAdaptersInfoExit(CONTEXT* ctx, ADDRINT ret, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::adapterInformations* pc = &apiOutputs->_adapterInformations;
	PIP_ADAPTER_INFO adapInfo = pc->macStruct;
	W::PULONG size = pc->macSizeStruct;
	W::ULONG preSize = pc->macSizeStructInitial;

	if (ret != 0 || preSize == 0 || preSize < *size || adapInfo->AddressLength == 0)
		return;

#if TAINT_GETADAPTERSINFO
	logHookId(ctx, "GetAdaptersInfo", (ADDRINT)adapInfo, preSize);
#endif 
	while (adapInfo != nullptr) {
		if (adapInfo->AddressLength > MAX_POSSIBLE_SIZE_MAC) 
			return; 
		if (_knobBypass) {
			if (adapInfo->AddressLength == 6 && (!memcmp("\x08\x00\x27", adapInfo->Address, 3) ||
				!memcmp("\x00\x05\x69", adapInfo->Address, 3) || !memcmp("\x00\x0c\x29", adapInfo->Address, 3) ||
				!memcmp("\x00\x1c\x14", adapInfo->Address, 3) || !memcmp("\x00\x50\x56", adapInfo->Address, 3))) {
				memcpy(adapInfo->Address, "\x07\x01\x33", 3);
				break;
			}
		}
#if TAINT_GETADAPTERSINFO
		addTaintMemory(ctx, (ADDRINT)(adapInfo->AdapterName), MAX_ADAPTER_NAME_LENGTH + 4, TAINT_COLOR_3, true, "GetAdaptersInfo");
		addTaintMemory(ctx, (ADDRINT)(adapInfo->Description), MAX_ADAPTER_DESCRIPTION_LENGTH + 4, TAINT_COLOR_3, true, "GetAdaptersInfo");
		addTaintMemory(ctx, (ADDRINT) & (adapInfo->AddressLength), sizeof(UINT), TAINT_COLOR_3, true, "GetAdaptersInfo");
		addTaintMemory(ctx, (ADDRINT)(adapInfo->Address), MAX_ADAPTER_ADDRESS_LENGTH, TAINT_COLOR_3, true, "GetAdaptersInfo");
		addTaintMemory(ctx, (ADDRINT) & (adapInfo->Index), sizeof(W::DWORD), TAINT_COLOR_3, true, "GetAdaptersInfo");
		addTaintMemory(ctx, (ADDRINT) & (adapInfo->Type), sizeof(W::UINT), TAINT_COLOR_3, true, "GetAdaptersInfo");
#endif

		adapInfo = adapInfo->Next;
	}
}

VOID EnumDisplaySettingsEntry(W::LPCTSTR* devName, CONTEXT* ctx) {
	if(_knobBypass)
		memset((void*)*devName, CHAR_EDS, W::lstrlen(*devName));
#if TAINT_ENUMDISPLAYSETTINGS
	logHookId(ctx, "EnumDisplaySettings", (ADDRINT)devName, W::lstrlen(*devName));
	addTaintMemory(ctx, (ADDRINT)devName, W::lstrlen(*devName), TAINT_COLOR_7, true, "EnumDisplaySettings");
#endif
}

VOID GetTickCountExit(CONTEXT* ctx, W::DWORD* ret, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::globalState* gs = State::getGlobalState();
	if (_knobBypass) {
		gs->_timeInfo.tick += 30 + gs->_timeInfo.sleepMsTick;
		gs->_timeInfo.sleepMsTick = 0;
		*ret = gs->_timeInfo.tick;
		logInfo->logBypass("GetTickCount");
	}
	// Taint source: API return value
#if TAINT_GETTICKCOUNT
	taintRegisterEax(ctx);
#endif
}

VOID SetTimerEntry(W::UINT* time) {
	if (*time == INFINITE) 
		return; 
	// Bypass the sleep duration 
	State::globalState* gs = State::getGlobalState();
	if (_knobBypass) {
		gs->_timeInfo.sleepMs += *time;
		gs->_timeInfo.sleepMsTick += *time;
		*time = BP_TIMER;
		logInfo->logBypass("SetTimer");
	}
}

VOID WaitForSingleObjectEntry(W::DWORD *time) {
	if (*time == INFINITE) 
		return;
	// Bypass the time-out interval
	State::globalState* gs = State::getGlobalState();
	if (_knobBypass) {
		gs->_timeInfo.sleepMs += *time;
		gs->_timeInfo.sleepMsTick += *time;
		*time = BP_TIMER;
	}
}

VOID IcmpSendEchoEntry(ADDRINT* replyBuffer, ADDRINT* replySize, W::DWORD *time) {
	if (*time == INFINITE)
		return;
	// Bypass the time-out interval
	State::globalState* gs = State::getGlobalState();
	if (_knobBypass) {
		gs->_timeInfo.sleepMs += *time;
		gs->_timeInfo.sleepMsTick += *time;
		*time = BP_ICMP_ECHO;
		logInfo->logBypass("IcmpSendEcho");
	}
	// Store reply buffer and reply size into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::icmpSendEchoInformations *icmpInformations = &apiOutputs->_icmpSendEchoInformations;
	icmpInformations->replyBuffer = replyBuffer;
	icmpInformations->replySize = replySize;
}

VOID IcmpSendEchoExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Taint source: API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::icmpSendEchoInformations *icmpInformations = &apiOutputs->_icmpSendEchoInformations;
#if TAINT_ICMPSENDECHO
	taintRegisterEax(ctx);
	logHookId(ctx, "IcmpSendEcho", *icmpInformations->replyBuffer, *icmpInformations->replySize);
	addTaintMemory(ctx, *icmpInformations->replyBuffer, *icmpInformations->replySize, TAINT_COLOR_1, true, "IcmpSendEcho");
#endif
}

VOID LoadLibraryAHook(const char** lib) {
	if (lib == NULL || *lib == NULL) 
		return;

	char value[PATH_BUFSIZE];
	char logName[256] = "LoadLibrary ";
	GET_STR_TO_UPPER(*lib, value, PATH_BUFSIZE);

	if (_knobBypass) {
		if (strstr(value, "VIRTUALBOX") != NULL || strstr(value, "VBOX") != NULL || strstr(value, "HOOK") != NULL) {
			strcat(logName, value);
			logModule->logBypass(logName);
			*lib = BP_FAKEDLL;
			return;
		}
	}
	return;
}

VOID LoadLibraryWHook(const wchar_t** lib) { 
	if (lib == NULL || *lib == NULL) 
		return;

	char value[PATH_BUFSIZE];
	char logName[256] = "LoadLibrary ";
	GET_WSTR_TO_UPPER(*lib, value, PATH_BUFSIZE);

	if (_knobBypass) {
		if (strstr(value, "VIRTUALBOX") != NULL || strstr(value, "VBOX") != NULL || strstr(value, "HOOK") != NULL) {
			strcat(logName, value);
			logModule->logBypass(logName);
			*lib = BP_FAKEDLL_W;
			return;
		}
	}
	return;
}

VOID LoadLibraryExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Taint source: API return value (very high load)
#if TAINT_LOADLIBRARY
	TAINT_TAG_REG(ctx, GPR_EAX, TAINT_COLOR_8, TAINT_COLOR_8, TAINT_COLOR_8, TAINT_COLOR_8);
#endif
}

VOID GetUsernameEntry(W::LPTSTR* lpBuffer, W::LPDWORD* nSize) {
	// Store username informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::usernameInformations* pc = &apiOutputs->_usernameInformations;
	pc->usernameBuffer = *lpBuffer;
	pc->lpNSize = *nSize;
}

VOID GetUsernameExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);

	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::usernameInformations* pc = &apiOutputs->_usernameInformations;
	if (pc->usernameBuffer == NULL || *pc->usernameBuffer == NULL)
		return;

	char value[PATH_BUFSIZE];
	char logName[256] = "GetUsername ";

	GET_STR_TO_UPPER(pc->usernameBuffer, value, PATH_BUFSIZE);
	// Bypass API return value
	if (_knobBypass) {
		if (HiddenElements::shouldHideUsernameStr(value)) {
			memcpy(pc->usernameBuffer, BP_FAKEUSERNAME, sizeof(BP_FAKEUSERNAME));
			strcat(logName, value);
			logModule->logBypass(logName);
		}
	}

	memset(value, 0, sizeof(value));
	GET_WSTR_TO_UPPER(pc->usernameBuffer, value, PATH_BUFSIZE);
	// Bypass API return value
	if (_knobBypass) {
		if (HiddenElements::shouldHideUsernameStr(value)) {
			memcpy(pc->usernameBuffer, BP_FAKEUSERNAME_W, sizeof(BP_FAKEUSERNAME_W));
			strcat(logName, value);
			logModule->logBypass(logName);
		}
	}
	// Taint source: API return value
#if TAINT_GETUSERNAME
	logHookId(ctx, "GetUsername", (ADDRINT)pc->usernameBuffer, *pc->lpNSize);
	addTaintMemory(ctx, (ADDRINT)pc->usernameBuffer, *pc->lpNSize, TAINT_COLOR_1, true, "GetUsername");
#endif
	return;
}

VOID FindWindowHookEntry(W::LPCTSTR* path1, W::LPCTSTR* path2) {
	char value[PATH_BUFSIZE] = { 0 };
	if (_knobBypass) {
		char logName[256] = "FindWindow ";
		// Bypass the first path
		if (_knobBypass) {
			if (path1 != NULL && *path1 != NULL && (char*)*path1 != "") {
				GET_STR_TO_UPPER((char*)*path1, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideWindowStr(value)) {
					strcat(logName, value);
					logModule->logBypass(logName);
					*path1 = STR_GUI_1A;
					return;
				}

				memset(value, 0, sizeof(value));
				GET_WSTR_TO_UPPER(*path1, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideWindowStr(value)) {
					strcat(logName, value);
					logModule->logBypass(logName);
					*path1 = STR_GUI_1B;
					return;
				}
			}
		}

		// Bypass the second path
		if (_knobBypass) {
			if ((path2 != NULL && *path2 != NULL && (char*)*path2 != "")) {
				memset(value, 0, sizeof(value));
				GET_STR_TO_UPPER((char*)*path2, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideWindowStr(value)) {
					strcat(logName, value);
					logModule->logBypass(logName);
					*path2 = STR_GUI_2;
					return;
				}

				memset(value, 0, sizeof(value));
				GET_WSTR_TO_UPPER(*path2, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideWindowStr(value)) {
					strcat(logName, value);
					logModule->logBypass(logName);
					*path2 = STR_GUI_2B;
					return;
				}
			}
		}
	}
}

VOID FindWindowHookExit(CONTEXT* ctx, W::BOOL* ret, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Taint source: API return value
#if TAINT_FINDWINDOW
	taintRegisterEax(ctx);
#endif
}

VOID CloseHandleHookEntry(W::HANDLE* handle) {
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	OBJECT_HANDLE_FLAG_INFORMATION flags;
	flags.ProtectFromClose = 0;
	flags.Inherit = 0;

	if (_knobBypass) {
		W::HANDLE ret = W::CreateMutex(NULL, FALSE, BP_MUTEX);
		// CloseHandle with status = STATUS_HANDLE_NOT_CLOSABLE
		if (W::NtQueryObject(*handle, (W::OBJECT_INFORMATION_CLASS)4, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), 0) >= 0) {
			if (flags.ProtectFromClose) {
				apiOutputs->closeHandleStatus = 1;
				*handle = ret;

			}
		}
		// CloseHandle with status = INVALID_HANDLE
		else {
			apiOutputs->closeHandleStatus = 2;
			*handle = ret;
		}
	}
}

VOID CloseHandleHookExit(W::BOOL* ret, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* apiOutputs = State::getApiOutputs();

	if (_knobBypass) {
		if (apiOutputs->closeHandleStatus == 1) {
			*ret = 0;
			logInfo->logBypass("CloseHandle STATUS_HANDLE_NOT_CLOSABLE");
		}
		else if (apiOutputs->closeHandleStatus == 2) {
			W::SetLastError(ERROR_INVALID_HANDLE);
			*ret = CODEFORINVALIDHANDLE;
			logInfo->logBypass("CloseHandle STATUS_INVALID_HANDLE");
		}
	}
}

/* END OF API HOOKS */