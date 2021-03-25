#pragma once
#include "functions.h"
#include "types.h"
#include "process.h"
#include "helper.h"
#include "HiddenElements.h"
#include <string>
#include <iostream>

/* ===================================================================== */
/* Define taint color                                                    */
/* ===================================================================== */
#define TAINT_COLOR_1 0x01
#define TAINT_COLOR_2 0x02
#define TAINT_COLOR_3 0x03
#define TAINT_COLOR_4 0x04
#define TAINT_COLOR_5 0x05
#define TAINT_COLOR_6 0x06
#define TAINT_COLOR_7 0x07
#define TAINT_COLOR_8 0x08

/* ============================================================================= */
/* Define macro to taint a register using thread_ctx_ptr and GPR from libdft     */
/* ============================================================================= */
#define TAINT_TAG_REG(ctx, taint_gpr, t0, t1, t2, t3) do { \
tag_t _tags[4] = {t0, t1, t2, t3}; \
thread_ctx_t *thread_ctx = (thread_ctx_t *)PIN_GetContextReg(ctx, thread_ctx_ptr); \
addTaintRegister(thread_ctx, taint_gpr, _tags, true); \
} while (0)

/* ============================================================================= */
/* Define macro to check the return address in ESP and check if is program code  */
/* ============================================================================= */
#define CHECK_ESP_RETURN_ADDRESS(esp_pointer) do { \
ADDRINT espValue = *((ADDRINT*) esp_pointer); \
State::globalState* gs = State::getGlobalState(); \
itreenode_t* node = itree_search(gs->dllRangeITree, espValue); \
if(node != NULL) return; \
} while (0)

/* ===================================================================== */
/* Instruction description for instruction tainting                      */
/* ===================================================================== */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

namespace Functions {
	/* ===================================================================== */
	/* Hook/API map (internal use)                                           */
	/* ===================================================================== */
	static std::map<std::string, int> fMap;

	/* ===================================================================== */
	/* Initialization function to define API map                             */
	/* ===================================================================== */
	void Init() {
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
		// Time API hooks
		fMap.insert(std::pair<std::string, int>("GetTickCount", GETTICKCOUNT_INDEX));
		fMap.insert(std::pair<std::string, int>("SetTimer", SETTIMER_INDEX));
		fMap.insert(std::pair<std::string, int>("WaitForSingleObject", WAITOBJ_INDEX));
		fMap.insert(std::pair<std::string, int>("IcmpSendEcho", ICMPECHO_INDEX));
		
		// ACTUALLY DEFINED FOR EACH INSTRUCTION IN LIBDFT_API

		// Define instruction hooking for taint analysis (taint sinks) - control transfer instruction (call, jmp, ret)
		/**
		// Instrument near call
		(void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR], dta_instrument_jmp_call);
		// Instrument jmp
		(void)ins_set_post(&ins_desc[XED_ICLASS_JMP], dta_instrument_jmp_call);
		**/
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
	}
	// Taint source: API return value
	taintRegisterEax(ctx);
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
	}
	// Taint source: API return value
	addTaintMemory(*apiOutputs->lpbDebuggerPresent, sizeof(W::BOOL), TAINT_COLOR_1, true, "CheckRemoteDebuggerPresent");
}

VOID EnumProcessesEntry(ADDRINT* pointerToProcessesArray, ADDRINT* pointerToBytesProcessesArray) {
	// Store the lpProcessesArray and bytes variable into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::enumProcessesInformations *pc = &apiOutputs->_enumProcessesInformations;
	pc->lpidProcesses = pointerToProcessesArray;
	pc->bytesLpidProcesses = pointerToBytesProcessesArray;
}

VOID EnumProcessesExit(ADDRINT eax, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Taint source: API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	State::apiOutputs::enumProcessesInformations *pc = &apiOutputs->_enumProcessesInformations;
	ADDRINT* bytesProcesses = (ADDRINT*)*pc->bytesLpidProcesses;
	addTaintMemory(*pc->lpidProcesses, *bytesProcesses, TAINT_COLOR_1, true, "EnumProcesses");
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
	}
	// taint source: API return value
	addTaintMemory(apiOutputs->lpProcessInformations, sizeof(W::PROCESSENTRY32), TAINT_COLOR_1, true, "Process32First/Process32Next");
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
	}
	// taint source: API return value
	addTaintMemory(apiOutputs->lpProcessInformationsW, sizeof(W::PROCESSENTRY32W), TAINT_COLOR_1, true, "Process32FirstW/Process32NextW");
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
	}
	// taint source: API return value
	addTaintMemory(*pc->freeBytesAvailableToCaller, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
	addTaintMemory(*pc->totalNumberOfBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
	addTaintMemory(*pc->totalNumberOfFreeBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
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
	}
	// taint source: API return value
	addTaintMemory(*pc->freeBytesAvailableToCaller, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
	addTaintMemory(*pc->totalNumberOfBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
	addTaintMemory(*pc->totalNumberOfFreeBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
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
	if(_knobBypass)
		memoryInformations->ullTotalPhys = BP_MINRAMGB;
	// Taint source: API return value
	addTaintMemory(*apiOutputs->lpMemoryInformations, sizeof(W::MEMORYSTATUSEX), TAINT_COLOR_1, true, "GlobalMemoryStatus");
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
	if(_knobBypass)
		systemInfoStructure->dwNumberOfProcessors = BP_NUMCORES;
	// Taint source: API return value
	addTaintMemory(*apiOutputs->lpSystemInformations, sizeof(W::SYSTEM_INFO), TAINT_COLOR_1, true, "GetSystemInfo");
	addTaintMemory((ADDRINT)dwActiveProcessorMask, sizeof(W::DWORD), TAINT_COLOR_1, true, "GetSystemInfo dwActiveProcessorMask");
}

VOID GetCursorPosEntry(ADDRINT* pointerToLpPoint) {
	// Store mouse pointer informations into global variables
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	apiOutputs->lpCursorPointerInformations = pointerToLpPoint;
}

VOID GetCursorPosExit(CONTEXT* ctx, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::apiOutputs* apiOutputs = State::getApiOutputs();
	W::LPPOINT point = (W::LPPOINT)*apiOutputs->lpCursorPointerInformations;
	if (_knobBypass) {
		point->x = rand() % 500;
		point->y = rand() % 500;
	}
	// Taint source: API return value
	addTaintMemory(*apiOutputs->lpCursorPointerInformations, sizeof(W::POINT), TAINT_COLOR_1, true, "GetCursorPos");
}

VOID GetTickCountExit(CONTEXT* ctx, W::DWORD* ret, ADDRINT esp) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	// Bypass API return value
	State::globalState* gs = State::getGlobalState();
	if (_knobBypass) {
		gs->_timeInfo.tick += 30 + gs->_timeInfo.sleepMsTick;
		gs->_timeInfo.sleepMsTick = 0;
		*ret = gs->_timeInfo.tick;
	}
	// Taint source: API return value
	taintRegisterEax(ctx);
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
	taintRegisterEax(ctx);
	addTaintMemory(*icmpInformations->replyBuffer, *icmpInformations->replySize, TAINT_COLOR_1, true, "IcmpSendEcho");
}

/* END OF API HOOKS */

// ACTUALLY DEFINED FOR EACH INSTRUCTION IN LIBDFT_API

/* INSTRUCTION HOOKS (taint sinks) begin here */

/**
static void dta_instrument_jmp_call(INS ins) {
	instrumentForTaintCheck(ins);
}
**/

/* END OF INSTRUCTION HOOKS */