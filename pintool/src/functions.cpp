#pragma once
#include "functions.h"
#include "types.h"
#include "process.h"
#include <string>
#include <iostream>

/* ===================================================================== */
/* Define random stapp when we need to fill fields                       */
/* ===================================================================== */
#define CHAR_SDI	's'
#define STR_GUI_1A	"W" 
#define STR_GUI_1B	"a"
#define STR_GUI_2	"WantSuppli"
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
		// Define API map
		fMap.insert(std::pair<std::string, int>("IsDebuggerPresent", ISDEBUGGERPRESENT_INDEX));
		fMap.insert(std::pair<std::string, int>("CheckRemoteDebuggerPresent", CHECKREMOTEDEBUGGERPRESENT_INDEX));
		fMap.insert(std::pair<std::string, int>("EnumProcesses", ENUMPROCESSES_INDEX));
		fMap.insert(std::pair<std::string, int>("K32EnumProcesses", ENUMPROCESSES_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32First", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32FirstW", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32Next", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32NextW", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceExA", GETDISKFREESPACE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceExW", GETDISKFREESPACE_INDEX));
		fMap.insert(std::pair<std::string, int>("GlobalMemoryStatusEx", GLOBALMEMORYSTATUS_INDEX));
		fMap.insert(std::pair<std::string, int>("GetSystemInfo", GETSYSTEMINFO_INDEX));
		fMap.insert(std::pair<std::string, int>("GetTickCount", GETTICKCOUNT_INDEX));
		fMap.insert(std::pair<std::string, int>("GetCursorPos", GETCURSORPOS_INDEX));

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
					// API IsDebuggerPresent
					case ISDEBUGGERPRESENT_INDEX:
						// Add hooking with IPOINT_AFTER to retrieve taint the EAX register on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)IsDebuggerPresentExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_EAX,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					// API CheckRemoteDebuggerPresent 
					case CHECKREMOTEDEBUGGERPRESENT_INDEX:
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve pbDebuggerPresent)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CheckRemoteDebuggerPresentEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_END);
						// Add hooking with IPOINT_AFTER to the nemory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CheckRemoteDebuggerPresentExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_EAX,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					// API EnumProcesses and K32Enumprocesses
					case ENUMPROCESSES_INDEX:
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
					// API PRocess32First and Process32Next
					case PROCESS32FIRSTNEXT_INDEX:
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
					// API GetDiskFreeSpace
					case GETDISKFREESPACE_INDEX:
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve disk informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetDiskFreeSpaceEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the memory on output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetDiskFreeSpaceExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					// API GlobalMemoryStatus
					case GLOBALMEMORYSTATUS_INDEX:
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
					// API GetSystemInfo
					case GETSYSTEMINFO_INDEX:
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
					// API GetTickCount
					case GETTICKCOUNT_INDEX:
						// Add hooking with IPOINT_AFTER to retrieve the API output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetTickCountExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_EAX,
							IARG_REG_VALUE, REG_STACK_PTR,
							IARG_END);
						break;
					// API GetCursorPos
					case GETCURSORPOS_INDEX:
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

VOID IsDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);
	taintRegisterEax(ctx);
}

VOID CheckRemoteDebuggerPresentEntry(ADDRINT* pbDebuggerPresent) {
	// store the pbDebuggerPresent into global variables
	State::apiOutputs* gs = State::getApiOutputs();
	gs->lpbDebuggerPresent = pbDebuggerPresent;
}

VOID CheckRemoteDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* gs = State::getApiOutputs();
	addTaintMemory(*gs->lpbDebuggerPresent, sizeof(W::BOOL), TAINT_COLOR_1, true, "CheckRemoteDebuggerPresent");
}

VOID EnumProcessesEntry(ADDRINT* pointerToProcessesArray, ADDRINT* pointerToBytesProcessesArray) {
	// store the lpProcessesArray and bytes variable into global variables
	State::apiOutputs* gs = State::getApiOutputs();
	State::apiOutputs::enumProcessesInformations *pc = &gs->_enumProcessesInformations;
	pc->lpidProcesses = pointerToProcessesArray;
	pc->bytesLpidProcesses = pointerToBytesProcessesArray;
}

VOID EnumProcessesExit(ADDRINT eax, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* gs = State::getApiOutputs();
	State::apiOutputs::enumProcessesInformations *pc = &gs->_enumProcessesInformations;
	ADDRINT* bytesProcesses = (ADDRINT*)*pc->bytesLpidProcesses;
	addTaintMemory(*pc->lpidProcesses, *bytesProcesses, TAINT_COLOR_1, true, "EnumProcesses");
}

VOID Process32FirstNextEntry(ADDRINT hSnapshot, ADDRINT pointerToProcessInformations) {
	// store processes array into global variables
	State::apiOutputs* gs = State::getApiOutputs();
	gs->lpProcessInformations = pointerToProcessInformations;
}

VOID Process32FirstNextExit(CONTEXT* ctx, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* gs = State::getApiOutputs();
	addTaintMemory(gs->lpProcessInformations, sizeof(W::PROCESSENTRY32W), TAINT_COLOR_1, true, "Process32First/Process32Next");
}

VOID GetDiskFreeSpaceEntry(ADDRINT* pointerToLpFreeBytesAvailableToCaller, ADDRINT* pointerToLpTotalNumberOfBytes, ADDRINT* pointerToLpTotalNumberOfFreeBytes) {
	// store disk informations into global variables
	State::apiOutputs* gs = State::getApiOutputs();
	State::apiOutputs::diskFreeSpaceInformations *pc = &gs->_diskFreeSpaceInformations;
	pc->freeBytesAvailableToCaller = pointerToLpFreeBytesAvailableToCaller;
	pc->totalNumberOfBytes = pointerToLpTotalNumberOfBytes;
	pc->totalNumberOfFreeBytes = pointerToLpTotalNumberOfFreeBytes;
}

VOID GetDiskFreeSpaceExit(CONTEXT* ctx, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);	
	State::apiOutputs* gs = State::getApiOutputs();
	State::apiOutputs::diskFreeSpaceInformations *pc = &gs->_diskFreeSpaceInformations;
	addTaintMemory(*pc->freeBytesAvailableToCaller, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
	addTaintMemory(*pc->totalNumberOfBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
	addTaintMemory(*pc->totalNumberOfFreeBytes, sizeof(W::ULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
}

VOID GlobalMemoryStatusEntry(ADDRINT* pointerToLpBuffer) {
	// store memory informations into global variables
	State::apiOutputs* gs = State::getApiOutputs();
	gs->lpMemoryInformations = pointerToLpBuffer;
}

VOID GlobalMemoryStatusExit(CONTEXT* ctx, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* gs = State::getApiOutputs();
	addTaintMemory(*gs->lpMemoryInformations, sizeof(W::MEMORYSTATUSEX), TAINT_COLOR_1, true, "GlobalMemoryStatus");
}

VOID GetSystemInfoEntry(ADDRINT* pointerToLpSystemInfo) {
	// store system informations into global variables
	State::apiOutputs* gs = State::getApiOutputs();
	gs->lpSystemInformations = pointerToLpSystemInfo;
}

VOID GetSystemInfoExit(CONTEXT* ctx, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* gs = State::getApiOutputs();
	W::LPSYSTEM_INFO systemInfoStructure = (W::LPSYSTEM_INFO) gs->lpSystemInformations;
	ADDRINT dwActiveProcessorMask = systemInfoStructure->dwActiveProcessorMask; // inner-pointer dwActiveProcessorMask
	addTaintMemory(*gs->lpSystemInformations, sizeof(W::SYSTEM_INFO), TAINT_COLOR_1, true, "GetSystemInfo");
	addTaintMemory(dwActiveProcessorMask, sizeof(W::DWORD), TAINT_COLOR_1, true, "GetSystemInfo dwActiveProcessorMask"); 
}

VOID GetTickCountExit(CONTEXT* ctx, ADDRINT eax, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);
	taintRegisterEax(ctx);
}

VOID GetCursorPosEntry(ADDRINT* pointerToLpPoint) {
	// store mouse pointer informations into global variables
	State::apiOutputs* gs = State::getApiOutputs();
	gs->lpCursorPointerInformations = pointerToLpPoint;
}

VOID GetCursorPosExit(CONTEXT* ctx, ADDRINT esp) {
	// taint source: API return value
	CHECK_ESP_RETURN_ADDRESS(esp);
	State::apiOutputs* gs = State::getApiOutputs();
	addTaintMemory(*gs->lpCursorPointerInformations, sizeof(W::POINT), TAINT_COLOR_1, true, "GetCursorPos");
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