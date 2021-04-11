#pragma once

#include <map>
#include "pin.H" 
#include "winheaders.h"
#include "itree.h"

extern BOOL _knobApiTracing;
extern BOOL _knobBypass;

namespace State {

	/* ===================================================================== */
	/* Structure about time informations                                     */
	/* ===================================================================== */
	struct timeInfo {
		W::DWORD sleepMs; // WaitForSingleObjectHook, SYSHOOKS::NtDelayexecution_entry, INS_patchRtdsc_exit
		W::DWORD sleepMsTick; // GetTickCount, WaitForSingleObjectHook, SYSHOOKS::NtDelayexecution_entry, SYSHOOKS::NtQueryPerformanceCounter_exit
		W::SHORT sleepTime; // NtDelayexecution, IcmpCreateFileEntryHook
		W::DWORD lastMs; // SYSHOOKS::NtDelayexecution_entry
		W::DWORD numLastMs; // SYSHOOKS::NtDelayexecution_entry
		W::DWORD lastMs2; // SYSHOOKS::NtQueryPerformanceCounter
		W::DWORD numLastMs2; // SYSHOOKS::NtQueryPerformanceCounter
		W::DWORD tick; // GetTickCountHook - REQUIRES INITIALIZATION
		UINT64 _edx_eax; // INS_patchRtdsc_exit - REQUIRES INITIALIZATION
		UINT32 _eax; // INS_patchRtdsc_exit
		UINT32 _edx; // INS_patchRtdsc_exit
	};

	/* ===================================================================== */
	/* Structure to store global objects (like the itree for DLLs)           */
	/* ===================================================================== */
	struct globalState {
		timeInfo _timeInfo;
		W::SHORT ntQueryCounter;
		W::SHORT flagStep;
		W::BOOL waitForDebugger;
		itreenode_t* dllRangeITree;
		std::vector<monitoredDLL> dllExports;
		ADDRINT cpuid_eax;
		ADDRINT* pointerToLpidProcess;
		ADDRINT* pointerToBytesLpidProcess;
	};

	/* ===================================================================== */
	/* Structure to store API outputs                                        */
	/* ===================================================================== */
	struct apiOutputs {
		ADDRINT* lpbDebuggerPresent;
		ADDRINT  lpProcessInformations;
		ADDRINT  lpProcessInformationsW;
		ADDRINT lpCursorPointerInformations;
		ADDRINT* lpMemoryInformations;
		ADDRINT* lpSystemInformations;
		struct enumProcessesInformations {
			ADDRINT* lpidProcesses;
			ADDRINT* bytesLpidProcesses;
		} _enumProcessesInformations;
		struct diskFreeSpaceInformations {
			ADDRINT* freeBytesAvailableToCaller;
			ADDRINT* totalNumberOfBytes;
			ADDRINT* totalNumberOfFreeBytes;
		} _diskFreeSpaceInformations;
		struct diskFreeSpaceInformationsW {
			ADDRINT* freeBytesAvailableToCaller;
			ADDRINT* totalNumberOfBytes;
			ADDRINT* totalNumberOfFreeBytes;
		} _diskFreeSpaceInformationsW;
		struct icmpSendEchoInformations {
			ADDRINT* replyBuffer;
			ADDRINT* replySize;
		} _icmpSendEchoInformations;
	};

	/* ===================================================================== */
	/* Initialization function to allocate memory for structures             */
	/* ===================================================================== */
	void init();

	/* ===================================================================== */
	/* Function to access the structure that stores global objects           */
	/* ===================================================================== */
	globalState* getGlobalState();

	/* ===================================================================== */
	/* Function to access the structure that stores API outputs              */
	/* ===================================================================== */
	apiOutputs* getApiOutputs();
};

/* ===================================================================== */
/* Singleton structure object to access global objects                   */
/* ===================================================================== */
extern State::globalState _globalState;

/* ===================================================================== */
/* Singleton structure object to access API outputs                      */
/* ===================================================================== */
extern State::apiOutputs _apiOutputs;

/* ===================================================================== */
/* Update structure that store global objects                            */
/* ===================================================================== */
#define FetchGlobalState	State::globalState* gs = &_globalState;
#define FetchApiOutputs	    State::apiOutputs* apiOutputs = &_apiOutputs;
#define FetchTimeState		State::timeInfo* tinfo = &_globalState._timeInfo;