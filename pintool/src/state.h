#pragma once

#include "pin.H" 
#include "winheaders.h"
#include "itree.h"

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
		ADDRINT* pointerToLpidProcess;
		ADDRINT* pointerToBytesLpidProcess;
	};

	/* ===================================================================== */
	/* Initialization function to allocate memory for structures             */
	/* ===================================================================== */
	void init();

	/* ===================================================================== */
	/* Function to access the structure that stores global objects           */
	/* ===================================================================== */
	globalState* getGlobalState();
};

/* ===================================================================== */
/* Singleton structure object to access global objects                   */
/* ===================================================================== */
extern State::globalState _globalState;

/* ===================================================================== */
/* Update structure that store global objects                            */
/* ===================================================================== */
#define FetchGlobalState	State::globalState* gs = &_globalState;
