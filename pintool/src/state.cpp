#include "state.h"

/* ===================================================================== */
/* Singleton structure object to access global objects                   */
/* ===================================================================== */
State::globalState _globalState;
State::apiOutputs  _apiOutputs;

/* ===================================================================== */
/* Knob variables                                                        */
/* ===================================================================== */
BOOL _knobApiTracing;
BOOL _knobBypass;

namespace State {
	/* ===================================================================== */
	/* Initialization function to allocate memory for structures             */
	/* ===================================================================== */
	void init() {
		// Initialize memory portion
		memset(&_globalState, 0, sizeof(globalState));
		memset(&_apiOutputs, 0, sizeof(apiOutputs));

		// Useful time informations (magic numbers)
		State::globalState* gs = State::getGlobalState();
		gs->_timeInfo.tick = 3478921;
		gs->_timeInfo._edx_eax = 0x6000000002346573ULL;
		gs->dllExports = std::vector<monitoredDLL>();
	}

	/* ===================================================================== */
	/* Function to access the structure that stores global objects           */
	/* ===================================================================== */
	globalState* getGlobalState() {
		return &_globalState;
	}

	/* ===================================================================== */
	/* Function to access the structure that stores API outputs              */
	/* ===================================================================== */
	apiOutputs* getApiOutputs() {
		return &_apiOutputs;
	}
}