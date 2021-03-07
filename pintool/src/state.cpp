#include "state.h"

/* ===================================================================== */
/* Singleton structure object to access global objects                   */
/* ===================================================================== */
State::globalState _globalState;
State::apiOutputs  _apiOutputs;

namespace State {
	/* ===================================================================== */
	/* Initialization function to allocate memory for structures             */
	/* ===================================================================== */
	void init() {
		// Initialize memory portion
		memset(&_globalState, 0, sizeof(globalState));
		memset(&_apiOutputs, 0, sizeof(apiOutputs));

		// Useful time informations (magic numbers)
		_globalState._timeInfo.tick = 3478921;
		_globalState._timeInfo._edx_eax = 0x6000000002346573ULL;
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