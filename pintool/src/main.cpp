/* ================================================================== */
/* Imports                                                            */
/* ================================================================== */
#pragma once
#include "main.h"


/* ================================================================== */
/* Global variables                                                   */ 
/* ================================================================== */

// Define page size
#ifndef PAGE_SIZE
	#define PAGE_SIZE 0x1000
#endif
// Tool name and relative version
#define TOOL_NAME "simpleProfilerAPI"
#define VERSION "2.0"
// Object that contains useful functions to access the process
ProcessInfo pInfo;
// Object that contains useful functions for logging
LoggingInfo logInfo;
// Object that contains useful functions for special instructions instrumentation (cpuid, rdtsc)
SpecialInstructionsHandler* specialInstructionsHandlerInfo;
// Define TLS key
TLS_KEY tls_key = INVALID_TLS_KEY;

/* ================================================================== */
/* Knobs definitions                                                  */
/* ================================================================== */

// Define knobs
KNOB<BOOL> knobApiTracing(KNOB_MODE_WRITEONCE, "pintool", "trace", "false", "Enable API tracing at instruction level after each tainted conditional branch (high load)");
KNOB <BOOL> knobBypass(KNOB_MODE_WRITEONCE, "pintool", "bypass", "true", "Enable return value bypass for APIs and instructions to avoid sandbox/VM detection (enabled by default)");
KNOB <BOOL> knobLeak(KNOB_MODE_WRITEONCE, "pintool", "leak", "false", "Enable bypass to avoid leaks of real EIP through FPU instructions (disabled by default)");
KNOB<BOOL> knobSystemCodeAlert(KNOB_MODE_WRITEONCE, "pintool", "alertSystemCode", "true", "Enable taint alert for tainted system code (enabled by default)");

/* ============================================================================= */
/* Define macro to check the instruction address and check if is program code    */
/* ============================================================================= */
#define CHECK_EIP_ADDRESS(eip_address) do { \
State::globalState* gs = State::getGlobalState(); \
itreenode_t* node = itree_search(gs->dllRangeITree, eip_address); \
if(node != NULL) return; \
} while (0)

/* ===================================================================== */
/* Function called for every loaded module                               */
/* ===================================================================== */
VOID ImageLoad(IMG Image, VOID *v) {
	// Add the module to the current process
	pInfo.addModule(Image);
	// Insert the current image to the interval tree
	pInfo.addCurrentImageToTree(Image);
	// Add APIs hooking for the current image
	Functions::AddHooks(Image);
}

/* ===================================================================== */
/* Function called for every unload module                               */
/* ===================================================================== */
VOID ImageUnload(IMG Image, VOID* v) {
	// Remote the current image from the interval tree
	pInfo.removeCurrentImageFromTree(Image);
}

/* ===================================================================== */
/* Function called BEFORE every TRACE                                    */
/* ===================================================================== */
VOID InstrumentInstruction(TRACE trace, VOID *v) {
	// Define iterators 
	BBL bbl;
	INS ins;

	// Traverse all the BBLs in the trace 
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		// Traverse all the instructions in the BBL 
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			// Check for special instructions (cpuid, rdtsc, int and in) to avoid VM/sandbox detection and taint memory
			specialInstructionsHandlerInfo->checkSpecialInstruction(ins);
			if (_knobApiTracing) {
				// If "control flow" instruction (branch, call, ret) OR "far jump" instruction (FAR_JMP in Windows with IA32 is sometimes a syscall)
				if (_alertApiTracingCounter > 0 && (INS_IsControlFlow(ins) || INS_IsFarJump(ins))) {
					// Insert a call to "saveTransitions" (AFUNPTR) relative to instruction "ins"
					// parameters: IARG_INST_PTR (address of instrumented instruction), IARG_BRANCH_TARGET_ADDR (target address of the branch instruction)
					// hint: remember to use IARG_END (end argument list)!!
					ADDRINT curEip = INS_Address(ins);
					INS_InsertCall(
						ins,
						IPOINT_BEFORE, (AFUNPTR)SaveTransitions,
						IARG_INST_PTR,
						IARG_BRANCH_TARGET_ADDR,
						IARG_ADDRINT, curEip,
						IARG_END
					);
				}
			}
		}
	}
}

/* ===================================================================== */
/* Utility function to search the nearest address in the export map of   */
/* the current DLL to find which system API is called                    */
/* ===================================================================== */
W::DWORD searchNearestAddressExportMap(std::map<W::DWORD, std::string> exportsMap, ADDRINT addr) {
	W::DWORD currentAddr;
	for (const auto& p : exportsMap) {
		if (!currentAddr) {
			currentAddr = p.first;
		}
		else {
			if (std::abs((long)(p.first - addr)) < std::abs((long)(currentAddr - addr))) {
				currentAddr = p.first;
			}
		}
	}
	return currentAddr;
}

/* ===================================================================== */
/* Function called BEFORE the analysis routine to enter critical section */
/* ===================================================================== */
VOID SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo, ADDRINT cur_eip) {
	CHECK_EIP_ADDRESS(cur_eip);
	// Enter critical section (ensure that we can call PIN APIs)
	PIN_LockClient();
	// Call analysis routine
	_SaveTransitions(addrFrom, addrTo);
	// Exit critical section
	PIN_UnlockClient();
}

/* ===================================================================== */
/* Function called for each ANALYSIS ROUTINE (instruction analysis)      */
/* Parameters: addrFrom (address of instruction), addrTo (target address)*/
/* ===================================================================== */
VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo) {
	// Get access to global state variables
	State::globalState* gs = State::getGlobalState();

	// Last shellcode to which the transition got redirected
	static ADDRINT lastShellc = UNKNOWN_ADDR;

	// Variables to check caller/target process
	const bool isCallerMy = pInfo.isMyAddress(addrFrom);
	const bool isTargetMy = pInfo.isMyAddress(addrTo);

	// Variables to get caller/target module
	IMG callerModule = IMG_FindByAddress(addrFrom);
	IMG targetModule = IMG_FindByAddress(addrTo);

	// Variables to get the address of the page relative to addresses
	ADDRINT pageFrom = GetPageOfAddr(addrFrom);
	ADDRINT pageTo = GetPageOfAddr(addrTo);

	// [API CALL TRACING]
	// Is it a transition FROM THE TRACED MODULE TO A FOREIGN MODULE? (my process is calling the instruction and pointing to a foreign module) 
	std::map<W::DWORD, std::string> exportsMap;
	std::string dllName;
	W::DWORD nearestAddressExportsMap;
	if (isCallerMy && !isTargetMy) {
		// Get relative virtual address (address - get_base(address)) of the foreign module
		ADDRINT RvaFrom = addr_to_rva(addrFrom);
		// Check if the image of the foreign module is VALID
		if (IMG_Valid(targetModule)) {
			const std::string func = get_func_at(addrTo);
			// Get DLL name (Image name) from the Pin APIs and the interval tree
			itreenode_t* currentNode = itree_search(gs->dllRangeITree, addrTo);
			for (int i = 0; i < gs->dllExports.size(); i++) {
				if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
					exportsMap = gs->dllExports[i].exports;
					dllName = std::string((char*)gs->dllExports[i].dllPath);
					nearestAddressExportsMap = searchNearestAddressExportMap(exportsMap, addrTo);
				}
			}
			// Write to log file the API call with dll name and function name
			logInfo.logCall(0, RvaFrom, true, dllName, (exportsMap)[nearestAddressExportsMap].c_str());
			_alertApiTracingCounter -= 1;
		}
		else {
			// Image not valid (no mapped module), let's save the beginning of this area as possible shellcode
			lastShellc = pageTo;
		}
	}
	// [SHELLCODE API CALL TRACING]
	// Trace calls from witin the last shellcode that was called from the traced module
	if (!IMG_Valid(callerModule)) {
		const ADDRINT callerPage = pageFrom;
		// If the caller page is a known address and correspond to the last possible shellcode, log it
		if (callerPage != UNKNOWN_ADDR && callerPage == lastShellc) {
			// If the target of the shellcode is valid continue
			if (IMG_Valid(targetModule)) {
				// Log the API call of the called shellcode (get function name and dll name)
				itreenode_t* currentNode = itree_search(gs->dllRangeITree, addrTo);
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						exportsMap = gs->dllExports[i].exports;
						dllName = std::string((char*)gs->dllExports[i].dllPath);
						nearestAddressExportsMap = searchNearestAddressExportMap(exportsMap, addrTo);
					}
				}
				logInfo.logCall(callerPage, addrFrom, false, dllName, (exportsMap)[nearestAddressExportsMap].c_str());
				_alertApiTracingCounter -= 1;
			}
			// Otherwise, set the variable lastShellc if the mode is recursive (shellcode inside shellcode)
			else if (pageFrom != pageTo) {
				lastShellc = pageTo;
			}
		}
	}
}

/* ===================================================================== */
/* Function to handle context change and retrieve exception reason       */
/* ===================================================================== */
static void OnCtxChange(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom, CONTEXT *ctxtTo, INT32 info, VOID *v) {
	// Check if context variable exists
	if (ctxtTo == NULL || ctxtFrom == NULL) {
		return;
	}
	// Update global variables on Windows generic exception
	if (reason == CONTEXT_CHANGE_REASON_EXCEPTION) { 
		FetchGlobalState;
	}
	// Enter critical section (ensure that we can call PIN APIs)
	PIN_LockClient();
	// Extract address from and address to from the registry context
	const ADDRINT addrFrom = (ADDRINT)PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
	const ADDRINT addrTo = (ADDRINT)PIN_GetContextReg(ctxtTo, REG_INST_PTR);
	// Add logging based on reason
	std::string reasonDescription = "";
	switch(reason) {
		case CONTEXT_CHANGE_REASON_FATALSIGNAL:
			reasonDescription = "fatal unix signal";
			break;
		case CONTEXT_CHANGE_REASON_SIGNAL:
			reasonDescription = "handled unix signal";
			break;
		case CONTEXT_CHANGE_REASON_SIGRETURN:
			reasonDescription = "return from unix signal handler";
			break;
		case CONTEXT_CHANGE_REASON_APC:
			reasonDescription = "windows apc";
			break;
		case CONTEXT_CHANGE_REASON_EXCEPTION:
			reasonDescription = "windows generic exception";
			break; 
		case CONTEXT_CHANGE_REASON_CALLBACK:
			reasonDescription = "windows callback";
			break;
	}
	// Log the exception
	logInfo.logException(addrFrom, reasonDescription);
	// Exit critical section
	PIN_UnlockClient();
}


/* ===================================================================== */
/* Function to handle each thread start and retrieve useful informations */
/* for libdft                                                            */
/* ===================================================================== */
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *) {
	// TLS handling
	pintool_tls* tdata = new pintool_tls;
	if (PIN_SetThreadData(tls_key, tdata, tid) == FALSE) {
		std::cerr << "Cannot initialize the TLS key for the thread " + tid << "!" << std::endl;
		PIN_ExitProcess(1);
	}
	// Initialize libdft thread context
	thread_ctx_t *thread_ctx = libdft_thread_start(ctxt);
	// Setup thread informations
	#define TTINFO(field) thread_ctx->ttinfo.field
	// Retrieve thread ID
	TTINFO(tid) = tid;
	// Retrieve OS thread ID
	TTINFO(os_tid) = PIN_GetTid();
	// Initialize other fields
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
	TTINFO(offendingInstruction) = 0;
	TTINFO(logTaintedSystemCode) = 0;
	// Initialize shadow stack
	TTINFO(shadowStackThread) = new callStackThread;
	TTINFO(shadowStackThread)->callStack = new std::vector<callStackFrame>;
	TTINFO(shadowStackThread)->callStack->reserve(32);
	TTINFO(shadowStackThread)->callStackTop = 0;
	// Undefine thread informations (used later in bridge.cpp for libdft tainting)
	#undef TTINFO
	// Initialize buffered logger for the current thread
	threadInitLogger(tid, tdata);
}

/* ===================================================================== */
/* Function to handle each thread end and destroy libdft thread context  */
/* ===================================================================== */
VOID OnThreadFini(THREADID tid, const CONTEXT *ctxt, INT32, VOID *) {
	// Destroy libdft thread context
	libdft_thread_fini(ctxt);
	// Destroy buffered logger for the current thread
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, tid));
	threadExitLogger(tid, tdata);
}

/* ===================================================================== */
/* Function to handle the exceptions (anti-DBI checks)                   */
/* ===================================================================== */
EXCEPT_HANDLING_RESULT internalExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v) {
	std::cout << PIN_ExceptionToString(pExceptInfo).c_str() << " Code: " << pExceptInfo->GetExceptCode() << std::endl;
	// Handle single-step exception
	if (pExceptInfo->GetExceptCode() == EXCEPTCODE_DBG_SINGLE_STEP_TRAP) {
		ExceptionHandler *eh = ExceptionHandler::getInstance();
		eh->setExceptionToExecute(NTSTATUS_STATUS_BREAKPOINT);
		logInfo.logBypass("Single Step Exception");
		return EHR_HANDLED;
	} 
	// Libdft hack for EFLAGS (unaligned memory access)
	else if (PIN_GetExceptionCode(pExceptInfo) == EXCEPTCODE_ACCESS_MISALIGNED) {
		// Clear EFLAGS.AC 
		PIN_SetPhysicalContextReg(pPhysCtxt, REG_EFLAGS, CLEAR_EFLAGS_AC(PIN_GetPhysicalContextReg(pPhysCtxt, REG_EFLAGS)));
		return EHR_HANDLED;
	}
	return EHR_CONTINUE_SEARCH;
}

/* ===================================================================== */
/* Print Help Message (usage message)                                    */
/* ===================================================================== */
INT32 Usage() {
	cerr << "Hi there :-) Have fun with some Dynamic Taint Analysis!\n" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

/* =================================================================================================== */
/* Main function                                                                                       */
/* =================================================================================================== */
/* argc, argv are the entire command line: pin.exe -t <toolname.dll> <knobParameters> -- sample.exe    */
/* =================================================================================================== */
int main(int argc, char * argv[]) {
	// Initialize pin symbols
	PIN_InitSymbols();

	// Initialize pin (in case of error print usage)
	if (PIN_Init(argc, argv)) {
		return Usage();
	}

	// Open output file using the logging module (API tracing)
	logInfo.init(LOGPATH MAIN_LOG_NAME);
	initLoggerShadowCallStack(LOGPATH CALLSTACK_LOG_NAME);

	// Setup knob variables
	_knobBypass = knobBypass.Value();
	_knobLeak = knobLeak.Value();
	_knobApiTracing = knobApiTracing.Value();
	_knobAlertSystemCode = knobSystemCodeAlert.Value();

	// Initialize global state informations
	State::init();
	State::globalState* gs = State::getGlobalState();
	gs->logInfo = &logInfo;

	// Initialize elements to be hidden
	HiddenElements::initializeHiddenStuff();

	// Remove old file related to taint analysis
	W::WIN32_FIND_DATA ffd; 
	W::HANDLE hFind = FindFirstFile(LOGPATH_TAINT "*.log", &ffd);
	do {
		std::string fileName = ffd.cFileName;
		if (fileName.rfind("tainted-", 0) == 0) {
			char fullPath[256];
			sprintf(fullPath, LOGPATH_TAINT "%s", fileName.c_str());
			remove(fullPath);
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	// Get module name from command line argument
	std::string appName = "";
	// Iterate over argc until "--"
	for (int i = 1; i < (argc - 1); i++) {
		if (strcmp(argv[i], "--") == 0) {
			appName = argv[i + 1];
			// If the app_name contains a directory, split it and get the file name
			if (appName.find("/") != std::string::npos) {
				appName = appName.substr(appName.rfind("/") + 1);
			}
			break;
		}
	}

	// Obtain a TLS key
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY) {
		std::cerr << "Cannot initialize TLS key!" << std::endl;
		PIN_ExitProcess(1);
	}

	// Initialize ProcessInfo object 
	pInfo.init(appName);

	// Register system hooking
	SYSHOOKING::Init(&logInfo);

	// Initialize FPU leak evasions
	if(_knobLeak)
		SpecialInstructionsHandler::fpuInit();

	// Register function to be called BEFORE every TRACE (analysis routine for API TRACING, SHELLCODE TRACING AND SECTION TRACING)
	TRACE_AddInstrumentFunction(InstrumentInstruction, (VOID*)0);

	// Initialize SpecialInstructions (to handle special instructions) object with related modules (processInfo and logInfo)
	specialInstructionsHandlerInfo = SpecialInstructionsHandler::getInstance();
	specialInstructionsHandlerInfo->init(&pInfo, &logInfo);

	// Register function to be called for every loaded module (populate ProcessInfo object, populate interval tree and add API HOOKING FOR FURTHER TAINT ANALYSIS)
	IMG_AddInstrumentFunction(ImageLoad, NULL);

	// Register function to be called for evenry unload module (remove image from interval tree)
	IMG_AddUnloadFunction(ImageUnload, NULL);

	// Initialize Functions object (to handle API hooking and taint hooking) 
	Functions::Init(&logInfo);

	// Register context changes
	PIN_AddContextChangeFunction(OnCtxChange, NULL);

	// Register exception control flow
	PIN_AddInternalExceptionHandler(internalExceptionHandler, NULL);

	// Register thread start evenet to initialize libdft thread context
	PIN_AddThreadStartFunction(OnThreadStart, NULL);

	// Register thread end evenet to destroy libdft thread context
	PIN_AddThreadFiniFunction(OnThreadFini, NULL);

	// Initialize libdft engine
	if (libdft_init_data_only()) {
		std::cerr << "Error during libdft initialization!" << std::endl;
		PIN_ExitProcess(1);
	}

	// Initialize disassembler module
	if (initializeDisassembler()) {
		std::cerr << "Error during disassembler module initialization!" << std::endl;
		PIN_ExitProcess(1);
	}

	// Welcome message :-)
	std::cerr << "===============================================" << std::endl;
	std::cerr << "This application is instrumented by " << TOOL_NAME << " v." << VERSION << std::endl;
	std::cerr << "Profiling module " << appName << std::endl;
	std::cerr << "===============================================" << std::endl;

	// Start the program, never returns
	PIN_StartProgram();

	// Stop libdft engine (typically not reached but make the compiler happy)
	libdft_die();

	// Exit program
	return EXIT_SUCCESS;
}