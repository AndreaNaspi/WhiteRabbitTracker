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

/* ================================================================== */
/* Knobs definitions                                                  */
/* ================================================================== */

// Define knob for output file (used by "-o" option, default value: profile.log)
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "profile.log", "specify output file name");

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
	xed_iclass_enum_t ins_indx;

	// Traverse all the BBLs in the trace 
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		// Traverse all the instructions in the BBL 
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			// Check for special instructions (cpuid, rdtsc, int and in) to avoid VM/sandbox detection and taint memory
			specialInstructionsHandlerInfo->checkSpecialInstruction(ins);
			// If "control flow" instruction (branch, call, ret) OR "far jump" instruction (FAR_JMP in Windows with IA32 is sometimes a syscall)
			/*if ((INS_IsControlFlow(ins) || INS_IsFarJump(ins))) {
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
			}*/
		}
	}
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
	// Last shellcode to which the transition got redirected:
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
	if (isCallerMy && !isTargetMy) {
		// Get relative virtual address (address - get_base(address)) of the foreign module
		ADDRINT RvaFrom = addr_to_rva(addrFrom);
		// Check if the image of the foreign module is VALID
		if (IMG_Valid(targetModule)) {
			const std::string func = get_func_at(addrTo);
			// Get DLL name (Image name) from the Pin APIs
			const std::string dll_name = IMG_Name(targetModule);
			// Write to log file the API call with dll name and function name
			logInfo.logCall(0, RvaFrom, true, dll_name, func);
		}
		else {
			// Image not valid (no mapped module), let's save the beginning of this area as possible shellcode
			lastShellc = pageTo;
			// Write to log file the call to a not valid target module (save the beginning of this area as possible shellcode)
			logInfo.logCall(0, RvaFrom, lastShellc, addrTo);
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
				const std::string func = get_func_at(addrTo);
				const std::string dll_name = IMG_Name(targetModule);
				logInfo.logCall(callerPage, addrFrom, false, dll_name, func);
			}
			// Otherwise, set the variable lastShellc if the mode is recursive (shellcode inside shellcode)
			else if (pageFrom != pageTo) {
				lastShellc = pageTo;
			}
		}
	}
	// [SECTION TRACING]
	// Is the address WITHIN THE TRACED MODULE? 
	if (isTargetMy) {
		// Get relative virtual address (address - get_base(address)) of the target address
		ADDRINT rva = addr_to_rva(addrTo); 
		// Transition from one section to another?
		if (pInfo.updateTracedModuleSection(rva)) {
			// Get the target section
			const s_module* sec = pInfo.getSecByAddr(rva);
			// Get the section name
			std::string curr_name = (sec) ? sec->name : "?";
			// New section called detected
			if (isCallerMy) {
				// Convert to RVA
				ADDRINT rvaFrom = addr_to_rva(addrFrom); 
				const s_module* prev_sec = pInfo.getSecByAddr(rvaFrom);
				std::string prev_name = (prev_sec) ? prev_sec->name : "?";
				logInfo.logNewSectionCalled(rvaFrom, prev_name, curr_name);
			}
			// Otherwise, section change detected
			logInfo.logSectionChange(rva, curr_name);
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
	// Call analysis routine
	_SaveTransitions(addrFrom, addrTo);
	// Exit critical section
	PIN_UnlockClient();
}


/* ===================================================================== */
/* Function to handle each thread start and retrieve useful informations */
/* for libdft                                                            */
/* ===================================================================== */
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *) {
	// Initialize libdft thread context
	thread_ctx_t *thread_ctx = libdft_thread_start(ctxt);
	// Setup thread informations
	#define TTINFO(field) thread_ctx->ttinfo.field
	// Retrieve thread ID
	TTINFO(tid) = tid;
	// Retrieve OS thread ID
	TTINFO(os_tid) = PIN_GetTid();
	// Setup log path for the specific thread ID
	char tmp[32];
	sprintf(tmp, "tainted-%u.log", TTINFO(os_tid));
	TTINFO(logname) = strdup(tmp);
	// Undefine thread informations (used later in bridge.cpp for libdft tainting)
	#undef TTINFO
}

/* ===================================================================== */
/* Function to handle each thread end and destroy libdft thread context  */
/* ===================================================================== */
VOID OnThreadFini(THREADID tid, const CONTEXT *ctxt, INT32, VOID *) {
	// Destroy libdft thread context
	libdft_thread_fini(ctxt);
}

/* ===================================================================== */
/* Function to handle the exceptions (anti-DBI checks)                   */
/* ===================================================================== */
EXCEPT_HANDLING_RESULT internalExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v) {
	// Handle single-step exception
	if (pExceptInfo->GetExceptCode() == EXCEPTCODE_DBG_SINGLE_STEP_TRAP) {
		ExceptionHandler *eh = ExceptionHandler::getInstance();
		eh->setExceptionToExecute(NTSTATUS_STATUS_BREAKPOINT);
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
	cerr << "This tool counts the number of dynamic instructions executed" << endl;
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

	// Initialize global state informations
	State::init();

	// Open output file using the logging module (API tracing)
	logInfo.init(KnobOutputFile.Value());

	// Remove old file related to taint analysis
	W::WIN32_FIND_DATA ffd; 
	W::HANDLE hFind = FindFirstFile(".\\*.log", &ffd);
	do {
		std::string fileName = ffd.cFileName;
		if (fileName.rfind("tainted-", 0) == 0)
			remove(fileName.c_str());
	} while (FindNextFile(hFind, &ffd) != 0);

	// Get module name from command line argument
	std::string app_name = "";
	// Iterate over argc until "--"
	for (int i = 1; i < (argc - 1); i++) {
		if (strcmp(argv[i], "--") == 0) {
			app_name = argv[i + 1];
			// If the app_name contains a directory, split it and get the file name
			if (app_name.find("/") != std::string::npos) {
				app_name = app_name.substr(app_name.rfind("/") + 1);
			}
			break;
		}
	}

	// Initialize ProcessInfo object 
	pInfo.init(app_name);

	// Register exception control flow
	PIN_AddInternalExceptionHandler(internalExceptionHandler, NULL);

	// Initialize SpecialInstructions (to handle special instructions) object with related modules (processInfo and logInfo)
	specialInstructionsHandlerInfo = SpecialInstructionsHandler::getInstance();
	specialInstructionsHandlerInfo->init(&pInfo, &logInfo);

	// Register function to be called for every loaded module (populate ProcessInfo object, populate interval tree and add API HOOKING FOR FURTHER TAINT ANALYSIS)
	IMG_AddInstrumentFunction(ImageLoad, NULL);

	// Register function to be called for evenry unload module (remove image from interval tree)
	IMG_AddUnloadFunction(ImageUnload, NULL);

	// Register function to be called BEFORE every TRACEA (analysis routine for API TRACING, SHELLCODE TRACING AND SECTION TRACING)
	TRACE_AddInstrumentFunction(InstrumentInstruction, (VOID *)0);

	// Register context changes
	PIN_AddContextChangeFunction(OnCtxChange, NULL);

	// Register thread start evenet to initialize libdft thread context
	PIN_AddThreadStartFunction(OnThreadStart, NULL);

	// Register thread end evenet to destroy libdft thread context
	PIN_AddThreadFiniFunction(OnThreadFini, NULL);

	// Initialize libdft engine
	if (libdft_init_data_only()) {
		std::cerr << "Error during libdft initialization!" << std::endl;
		return EXIT_FAILURE;
	}

	// Initialize Functions (to handle API hooking and taint hooking) object 
	Functions::Init();

	// Welcome message :)
	std::cerr << "===============================================" << std::endl;
	std::cerr << "This application is instrumented by " << TOOL_NAME << " v." << VERSION << std::endl;
	std::cerr << "Profiling module " << app_name << std::endl;
	std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
	std::cerr << "===============================================" << std::endl;

	// Start the program, never returns
	PIN_StartProgram();

	// Stop libdft engine (typically not reached but make the compiler happy)
	libdft_die();

	// Exit program
	return EXIT_SUCCESS;
}