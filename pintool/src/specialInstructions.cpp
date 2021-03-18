#include "specialInstructions.h"

/* ============================================================================= */
/* Define macro to check the instruction address and check if is program code    */
/* ============================================================================= */
#define CHECK_EIP_ADDRESS(eip_address) do { \
State::globalState* gs = State::getGlobalState(); \
itreenode_t* node = itree_search(gs->dllRangeITree, eip_address); \
if(node != NULL) return; \
} while (0)

/* ===================================================================== */
/* constructor for singleton object                                      */
/* ===================================================================== */
SpecialInstructionsHandler::SpecialInstructionsHandler() {
}

/* ===================================================================== */
/* singleton getInstance function                                        */
/* ===================================================================== */
SpecialInstructionsHandler* SpecialInstructionsHandler::instance = nullptr;
SpecialInstructionsHandler* SpecialInstructionsHandler::getInstance() {
	if (instance == nullptr) {
		instance = new SpecialInstructionsHandler();
	}
	return instance;
}

/* ===================================================================== */
/* Utility function to compare two strings (compare instruction name)    */
/* ===================================================================== */
bool SpecialInstructionsHandler::isStrEqualI(std::string string1, std::string string2) {
	// if the length is different, return false
	if (string1.length() != string2.length()) {
		return false;
	}
	// compare the strings char-by-char
	for (size_t i = 0; i < string1.length(); i++) {
		if (tolower(string1[i]) != tolower(string2[i])) {
			return false;
		}
	}
	return true;
}

/* ===================================================================== */
/* Utility function to handle registers for cpuid handling               */
/* ===================================================================== */
void SpecialInstructionsHandler::regInit(REGSET* regsIn, REGSET* regsOut) {
	REGSET_AddAll(*regsIn);
	REGSET_Clear(*regsOut);
	REGSET_Insert(*regsOut, REG_GAX);
	REGSET_Insert(*regsOut, REG_GBX);
	REGSET_Insert(*regsOut, REG_GDX);
	REGSET_Insert(*regsOut, REG_GCX);
}

/* ===================================================================== */
/* Function to check for specific special instruction and insert handlers*/
/* ===================================================================== */
void SpecialInstructionsHandler::checkSpecialInstruction(INS ins) {
	static int insCount = 0;
	ExceptionHandler *eh = ExceptionHandler::getInstance();
	SpecialInstructionsHandler* specialInstructionsHandlerInfo = SpecialInstructionsHandler::getInstance();
	// check if exist a PENDING EXCEPTION (like for int 2d) and EXECUTE THE EXCEPTION
	if (insCount == 0)
		insCount++;
	else {
		if (eh->isPendingException()) {
			insCount = 0;
			// Trigger the current exception
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ExceptionHandler::executeExceptionIns, IARG_CONTEXT,
				IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins), IARG_END);
			return;
		}
	}
	// Get disassembled instruction
	std::string diassembled_ins = INS_Disassemble(ins);
	// Initialize registries for possible IARG_PARTIAL_CONTEXT
	REGSET regsIn, regsOut;
	// If "cpuid" instruction (log call with relevant registers and alter values to avoid VM/sandbox detection)
	if (specialInstructionsHandlerInfo->isStrEqualI(INS_Mnemonic(ins), "cpuid") || diassembled_ins.find("cpuid") != std::string::npos) {
		// Insert a pre-call before cpuid to log the instruction and get the EAX parameter (category of information)
		ADDRINT curEip = INS_Address(ins);
		specialInstructionsHandlerInfo->regInit(&regsIn, &regsOut);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)SpecialInstructionsHandler::CpuidCalled,
			IARG_INST_PTR,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_ADDRINT, curEip,
			IARG_END);
		// Insert a post-call after cpuid to alter the return registers (EBX, ECX, EDX) based on the parameter (EAX) and avoid VM/sandbox detection
		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)SpecialInstructionsHandler::AlterCpuidValues,
			IARG_INST_PTR,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_ADDRINT, curEip,
			IARG_END);
	}
	// if "rdtsc" instruction (log and alter values to avoid VM/sandbox detection)
	else if (INS_IsRDTSC(ins) || diassembled_ins.find("rdtsc") != std::string::npos) {
		ADDRINT curEip = INS_Address(ins);
		// Insert a post-call to alter edx register (rdtsc results) in case of rdtsc instruction (avoid VM/sandbox detection)
		// Specify IARG_RETURN_REGS and REG_GDX to write on a specific return register (rdtsc result)
		INS_InsertCall(
			ins,
			IPOINT_AFTER, (AFUNPTR)SpecialInstructionsHandler::AlterRdtscValueEdx,
			IARG_CONTEXT,
			IARG_ADDRINT, curEip,
			IARG_RETURN_REGS,
			REG_GDX,
			IARG_END);
		// Insert a post-call to alter eax register (rdtsc results) in case of rdtsc instruction (avoid VM/sandbox detection)
		// Specify IARG_RETURN_REGS and REG_GAX to write on a specific return register (rdtsc result)
		INS_InsertCall(ins,
			IPOINT_AFTER, (AFUNPTR)SpecialInstructionsHandler::AlterRdtscValueEax,
			IARG_CONTEXT,
			IARG_ADDRINT, curEip,
			IARG_RETURN_REGS,
			REG_GAX,
			IARG_END);
	}
	// if "int 2d" instruction (log and generate exception to avoid VM/sandbox detection)
	else if (specialInstructionsHandlerInfo->isStrEqualI(INS_Mnemonic(ins), "int 0x2d") || diassembled_ins.find("int 0x2d") != std::string::npos) {
		ADDRINT curEip = INS_Address(ins);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)SpecialInstructionsHandler::Int2dCalled,
				        IARG_CONTEXT,
						IARG_ADDRINT, curEip,
					    IARG_END);
	}
	// if "in eax, dx" instruction (log and alter values to avoid VMWare detection
	else if (specialInstructionsHandlerInfo->isStrEqualI(INS_Mnemonic(ins), "in eax, dx") || diassembled_ins.find("in eax, dx") != std::string::npos) {
		// Insert a post-call to alter ebx register ('in eax, dx' result) in case of 'in eax, dx' instruction (avoid VMWare detection)
		ADDRINT curEip = INS_Address(ins);
		specialInstructionsHandlerInfo->regInit(&regsIn, &regsOut);
		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)SpecialInstructionsHandler::InEaxDxCalledAlterValueEbx,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_ADDRINT, curEip,
			IARG_END);

	}
}

/* ===================================================================== */
/* Function to handle and log the cpuid instruction                      */
/* ===================================================================== */
void SpecialInstructionsHandler::CpuidCalled(ADDRINT ip, CONTEXT* ctxt, ADDRINT cur_eip) {
	// Get class instance to access objects
	SpecialInstructionsHandler *classHandler = SpecialInstructionsHandler::getInstance();
	// Get address and parameters of the instruction
	ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
	ADDRINT _eax;
	PIN_GetContextRegval(ctxt, REG_GAX, reinterpret_cast<UINT8*>(&_eax));
	// Save the parameter (register EAX) to save the category ofi nformation
	classHandler->cpuid_eax = _eax;
}

/* ===================================================================== */
/* Utility function to alter EBX, ECX, EDX (cpuid results)               */
/* ===================================================================== */
void SpecialInstructionsHandler::AlterCpuidValues(ADDRINT ip, CONTEXT * ctxt, ADDRINT cur_eip) {
	CHECK_EIP_ADDRESS(cur_eip);
	// Get class instance to access objects
	SpecialInstructionsHandler *classHandler = SpecialInstructionsHandler::getInstance();
	// Get cpuid results (EBX, ECX, EDX)
	ADDRINT _ebx, _ecx, _edx;
	PIN_GetContextRegval(ctxt, REG_GDX, reinterpret_cast<UINT8*>(&_edx));
	PIN_GetContextRegval(ctxt, REG_GBX, reinterpret_cast<UINT8*>(&_ebx));
	PIN_GetContextRegval(ctxt, REG_GCX, reinterpret_cast<UINT8*>(&_ecx));
	// EAX = 1 -> processor info and feature bits in ECX
	if (classHandler->cpuid_eax == 1) {
		UINT32 mask = 0xFFFFFFFFULL;
		_ecx &= (mask >> 1);
	}
	// EAX >= 0x40000000 && EAX <= 0x400000FF -> reserved cpuid levels for Intel and AMD to provide an interface to pass information from the hypervisor to the guest (VM)
	else if (classHandler->cpuid_eax >= 0x40000000 && classHandler->cpuid_eax <= 0x400000FF) {
		// Set the registers to value 0 unsigned long long
		_ecx = 0x0ULL;
		_ebx = 0x0ULL;
		_edx = 0x0ULL;
	}
	// Change cpuid results (EBX, ECX, EDX)
	PIN_SetContextReg(ctxt, REG_GCX, _ecx);
	PIN_SetContextReg(ctxt, REG_GBX, _ebx);
	PIN_SetContextReg(ctxt, REG_GDX, _edx);
}

/* ===================================================================== */
/* Utility function to alter edx (rdtsc result) in case of rdtsc       */
/* ===================================================================== */
ADDRINT SpecialInstructionsHandler::AlterRdtscValueEdx(const CONTEXT* ctxt, ADDRINT cur_eip) {
	// CHECK_EIP_ADDRESS(cur_eip);
	ADDRINT result = 0;
	// Alter the result timer (rdtsc result)
	result = setTimer(ctxt, false);
	// Return changed value (unused for the moment)
	return result;
}

/* ===================================================================== */
/* Utility function to alter eaxrdtsc result) in case of rdtsc           */
/* ===================================================================== */
ADDRINT SpecialInstructionsHandler::AlterRdtscValueEax(const CONTEXT* ctxt, ADDRINT cur_eip) {
	// CHECK_EIP_ADDRESS(cur_eip);
	ADDRINT result = 0;
	// Alter the result timer (rdtsc result)
	result = setTimer(ctxt, true);
	// Return changed value (unused for the moment)
	return result;
}

/* ===================================================================== */
/* Function to handle the int 2d and log the instruction                 */
/* ===================================================================== */
void SpecialInstructionsHandler::Int2dCalled(const CONTEXT* ctxt, ADDRINT cur_eip) {
	CHECK_EIP_ADDRESS(cur_eip);
	// Get class instance to access objects
	ExceptionHandler *eh = ExceptionHandler::getInstance();
	SpecialInstructionsHandler *classHandler = SpecialInstructionsHandler::getInstance();
	// Insert and call exception on int 2d
	eh->setExceptionToExecute(NTSTATUS_STATUS_BREAKPOINT);
}

/* ===================================================================== */
/* Function to handle and log the 'in eax, dx' instruction               */
/* ===================================================================== */
void SpecialInstructionsHandler::InEaxDxCalledAlterValueEbx(CONTEXT* ctxt, ADDRINT cur_eip) {
	CHECK_EIP_ADDRESS(cur_eip);
	// Get class instance to access objects
	SpecialInstructionsHandler *classHandler = SpecialInstructionsHandler::getInstance();
	// Change return value (ebx) of the instruction 'in eax, dx'
	ADDRINT _ebx = 0;
	PIN_SetContextReg(ctxt, REG_GBX, _ebx);
	// TAINT EAX OR EBX
}

/* ===================================================================== */
/* Utility function to alter the timer from the rdtsc results            */
/* ===================================================================== */
ADDRINT SpecialInstructionsHandler::setTimer(const CONTEXT* ctxt, bool isEax) {
	static UINT64 Timer = 0;
	UINT64 result = 0;

	// obtain the registers when the timer is 0, else increment it by 100
	if (Timer == 0) {
		ADDRINT edx = (ADDRINT)PIN_GetContextReg(ctxt, REG_GDX);
		ADDRINT eax = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
		Timer = (UINT64(edx) << 32) | eax;
	}
	else {
		Timer += 100;
	}

	// shift registers to alter the result
	if (isEax) {
		result = (Timer << 32) >> 32;
	}
	else {
		result = (Timer) >> 32;
	}
	// return changed timer (unused for the moment)
	return (ADDRINT)result;
}