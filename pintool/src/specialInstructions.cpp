#include "specialInstructions.h"

/* ============================================================================= */
/* Define macro to taint a register using thread_ctx_ptr and GPR from libdft     */
/* ============================================================================= */
#define TAINT_TAG_REG(ctx, taint_gpr, t0, t1, t2, t3) do { \
tag_t _tags[4] = {t0, t1, t2, t3}; \
thread_ctx_t *thread_ctx = (thread_ctx_t *)PIN_GetContextReg(ctx, thread_ctx_ptr); \
addTaintRegister(thread_ctx, taint_gpr, _tags, true); \
} while (0)

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
	// Get instruction address
	ADDRINT curEip = INS_Address(ins);
	// If "cpuid" instruction (log call with relevant registers and alter values to avoid VM/sandbox detection)
	if (specialInstructionsHandlerInfo->isStrEqualI(INS_Mnemonic(ins), "cpuid") || diassembled_ins.find("cpuid") != std::string::npos) {
		// Insert a pre-call before cpuid to get the EAX register
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
		// Insert a post-call to alter eax and edx registers (rdtsc results) in case of rdtsc instruction (avoid VM/sandbox detection)
		specialInstructionsHandlerInfo->regInit(&regsIn, &regsOut);
		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)SpecialInstructionsHandler::AlterRdtscValues,
			IARG_INST_PTR,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_ADDRINT, curEip,
			IARG_END);
	}
	// if "int 2d" instruction (log and generate exception to avoid VM/sandbox detection)
	else if (specialInstructionsHandlerInfo->isStrEqualI(INS_Mnemonic(ins), "int 0x2d") || diassembled_ins.find("int 0x2d") != std::string::npos) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)SpecialInstructionsHandler::Int2dCalled,
				        IARG_CONTEXT,
						IARG_ADDRINT, curEip,
					    IARG_END);
	}
	// if "in eax, dx" instruction (log and alter values to avoid VMWare detection
	else if (specialInstructionsHandlerInfo->isStrEqualI(INS_Mnemonic(ins), "in eax, dx") || diassembled_ins.find("in eax, dx") != std::string::npos) {
		// Insert a post-call to alter ebx register ('in eax, dx' result) in case of 'in eax, dx' instruction (avoid VMWare detection)
		specialInstructionsHandlerInfo->regInit(&regsIn, &regsOut);
		INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)SpecialInstructionsHandler::InEaxDxCalledAlterValueEbx,
			IARG_PARTIAL_CONTEXT, &regsIn, &regsOut,
			IARG_ADDRINT, curEip,
			IARG_END);

	}
}

/* ===================================================================== */
/* Function to handle the cpuid instruction                              */
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
	// CHECK_EIP_ADDRESS(cur_eip);
	// Get class instance to access objects
	SpecialInstructionsHandler *classHandler = SpecialInstructionsHandler::getInstance();
	// Get cpuid results (EBX, ECX, EDX)
	ADDRINT _ebx, _ecx, _edx;
	PIN_GetContextRegval(ctxt, REG_GBX, reinterpret_cast<UINT8*>(&_ebx));
	PIN_GetContextRegval(ctxt, REG_GCX, reinterpret_cast<UINT8*>(&_ecx));
	PIN_GetContextRegval(ctxt, REG_GDX, reinterpret_cast<UINT8*>(&_edx));
	// EAX = 1 -> processor info and feature bits in ECX
	if (classHandler->cpuid_eax == 1) {
		UINT32 mask = 0xFFFFFFFFULL;
		_ecx &= (mask >> 1);
		//TAINT_TAG_REG(ctxt, GPR_ECX, 1, 1, 1, 1);
	}
	// EAX >= 0x40000000 && EAX <= 0x400000FF -> reserved cpuid levels for Intel and AMD to provide an interface to pass information from the hypervisor to the guest (VM)
	else if (classHandler->cpuid_eax >= 0x40000000 && classHandler->cpuid_eax <= 0x400000FF) {
		// Set the registers to value 0 unsigned long long
		_ebx = 0x0ULL;
		_ecx = 0x0ULL;
		_edx = 0x0ULL;
		/*TAINT_TAG_REG(ctxt, GPR_EBX, 1, 1, 1, 1);
		TAINT_TAG_REG(ctxt, GPR_ECX, 1, 1, 1, 1);
		TAINT_TAG_REG(ctxt, GPR_EDX, 1, 1, 1, 1);*/
	}
	// Change cpuid results (EBX, ECX, EDX)
	PIN_SetContextReg(ctxt, REG_GBX, _ebx);
	PIN_SetContextReg(ctxt, REG_GCX, _ecx);
	PIN_SetContextReg(ctxt, REG_GDX, _edx);
}

/* ===================================================================== */
/* Function to handle the rdtsc instruction                              */
/* ===================================================================== */
void SpecialInstructionsHandler::AlterRdtscValues(ADDRINT ip, CONTEXT * ctxt, ADDRINT cur_eip) {
	CHECK_EIP_ADDRESS(cur_eip);
	// Handle and bypass the instruction
	State::globalState* gs = State::getGlobalState();
	gs->_timeInfo._edx = (gs->_timeInfo._edx_eax & 0xffffffff00000000ULL) >> 32; // most significant 32
	gs->_timeInfo._edx_eax += gs->_timeInfo.sleepMs; //add to result ms of previous sleep call
	gs->_timeInfo._eax = gs->_timeInfo._edx_eax & 0x00000000ffffffffULL; // less significant 32
	gs->_timeInfo._edx_eax += 30;
	gs->_timeInfo.sleepMs = 0;
	PIN_SetContextReg(ctxt, REG_GAX, gs->_timeInfo._eax);
	PIN_SetContextReg(ctxt, REG_GDX, gs->_timeInfo._edx);
	// Taint the registers
	TAINT_TAG_REG(ctxt, GPR_EAX, 1, 1, 1, 1);
	TAINT_TAG_REG(ctxt, GPR_EDX, 1, 1, 1, 1);
}
/* ===================================================================== */
/* Function to handle the int 2d instruction                             */
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
/* Function to handle the 'in eax, dx' instruction                       */
/* ===================================================================== */
void SpecialInstructionsHandler::InEaxDxCalledAlterValueEbx(CONTEXT* ctxt, ADDRINT cur_eip) {
	// CHECK_EIP_ADDRESS(cur_eip);
	// Get class instance to access objects
	SpecialInstructionsHandler *classHandler = SpecialInstructionsHandler::getInstance();
	// Change return value (ebx) of the instruction 'in eax, dx'
	ADDRINT _ebx = 0;
	PIN_SetContextReg(ctxt, REG_GBX, _ebx);
	// Taint the registers
	TAINT_TAG_REG(ctxt, GPR_EBX, 1, 1, 1, 1);
}