#include "pin.H"

#include <string>
#include "libdft_api.h"
#include "tagmap.h"
#include "bridge.h" 
#include "../itree.h"
#include "../state.h"
#include "../disassembler.h"

#define TTINFO(field) thread_ctx->ttinfo.field

#define RTAG thread_ctx->vcpu.gpr
#define R32TAG(RIDX) \
    {RTAG[(RIDX)][0], RTAG[(RIDX)][1], RTAG[(RIDX)][2], RTAG[(RIDX)][3]}

void addTaintRegister(thread_ctx_t *thread_ctx, int gpr, tag_t tags[], bool reset) {
	tag_t src_tag[] = R32TAG(gpr);
	for (UINT32 i = 0; i < 4; ++i) {
		tag_t t = tags[i];
		if (!reset) 
			t |= src_tag[i];
		RTAG[gpr][i] = t;
	}
}

void clearTaintRegister(thread_ctx_t *thread_ctx, int gpr) {
	memset(RTAG[gpr], 0, sizeof(RTAG[gpr]));
}

void getRegisterTaints(thread_ctx_t *thread_ctx, int gpr, tag_t *tags) {
	memcpy(tags, RTAG[gpr], sizeof(RTAG[gpr]));
}

void getMemoryTaints(ADDRINT addr, tag_t* tags, UINT32 size) {
	for (UINT32 i = 0; i < size; ++i) {
		tags[i] = tagmap_getb(addr + i);
	}
}

/*
Function used to log the hook name + xor value when tainting memory
*/
void logHookId(CONTEXT* ctx, std::string hook_name, ADDRINT start_addr, UINT32 size) {
	thread_ctx_t* thread_ctx = (thread_ctx_t*)PIN_GetContextReg(ctx, thread_ctx_ptr);
	pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
	ADDRINT hash_context = (*(thread_ctx->ttinfo.shadowStackThread->callStack))[thread_ctx->ttinfo.shadowStackThread->callStackTop - 1].hashID;

	ADDRINT end_addr = (ADDRINT)(start_addr + size);
	logTaintedMemoryArea(tdata, "- %s 0x%08x 0x%08x 0x%08x\n", hook_name.c_str(), hash_context, start_addr, end_addr);
}


void addTaintMemory(CONTEXT* ctx, ADDRINT addr, UINT32 size, tag_t tag, bool reset, std::string apiName) {
	// Check if the program is 64-bit
	ASSERT(sizeof(ADDRINT) == sizeof(UINT32), "64-bit mode not supported yet");
	// Check if the pointer is 0 or NULL (check address)
	if (addr == 0 || addr == NULL)
		return;
	// Log the tainted memory area
	std::stringstream taintMemoryArea;
	ADDRINT endMemoryArea = (ADDRINT)addr + size;
	thread_ctx_t* thread_ctx = (thread_ctx_t*)PIN_GetContextReg(ctx, thread_ctx_ptr);
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
	logTaintedMemoryArea(tdata, "0x%08x 0x%08x [%d]\n", addr, endMemoryArea, tag);
	// Taint the memory addresses
	std::cerr << "Tainting addresses " << addr << " to " << addr + size << " ("+apiName+")" << std::endl;
	for (UINT32 i = 0; i < size; ++i) {
		tag_t t = tag;
		if (!reset) t |= tagmap_getb(addr + i);
		tagmap_setb_with_tag(addr + i, t);
	}
}

void clearTaintMemory(ADDRINT addr, UINT32 size) {
	ASSERT(sizeof(ADDRINT) == sizeof(UINT32), "64-bit mode not supported yet");
	for (UINT32 i = 0; i < size; ++i) {
		tag_t t = 0;
		tagmap_setb_with_tag(addr + i, t);
	}
}


/*
Check which operands are tainted using the thread-context variables TTINFO(firstOperandTainted) and TTINFO(secondOperandTainted)
return values:
    0 = no tainted operands (e.g. cpuid)
	1 = only first operand tainted
	2 = only second operand tainted
	3 = both operands tainted
*/
int checkWhichOperandsAreTainted(thread_ctx_t *thread_ctx) {
	if (TTINFO(firstOperandTainted) && TTINFO(secondOperandTainted)) {
		return 3;
	}
	else if (TTINFO(firstOperandTainted) && !TTINFO(secondOperandTainted)) {
		return 1;
	}
	else if(!TTINFO(firstOperandTainted) && TTINFO(secondOperandTainted)){
		return 2;
	}
	else {
		return 0;
	}
}

// Search the nearest address in the export map of the current DLL to find which system API is tainted
W::DWORD searchNearestValueExportMap(std::map<W::DWORD, std::string> exportsMap, ADDRINT addr) {
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


static void PIN_FAST_ANALYSIS_CALL
detected_call(thread_ctx_t* thread_ctx, ADDRINT callTargetAddress, ADDRINT retTargetAddress, ADDRINT currentSPAddress, ADDRINT ipAddress) {
	callStackPush(thread_ctx->ttinfo.shadowStackThread, callTargetAddress, retTargetAddress, currentSPAddress);
}


static void PIN_FAST_ANALYSIS_CALL
detected_ret(thread_ctx_t* thread_ctx, ADDRINT retTargetAddress, ADDRINT currentSPAddress, ADDRINT ip) {
	callStackPop(thread_ctx->ttinfo.shadowStackThread, retTargetAddress, currentSPAddress);
}

/*
Analysis function for conditional jump instructions. Here, offendingInstruction can be the
possible instruction which affected this branch execution.

@ipAddress
@isBranchTaken: bool which tells if the instruction effectively jumps or not
@targetAddress: target address of the jump
*/
static void PIN_FAST_ANALYSIS_CALL 
condBranchAnalysis(thread_ctx_t *thread_ctx, ADDRINT addr, ADDRINT size, BOOL isBranchTaken, ADDRINT targetAddress, ADDRINT spAddress) {
	// Disassemble instruction
	std::string instruction = disassembleInstruction(addr, size);
	// Access to global objects
	State::globalState* gs = State::getGlobalState();
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
	std::string ins = (instruction).substr(0, (instruction).find(" "));
	std::string alertType = "condbranch";
	// Check if we have an offending instruction and if program code
	if (TTINFO(offendingInstruction) != 0 && itree_search(gs->dllRangeITree, addr) == NULL) {
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x 0x%08x %s\n", alertType.c_str(), addr, targetAddress, ins.c_str());
		logInstruction(tdata, "%s; 0x%08x 0x%08x %s\n", alertType.c_str(), addr, targetAddress, instruction.c_str());
		// Reset the offending instruction
		TTINFO(offendingInstruction) = 0;
	}
}

static void PIN_FAST_ANALYSIS_CALL 
 reg_imm_alert(thread_ctx_t* thread_ctx, ADDRINT addr, ADDRINT size, REG reg, UINT32 regIdx, ADDRINT immValue, UINT32 lengthBits, ADDRINT spAddress) {
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		INT32 length = (INT32)lengthBits;
		// Disassemble instruction
		std::string instruction = disassembleInstruction(addr, size);
		// Access to global objects
		State::globalState* gs = State::getGlobalState();
		pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
		std::string ins = (instruction).substr(0, (instruction).find(" "));
		std::string alertType = "reg-imm";
		// If the instruction is different from a mov, save it as a offending instruction (possible instruction which affected a branch execution)
		if (strcmp("mov", ins.c_str())) {
			TTINFO(offendingInstruction) = addr;
		}
		else {
			TTINFO(offendingInstruction) = 0;
		}
		// See which operands are tainted and which are not
		int operandsTainted = checkWhichOperandsAreTainted(thread_ctx);
		// If system code, log the tainted instruction one time
		itreenode_t* currentNode = itree_search(gs->dllRangeITree, addr);
		if (currentNode != NULL) {
			if (TTINFO(logTaintedSystemCode)) {
				TTINFO(logTaintedSystemCode) = 0;
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						std::map<W::DWORD, std::string> exportsMap = gs->dllExports[i].exports;
						W::DWORD nearestAddress = searchNearestValueExportMap(exportsMap, addr);
						// Log the tainted instruction using a buffered logger
						alertType = "system_reg-imm";
						logAlert(tdata, "%s; 0x%08x [%d] %s %s %d %d %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), REG_StringShort(reg).c_str(), immValue, operandsTainted,
							(exportsMap)[nearestAddress].c_str());
						logInstruction(tdata, "%s; 0x%08x [%d] %s %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str(), (exportsMap)[nearestAddress].c_str());
					}
				}
			}
			goto END;
		}
		else {
			TTINFO(logTaintedSystemCode) = 1;
		}
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x [%d] %s %s %d %d\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), REG_StringShort(reg).c_str(), immValue, operandsTainted);
		logInstruction(tdata, "%s; 0x%08x [%d] %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str());
	}
END:
	// Clear thread context from the taint
	TTINFO(tainted) = 0;
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL
mem_imm_alert(thread_ctx_t* thread_ctx, ADDRINT addr, ADDRINT size, ADDRINT memAddress, UINT32 readSize, ADDRINT immValue, UINT32 lengthBits, ADDRINT spAddress) {
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		INT32 length = (INT32)lengthBits;
		// Disassemble instrution
		std::string instruction = disassembleInstruction(addr, size);
		// Access to global objects
		State::globalState* gs = State::getGlobalState();
		pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
		std::string ins = (instruction).substr(0, (instruction).find(" "));
		std::string alertType = "mem-imm";
		//Extracting memory content
		ADDRINT memContent;
		memset(&memContent, 0, sizeof(ADDRINT));
		PIN_SafeCopy(&memContent, (ADDRINT*)memAddress, (readSize < sizeof(ADDRINT) ? readSize : sizeof(ADDRINT)));
		// If the instruction is different from a mov, save it as a offending instruction (possible instruction which affected a branch execution)
		if (strcmp("mov", ins.c_str())) {
			TTINFO(offendingInstruction) = addr;
		}
		else {
			TTINFO(offendingInstruction) = 0;
		}
		// See which operands are tainted and which are not
		int operandsTainted = checkWhichOperandsAreTainted(thread_ctx);
		// If system code, log the tainted instruction one time
		itreenode_t* currentNode = itree_search(gs->dllRangeITree, addr);
		if (currentNode != NULL) {
			if (TTINFO(logTaintedSystemCode)) {
				TTINFO(logTaintedSystemCode) = 0;
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						std::map<W::DWORD, std::string> exportsMap = gs->dllExports[i].exports;
						W::DWORD nearestAddress = searchNearestValueExportMap(exportsMap, addr);
						// Log the tainted instruction using a buffered logger
						alertType = "system_mem-imm";
						logAlert(tdata, "%s; 0x%08x [%d] %s 0x%08x(%d) %d %d %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), memAddress, readSize,
							immValue, operandsTainted, (exportsMap)[nearestAddress].c_str());
						logInstruction(tdata, "%s; 0x%08x [%d] %s %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str(), (exportsMap)[nearestAddress].c_str());
					}
				}
			}
			goto END;
		}
		else {
			TTINFO(logTaintedSystemCode) = 1;
		}
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x [%d] %s 0x%08x(%d) %d %d\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), memAddress, readSize, immValue, operandsTainted);
		logInstruction(tdata, "%s; 0x%08x [%d] %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str());
	}
END:
	// Clear thread context from the taint
	TTINFO(tainted) = 0;
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL
reg_reg_alert(thread_ctx_t* thread_ctx, ADDRINT addr, ADDRINT size, REG reg_op0, UINT32 regIdx_op0, REG reg_op1, UINT32 regIdx_op1, ADDRINT spAddress) {
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		// Disassemble instruction
		std::string instruction = disassembleInstruction(addr, size);
		// Access to global objects
		State::globalState* gs = State::getGlobalState();
		pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
		std::string ins = (instruction).substr(0, (instruction).find(" "));
		std::string alertType = "reg-reg";
		// If the instruction is different from a mov, save it as a offending instruction (possible instruction which affected a branch execution)
		if (strcmp("mov", ins.c_str())) {
			TTINFO(offendingInstruction) = addr;
		}
		else {
			TTINFO(offendingInstruction) = 0;
		}
		// See which operands are tainted and which are not
		int operandsTainted = checkWhichOperandsAreTainted(thread_ctx);
		// If system code, log the tainted instruction one time
		itreenode_t* currentNode = itree_search(gs->dllRangeITree, addr);
		if (currentNode != NULL) {
			if (TTINFO(logTaintedSystemCode)) {
				TTINFO(logTaintedSystemCode) = 0;
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						std::map<W::DWORD, std::string> exportsMap = gs->dllExports[i].exports;
						W::DWORD nearestAddress = searchNearestValueExportMap(exportsMap, addr);
						// Log the tainted instruction using a buffered logger
						alertType = "system_reg-reg";
						logAlert(tdata, "%s; 0x%08x [%d] %s %s %s %d %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), REG_StringShort(reg_op0).c_str(), REG_StringShort(reg_op1).c_str(), 
							operandsTainted, (exportsMap)[nearestAddress].c_str());
						logInstruction(tdata, "%s; 0x%08x [%d] %s %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str(), (exportsMap)[nearestAddress].c_str());
					}
				}
			}
			goto END;
		}
		else {
			TTINFO(logTaintedSystemCode) = 1;
		}
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x [%d] %s %s %s %d\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), REG_StringShort(reg_op0).c_str(), REG_StringShort(reg_op1).c_str(), operandsTainted);
		logInstruction(tdata, "%s; 0x%08x [%d] %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str());
}
END:
	// Clear thread context from the taint
	TTINFO(tainted) = 0;
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL
reg_mem_alert(thread_ctx_t* thread_ctx, ADDRINT addr, ADDRINT size, REG reg0, UINT32 regIdx_op0, ADDRINT memAddress, UINT32 readSize, ADDRINT spAddress) {
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		// Disassemble instruction
		std::string instruction = disassembleInstruction(addr, size);
		// Access to global objects
		State::globalState* gs = State::getGlobalState();
		pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
		std::string ins = (instruction).substr(0, (instruction).find(" "));
		std::string alertType = "reg-mem";
		// Extracting memory content
		ADDRINT memContent; 
		memset(&memContent, 0, sizeof(ADDRINT));
		PIN_SafeCopy(&memContent, (ADDRINT*)memAddress, (readSize < sizeof(ADDRINT) ? readSize : sizeof(ADDRINT)));
		// If the instruction is different from a mov, save it as a offending instruction (possible instruction which affected a branch execution)
		if (strcmp("mov", ins.c_str())) {
			TTINFO(offendingInstruction) = addr;
		}
		else {
			TTINFO(offendingInstruction) = 0;
		}
		// See which operands are tainted and which are not
		int operandsTainted = checkWhichOperandsAreTainted(thread_ctx);
		// If system code, log the tainted instruction one time
		itreenode_t* currentNode = itree_search(gs->dllRangeITree, addr);
		if (currentNode != NULL) {
			if (TTINFO(logTaintedSystemCode)) {
				TTINFO(logTaintedSystemCode) = 0;
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						std::map<W::DWORD, std::string> exportsMap = gs->dllExports[i].exports;
						W::DWORD nearestAddress = searchNearestValueExportMap(exportsMap, addr);
						// Log the tainted instruction using a buffered logger
						alertType = "system_reg-mem";
						logAlert(tdata, "%s; 0x%08x [%d] %s %s 0x%08x(%d) %d %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), REG_StringShort(reg0).c_str(), 
							memAddress, readSize, operandsTainted, (exportsMap)[nearestAddress].c_str());
						logInstruction(tdata, "%s; 0x%08x [%d] %s %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str(), (exportsMap)[nearestAddress].c_str());
					}
				}
			}
			goto END;
		}
		else {
			TTINFO(logTaintedSystemCode) = 1;
		}
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x [%d] %s %s 0x%08x(%d) %d\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), REG_StringShort(reg0).c_str(), memAddress, readSize, operandsTainted);
		logInstruction(tdata, "%s; 0x%08x [%d] %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str());
	}
END:
	// Clear thread context from the taint
	TTINFO(tainted) = 0;
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL
mem_reg_alert(thread_ctx_t* thread_ctx, ADDRINT addr, ADDRINT size, ADDRINT memAddress, UINT32 readSize, REG reg1, UINT32 regIdx_op1, ADDRINT spAddress) {
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		// Disassemble instruction
		std::string instruction = disassembleInstruction(addr, size);
		// Access to global objects
		State::globalState* gs = State::getGlobalState();
		pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
		std::string ins = (instruction).substr(0, (instruction).find(" "));
		std::string alertType = "mem-reg";
		//Extracting memory content
		ADDRINT memContent; 
		memset(&memContent, 0, sizeof(ADDRINT));
		PIN_SafeCopy(&memContent, (ADDRINT*)memAddress, (readSize < sizeof(ADDRINT) ? readSize : sizeof(ADDRINT)));
		// If the instruction is different from a mov, save it as a offending instruction (possible instruction which affected a branch execution)
		if (strcmp("mov", ins.c_str())) {
			TTINFO(offendingInstruction) = addr;
		}
		else {
			TTINFO(offendingInstruction) = 0;
		}
		// See which operands are tainted and which are not
		int operandsTainted = checkWhichOperandsAreTainted(thread_ctx);
		// If system code, log the tainted instruction one time
		itreenode_t* currentNode = itree_search(gs->dllRangeITree, addr);
		if (currentNode != NULL) {
			if (TTINFO(logTaintedSystemCode)) {
				TTINFO(logTaintedSystemCode) = 0;
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						std::map<W::DWORD, std::string> exportsMap = gs->dllExports[i].exports;
						W::DWORD nearestAddress = searchNearestValueExportMap(exportsMap, addr);
						// Log the tainted instruction using a buffered logger
						alertType = "system_mem-reg";
						logAlert(tdata, "%s; 0x%08x [%d] %s 0x%08x(%d) %s %d %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), memAddress, readSize,
							REG_StringShort(reg1).c_str(), operandsTainted, (exportsMap)[nearestAddress].c_str());
						logInstruction(tdata, "%s; 0x%08x [%d] %s %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str(), (exportsMap)[nearestAddress].c_str());
					}
				}
			}
			goto END;
		}
		else {
			TTINFO(logTaintedSystemCode) = 1;
		}
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x [%d] %s 0x%08x(%d) %s %d\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), memAddress, readSize, REG_StringShort(reg1).c_str(), operandsTainted);
		logInstruction(tdata, "%s; 0x%08x [%d] %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str());
	}
END:
	// Clear thread context from the taint
	TTINFO(tainted) = 0;
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL
reg_alert(thread_ctx_t* thread_ctx, ADDRINT addr, ADDRINT size, REG reg0, UINT32 regIdx_op0, ADDRINT spAddress) {
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		// Disassemble instruction
		std::string instruction = disassembleInstruction(addr, size);
		// Access to global objects
		State::globalState* gs = State::getGlobalState();
		pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
		std::string ins = (instruction).substr(0, (instruction).find(" "));
		std::string alertType = "reg";
		// If the instruction is different from a mov, save it as a offending instruction (possible instruction which affected a branch execution)
		if (strcmp("mov", ins.c_str())) {
			TTINFO(offendingInstruction) = addr;
		}
		else {
			TTINFO(offendingInstruction) = 0;
		}
		// See which operands are tainted and which are not
		int operandsTainted = checkWhichOperandsAreTainted(thread_ctx);
		// If system code, log the tainted instruction one time
		itreenode_t* currentNode = itree_search(gs->dllRangeITree, addr);
		if (currentNode != NULL) {
			if (TTINFO(logTaintedSystemCode)) {
				TTINFO(logTaintedSystemCode) = 0;
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						std::map<W::DWORD, std::string> exportsMap = gs->dllExports[i].exports;
						W::DWORD nearestAddress = searchNearestValueExportMap(exportsMap, addr);
						// Log the tainted instruction using a buffered logger
						alertType = "system_reg";
						logAlert(tdata, "%s; 0x%08x [%d] %s %s %s %d %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), REG_StringShort(reg0).c_str(), OP_NA,
							operandsTainted, (exportsMap)[nearestAddress].c_str());
						logInstruction(tdata, "%s; 0x%08x [%d] %s %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str(), (exportsMap)[nearestAddress].c_str());
					}
				}
			}
			goto END;
		}
		else {
			TTINFO(logTaintedSystemCode) = 1;
		}
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x [%d] %s %s %s %d\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), REG_StringShort(reg0).c_str(), OP_NA, operandsTainted);
		logInstruction(tdata, "%s; 0x%08x [%d] %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str());
	}
END:
	// Clear thread context from the taint
	TTINFO(tainted) = 0;
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL
mem_alert(thread_ctx_t* thread_ctx, ADDRINT addr, ADDRINT size, ADDRINT memAddress, UINT32 readSize, ADDRINT spAddress) {
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		// Disassemble instruction
		std::string instruction = disassembleInstruction(addr, size);
		// Access to global objects
		State::globalState* gs = State::getGlobalState();
		pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
		std::string ins = (instruction).substr(0, (instruction).find(" "));
		std::string alertType = "mem";
		//Extracting memory content
		ADDRINT memContent;
		memset(&memContent, 0, sizeof(ADDRINT));
		PIN_SafeCopy(&memContent, (ADDRINT*)memAddress, (readSize < sizeof(ADDRINT) ? readSize : sizeof(ADDRINT)));
		// If the instruction is different from a mov, save it as a offending instruction (possible instruction which affected a branch execution)
		if (strcmp("mov", ins.c_str())) {
			TTINFO(offendingInstruction) = addr;
		}
		else {
			TTINFO(offendingInstruction) = 0;
		}
		// See which operands are tainted and which are not
		int operandsTainted = checkWhichOperandsAreTainted(thread_ctx);
		// If system code, log the tainted instruction one time
		itreenode_t* currentNode = itree_search(gs->dllRangeITree, addr);
		if (currentNode != NULL) {
			if (TTINFO(logTaintedSystemCode)) {
				TTINFO(logTaintedSystemCode) = 0;
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						std::map<W::DWORD, std::string> exportsMap = gs->dllExports[i].exports;
						W::DWORD nearestAddress = searchNearestValueExportMap(exportsMap, addr);
						// Log the tainted instruction using a buffered logger
						alertType = "system_mem";
						logAlert(tdata, "%s; 0x%08x [%d] %s 0x%08x(%d) %s %d %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), memAddress, readSize,
							OP_NA, operandsTainted, (exportsMap)[nearestAddress].c_str());
						logInstruction(tdata, "%s; 0x%08x [%d] %s %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str(), (exportsMap)[nearestAddress].c_str());
					}
				}
			}
			goto END;
		}
		else {
			TTINFO(logTaintedSystemCode) = 1;
		}
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x [%d] %s 0x%08x(%d) %s %d\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), memAddress, readSize, OP_NA, operandsTainted);
		logInstruction(tdata, "%s; 0x%08x [%d] %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str());
	}
END:
	// Clear thread context from the taint
	TTINFO(tainted) = 0;
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL 
alert(thread_ctx_t *thread_ctx, ADDRINT addr, ADDRINT size) {
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		// Disassemble instruction
		std::string instruction = disassembleInstruction(addr, size);
		// Access to global objects
		State::globalState* gs = State::getGlobalState();
		pintool_tls* tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, TTINFO(tid)));
		std::string ins = (instruction).substr(0, (instruction).find(" "));
		std::string alertType = "generic";
		// If the instruction is different from a mov, save it as a offending instruction (possible instruction which affected a branch execution)
		if (strcmp("mov", ins.c_str())) {
			TTINFO(offendingInstruction) = addr;
		}
		else {
			TTINFO(offendingInstruction) = 0;
		}
		// See which operands are tainted and which are not
		int operandsTainted = checkWhichOperandsAreTainted(thread_ctx);
		// If system code, log the tainted instruction one time
		itreenode_t* currentNode = itree_search(gs->dllRangeITree, addr);
		if (currentNode != NULL) {
			if (TTINFO(logTaintedSystemCode)) {
				TTINFO(logTaintedSystemCode) = 0;
				for (int i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						std::map<W::DWORD, std::string> exportsMap = gs->dllExports[i].exports;
						W::DWORD nearestAddress = searchNearestValueExportMap(exportsMap, addr);
						// Log the tainted instruction using a buffered logger
						alertType = "system_generic";
						logAlert(tdata, "%s; 0x%08x [%d] %s %s %s %d %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), OP_NA, OP_NA, operandsTainted,
							(exportsMap)[nearestAddress].c_str());
						logInstruction(tdata, "%s; 0x%08x [%d] %s %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str(), (exportsMap)[nearestAddress].c_str());
					}
				}
			}
			goto END;
		}
		else {
			TTINFO(logTaintedSystemCode) = 1;
		}
		// Log the tainted instruction using a buffered logger
		logAlert(tdata, "%s; 0x%08x [%d] %s %s %s %d\n", alertType.c_str(), addr, (int)TTINFO(tainted), ins.c_str(), OP_NA, OP_NA, operandsTainted);
		logInstruction(tdata, "%s; 0x%08x [%d] %s\n", alertType.c_str(), addr, (int)TTINFO(tainted), instruction.c_str());
	}
END:
	// Clear thread context from the taint
	TTINFO(tainted) = 0;
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL assert_reg32(thread_ctx_t *thread_ctx, UINT32 reg, UINT32 opidx) {
	tag_t taintResult = thread_ctx->vcpu.gpr[reg][0] | thread_ctx->vcpu.gpr[reg][1] | thread_ctx->vcpu.gpr[reg][2] | thread_ctx->vcpu.gpr[reg][3];
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_reg16(thread_ctx_t *thread_ctx, UINT32 reg, UINT32 opidx) {
	tag_t taintResult = thread_ctx->vcpu.gpr[reg][0] | thread_ctx->vcpu.gpr[reg][1];
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_reg8(thread_ctx_t *thread_ctx, UINT32 reg, UINT32 opidx) {
	tag_t taintResult = thread_ctx->vcpu.gpr[reg][0];
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_mem256(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 opidx) {
	tag_t taintResult = tagmap_getl(addr) | tagmap_getl(addr + 4) | tagmap_getl(addr + 8) | tagmap_getl(addr + 12) |
					    tagmap_getl(addr + 16) | tagmap_getl(addr + 20) |
						tagmap_getl(addr + 24) | tagmap_getl(addr + 28);
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_mem128(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 opidx) {
	tag_t taintResult = tagmap_getl(addr) | tagmap_getl(addr + 4) | tagmap_getl(addr + 8) | tagmap_getl(addr + 12);
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_mem64(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 opidx) {
	tag_t taintResult = tagmap_getl(addr) | tagmap_getl(addr + 4);
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_mem32(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 opidx) {
	tag_t taintResult = tagmap_getl(addr);
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_mem16(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 opidx) {
	tag_t taintResult = tagmap_getw(addr);
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_mem8(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 opidx) {
	tag_t taintResult = tagmap_getb(addr);
	TTINFO(tainted) |= taintResult;

	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

static void PIN_FAST_ANALYSIS_CALL assert_mem_generic(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 size, UINT32 opidx) {
	ASSERT(size % 4 == 0, "Unaligned memory access?");
	tag_t taintResult = 0;
	for (UINT32 i = 0; i < size / 4; i++) {
		taintResult |= tagmap_getl(addr + 4 * i);
		TTINFO(tainted) |= tagmap_getl(addr + 4 * i);
	}
	// Check how many operands are tainted
	if (TTINFO(tainted) && ((int)taintResult) != 0) {
		if (opidx == 0) {
			TTINFO(firstOperandTainted) = 1;
		}
		else if (opidx == 1) {
			TTINFO(secondOperandTainted) = 1;
		}
	}
}

void instrumentForTaintCheck(INS ins) {
	// Initialize instruction operands and instruction opcode
	REG reg_op0, reg_op1;
	ADDRINT size = INS_Size(ins);

	// Sanity check for unexpected instructions
	if ((xed_iclass_enum_t)INS_Opcode(ins) <= XED_ICLASS_INVALID || (xed_iclass_enum_t)INS_Opcode(ins) >= XED_ICLASS_LAST) {
		std::cerr << "Unexpected instruction during taint check!" << std::endl;
		return;
	}

	// Instrument call instructions for call stack insertion
	if (INS_IsCall(ins)) {
		if (INS_IsDirectCall(ins)) {
			INS_InsertCall(
				ins,
				IPOINT_BEFORE,
				(AFUNPTR)detected_call,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_ADDRINT, INS_DirectBranchOrCallTargetAddress(ins), // Target address of call
				IARG_ADDRINT, INS_NextAddress(ins), // Next address of call -> return address of the call
				IARG_REG_VALUE, REG_STACK_PTR, // SP before ret executed
				IARG_ADDRINT, INS_Address(ins), // Address of the instruction
				IARG_END);
		}
		else {
			INS_InsertCall(
				ins,
				IPOINT_BEFORE,
				(AFUNPTR)detected_call,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_BRANCH_TARGET_ADDR,
				IARG_ADDRINT, INS_NextAddress(ins),
				IARG_REG_VALUE, REG_STACK_PTR, // SP before ret executed
				IARG_ADDRINT, INS_Address(ins),
				IARG_END);
		}
	}

	// Instrument ret instructions for shadow call stack deletion
	if (INS_IsRet(ins)) {
		INS_InsertCall(
			ins,
			IPOINT_BEFORE,
			(AFUNPTR)detected_ret,
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, thread_ctx_ptr,
			IARG_BRANCH_TARGET_ADDR, // Target address of ret
			IARG_REG_VALUE, REG_STACK_PTR, // SP before ret execution
			IARG_ADDRINT, INS_Address(ins), // Address of the instruction
			IARG_END);
	}

	// Instrument conditional jump instructions for control flow checks
	if (INS_Category(ins) == XED_CATEGORY_COND_BR) {
		INS_InsertCall(
			ins,
			IPOINT_BEFORE,
			(AFUNPTR)condBranchAnalysis,
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, thread_ctx_ptr,
			IARG_INST_PTR, // ip of the instruction
			IARG_ADDRINT, size, // instruction size
			IARG_BRANCH_TAKEN,
			IARG_BRANCH_TARGET_ADDR, // target of conditional jump
			IARG_REG_VALUE, REG_STACK_PTR, // SP before ins is executed
			IARG_END);
	}

	// The instruction does not have read operands
	if (INS_MaxNumRRegs(ins) == 0) 
		return; 

	// Get instruction operands
	UINT32 operands = INS_OperandCount(ins);

	// Iterate over registers
	for (UINT32 opIdx = 0; opIdx < operands; ++opIdx) {
		if (INS_OperandIsReg(ins, opIdx) && INS_OperandRead(ins, opIdx)) {
			REG reg = INS_OperandReg(ins, opIdx);
			if (REG_is_gr32(reg)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg32,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_UINT32,
					REG32_INDX(reg),
					IARG_UINT32, opIdx,
					IARG_END);
			}
			else if (REG_is_gr16(reg)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg16,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_UINT32,
					REG16_INDX(reg),
					IARG_UINT32, opIdx,
					IARG_END);
			}
			else if (REG_is_gr8(reg)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_reg8,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_UINT32,
					REG8_INDX(reg),
					IARG_UINT32, opIdx,
					IARG_END);
			}
		}
	}

	if (!INS_IsMemoryRead(ins)) goto end;

	// Iterate over memory operands
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOpIdx = 0; memOpIdx < memOperands; memOpIdx++) {
		if (INS_MemoryOperandIsRead(ins, memOpIdx)) {
			USIZE opSize = INS_MemoryOperandSize(ins, memOpIdx);
			AFUNPTR assert_mem = NULL;
			UINT32 myOpIdx;
			switch (opSize) {
			case 32:
				assert_mem = (AFUNPTR)assert_mem256;
				if (!INS_OperandIsMemory(ins, 0)) {
					myOpIdx = 1;
				}
				else {
					myOpIdx = memOpIdx;
				}
				break;
			case 16:
				assert_mem = (AFUNPTR)assert_mem128;
				if (!INS_OperandIsMemory(ins, 0)) {
					myOpIdx = 1;
				}
				else {
					myOpIdx = memOpIdx;
				}
				break;
			case 8:
				assert_mem = (AFUNPTR)assert_mem64;
				if (!INS_OperandIsMemory(ins, 0)) {
					myOpIdx = 1;
				}
				else {
					myOpIdx = memOpIdx;
				}
				break;
			case 4:
				assert_mem = (AFUNPTR)assert_mem32;
				if (!INS_OperandIsMemory(ins, 0)) {
					myOpIdx = 1;
				}
				else {
					myOpIdx = memOpIdx;
				}
				break;
			case 2:
				assert_mem = (AFUNPTR)assert_mem16;
				if (!INS_OperandIsMemory(ins, 0)) {
					myOpIdx = 1;
				}
				else {
					myOpIdx = memOpIdx;
				}
				break;
			case 1:
				assert_mem = (AFUNPTR)assert_mem8;
				if (!INS_OperandIsMemory(ins, 0)) {
					myOpIdx = 1;
				}
				else {
					myOpIdx = memOpIdx;
				}
				break;
			default:
				std::cerr << "Unknown memory read size: " << opSize << std::endl;
			}
			if (assert_mem != NULL) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_MEMORYOP_EA,
					memOpIdx,
					IARG_UINT32,
					myOpIdx, // Added to understand which operand we are talking about when assert is issued 
					IARG_END);
			}
			else {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)assert_mem_generic,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE,
					thread_ctx_ptr,
					IARG_MEMORYOP_EA,
					memOpIdx,
					IARG_UINT32,
					opSize,
					IARG_UINT32,
					myOpIdx, // Added to understand which operand we are talking about when assert is issued 
					IARG_END);
			}
		}
	}

end:
	/*Different cases of immediate instructions:
		- reg_8 imm
		- reg_16 imm
		- reg_32 imm
		- mem_8 imm  
		- mem_16 imm 
		- mem_32 imm 
	*/
	if (operands > 1 && INS_OperandIsImmediate(ins, OP_1)) {
		ADDRINT immValue = INS_OperandImmediate(ins, OP_1);
		// Get length information
		xed_decoded_inst_t* xedd = INS_XedDec(ins);
		INT32 length_bits = xed_decoded_inst_operand_length_bits(xedd, OP_1);

		// If the first operand is a reg, extract the operand and alert
		if (INS_OperandIsReg(ins, OP_0)) {
			reg_op0 = INS_OperandReg(ins, OP_0);
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)reg_imm_alert,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, // Instruction pointer
				IARG_ADDRINT, size, // Instruction size
				IARG_PTR, reg_op0, // Content of register operand 0
				IARG_UINT32, REG32_INDX(reg_op0), // Index of reg (need a switch case in analysis func to understand which reg it is)
				IARG_ADDRINT, immValue, // Instruction immediate value
				IARG_UINT32, length_bits, // Length of written bits (remember to cast it to INT32)
				IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
				IARG_END);
		}
		else {
			if (INS_IsMemoryWrite(ins)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)mem_imm_alert,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_INST_PTR, // Instruction pointer
					IARG_ADDRINT, size, // Instruction size
					IARG_MEMORYWRITE_EA, // Memory address
					IARG_MEMORYWRITE_SIZE,
					IARG_ADDRINT, immValue, // Instruction immediate value
					IARG_UINT32, length_bits, // Length of written bits (remember to cast it to INT32)
					IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
					IARG_END);
			}
			else if (INS_IsMemoryRead(ins)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)mem_imm_alert,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, thread_ctx_ptr,
					IARG_INST_PTR, // Instruction pointer
					IARG_ADDRINT, size, // Instruction size
					IARG_MEMORYREAD_EA, // Memory address
					IARG_MEMORYREAD_SIZE,
					IARG_ADDRINT, immValue, // Instruction immediate value
					IARG_UINT32, length_bits, // Length of written bits (remember to cast it to INT32)
					IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
					IARG_END);
			}
		}
	}
	// Both operands are registers (reg_reg)
	else if (operands > 1 && INS_MemoryOperandCount(ins) == 0) {
		reg_op0 = INS_OperandReg(ins, 0);
		reg_op1 = INS_OperandReg(ins, 1);
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)reg_reg_alert,
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, thread_ctx_ptr,
			IARG_INST_PTR, // Instruction pointer
			IARG_ADDRINT, size, // Instruction size
			IARG_PTR, reg_op0, // First register object
			IARG_UINT32, REG32_INDX(reg_op0), // Index of first register (need a switch case in analysis func to understand which reg it is)
			IARG_PTR, reg_op1, // Second register object
			IARG_UINT32, REG32_INDX(reg_op1), // Index of second register (need a switch case in analysis func to understand which reg it is)
			IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
			IARG_END);
	}
	// Operand on the right is memory (reg_mem)
	else if (operands > 1 && INS_OperandIsMemory(ins, OP_1)) {
		reg_op0 = INS_OperandReg(ins, OP_0);

		if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)reg_mem_alert,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, // Instruction pointer
				IARG_ADDRINT, size, // Instruction size
				IARG_PTR, reg_op0, // Content of first register
				IARG_UINT32, REG8_INDX(reg_op0), // Index of first register (need a switch case in analysis func to understand which reg it is)
				IARG_MEMORYREAD_EA, // Address of the memory operand
				IARG_MEMORYREAD_SIZE,
				IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
				IARG_END);
		}
	}
	// Operand on the left is memory (mem_reg)
	else if(operands > 1 && INS_OperandIsMemory(ins, OP_0) && INS_OperandIsReg(ins, OP_1)) {
		reg_op1 = INS_OperandReg(ins, OP_1);

		if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)mem_reg_alert,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, // Instruction pointer
				IARG_ADDRINT, size, // Instruction size
				IARG_MEMORYREAD_EA, // Address of memory operand
				IARG_MEMORYREAD_SIZE,
				IARG_PTR, reg_op1, // Register object
				IARG_UINT32, REG32_INDX(reg_op1), // Index of register (need a switch case in analysis func to understand which reg it is)
				IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
				IARG_END);
		}
		else if (INS_IsMemoryWrite(ins)) {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)mem_reg_alert,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, // Instruction pointer
				IARG_ADDRINT, size, // Instruction size
				IARG_MEMORYWRITE_EA, // Address of memory operand
				IARG_MEMORYWRITE_SIZE,
				IARG_PTR, reg_op1, // Register object
				IARG_UINT32, REG32_INDX(reg_op1), // Index of register (need a switch case in analysis func to understand which reg it is)
				IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
				IARG_END);
		}
	}
	// Instruction with single register (e.g. push)
	else if (INS_OperandIsReg(ins, OP_0)) {
		reg_op0 = INS_OperandReg(ins, OP_0);
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)reg_alert,
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, thread_ctx_ptr,
			IARG_INST_PTR, // Instruction pointer
			IARG_ADDRINT, size, // Instruction size
			IARG_PTR, reg_op0, // Register object
			IARG_UINT32, REG32_INDX(reg_op0), // Index of register (need a switch case in analysis func to understand which reg it is)
			IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
			IARG_END);
	}
	// Instruction with single memory address (e.g. push)
	else if (INS_OperandIsMemory(ins, OP_0)) {
		if (INS_IsMemoryWrite(ins)) {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)mem_alert,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, // Instruction pointer
				IARG_ADDRINT, size, // Instruction size
				IARG_MEMORYWRITE_EA, // Memory address
				IARG_MEMORYWRITE_SIZE,
				IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
				IARG_END);
		}
		else if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)mem_alert,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, thread_ctx_ptr,
				IARG_INST_PTR, // Instruction pointer
				IARG_ADDRINT, size, // Instruction size
				IARG_MEMORYREAD_EA, // Memory address
				IARG_MEMORYREAD_SIZE,
				IARG_REG_VALUE, REG_STACK_PTR, // Stack pointer before the instruction is executed
				IARG_END);
		}
	}

default_case:
	INS_InsertCall(ins,
		IPOINT_BEFORE,
		(AFUNPTR)alert,
		IARG_FAST_ANALYSIS_CALL,
		IARG_REG_VALUE,
		thread_ctx_ptr,
		IARG_INST_PTR,
		IARG_ADDRINT, size,
		IARG_END);
	return;
}

