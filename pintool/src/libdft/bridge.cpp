#include "pin.H"

#include "libdft_api.h"
#include "tagmap.h"
#include "bridge.h" 
#include "../itree.h"
#include "../state.h"

#define TTINFO(field) thread_ctx->ttinfo.field

#define RTAG thread_ctx->vcpu.gpr
#define R32TAG(RIDX) \
    {RTAG[(RIDX)][0], RTAG[(RIDX)][1], RTAG[(RIDX)][2], RTAG[(RIDX)][3]}

/*
#define TAINT_TAG_REG(ctx, taint_gpr, t0, t1, t2, t3) do { \
if (!Config::getInstance()->TAINT_MODE) break; \
tag_t _tags[4] = {t0, t1, t2, t3}; \
thread_ctx_t *thread_ctx = (thread_ctx_t *)PIN_GetContextReg(ctx, thread_ctx_ptr); \
addTaintRegister(thread_ctx, taint_gpr, _tags, true); \
} while (0)
TAINT_TAG_REG(ctx, GPR_EAX, 0, 0, 0, 0);
*/
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

void addTaintMemory(ADDRINT addr, UINT32 size, tag_t tag, bool reset, std::string apiName) {
	// check if the pointer is 0 or NULL (check address)
	ASSERT(sizeof(ADDRINT) == sizeof(UINT32), "64-bit mode not supported yet");
	// std::cerr << "Tainting addresses " << addr << " to " << addr + size << " ("+apiName+")" << std::endl;
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
* DTA/DFT alert
*
* @ins:	address of the offending instruction
* @bt:  address of the branch target
*/

static void PIN_FAST_ANALYSIS_CALL alert(thread_ctx_t *thread_ctx, ADDRINT addr, INS ins) {
#if 1
	// If the thread context is tainted
	if (TTINFO(tainted)) {
		// Check if we are in the program code (use itree search and check if null)
		State::globalState* gs = State::getGlobalState();
		if (itree_search(gs->dllRangeITree, addr) == NULL)
			goto END;
		// Get the tainted instruction in a buffer (using INS_Disassemble)
		char buf[512];
		sprintf(buf, "Tainted instruction: 0x%08x [%d] %s\n", addr, (int)TTINFO(tainted), INS_Disassemble(ins).c_str());
		// Open the log file (specified in OnThreadStart, see main.cpp) and log the tainted instruction
		FILE *logFile = fopen(TTINFO(logname), "a"); 
		if (logFile) {
			fprintf(logFile, "%s", buf);
			fclose(logFile);
		}
	}
END:
#else
}
#endif
	TTINFO(tainted) = 0;
}

static void PIN_FAST_ANALYSIS_CALL
assert_reg32(thread_ctx_t *thread_ctx, UINT32 reg) {
	TTINFO(tainted) |= thread_ctx->vcpu.gpr[reg][0] |
		thread_ctx->vcpu.gpr[reg][1] |
		thread_ctx->vcpu.gpr[reg][2] |
		thread_ctx->vcpu.gpr[reg][3];
}

static void PIN_FAST_ANALYSIS_CALL
assert_reg16(thread_ctx_t *thread_ctx, UINT32 reg) {
	TTINFO(tainted) |= thread_ctx->vcpu.gpr[reg][0] |
		thread_ctx->vcpu.gpr[reg][1];
}

static void PIN_FAST_ANALYSIS_CALL
assert_reg8(thread_ctx_t *thread_ctx, UINT32 reg) { 
	TTINFO(tainted) |= thread_ctx->vcpu.gpr[reg][0];
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem256(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getl(addr) | tagmap_getl(addr + 4) |
		tagmap_getl(addr + 8) | tagmap_getl(addr + 12) |
		tagmap_getl(addr + 16) | tagmap_getl(addr + 20) |
		tagmap_getl(addr + 24) | tagmap_getl(addr + 28);
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem128(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getl(addr) | tagmap_getl(addr + 4) |
		tagmap_getl(addr + 8) | tagmap_getl(addr + 12);
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem64(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getl(addr) | tagmap_getl(addr + 4);
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem32(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getl(addr);
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem16(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getw(addr);
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem8(thread_ctx_t *thread_ctx, UINT32 addr) {
	TTINFO(tainted) |= tagmap_getb(addr);
}

static void PIN_FAST_ANALYSIS_CALL
assert_mem_generic(thread_ctx_t *thread_ctx, UINT32 addr, UINT32 size) {
	ASSERT(size % 4 == 0, "Unaligned memory access?");
	for (UINT32 i = 0; i < size / 4; i++)
		TTINFO(tainted) |= tagmap_getl(addr + 4 * i);
}

void instrumentForTaintCheck(INS ins) {
	// The instruction does not have read operands
	if (INS_MaxNumRRegs(ins) == 0) return; 

	UINT32 operands = INS_OperandCount(ins);

	//Titerate over registers
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
			switch (opSize) {
			case 32:
				assert_mem = (AFUNPTR)assert_mem256;
				break;
			case 16:
				assert_mem = (AFUNPTR)assert_mem128;
				break;
			case 8:
				assert_mem = (AFUNPTR)assert_mem64;
				break;
			case 4:
				assert_mem = (AFUNPTR)assert_mem32;
				break;
			case 2:
				assert_mem = (AFUNPTR)assert_mem16;
				break;
			case 1:
				assert_mem = (AFUNPTR)assert_mem8;
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
					IARG_END);
			}
		}
	}

end:
	// Check taint before the instruction is executed
	INS_InsertCall(ins,
		IPOINT_BEFORE,
		(AFUNPTR)alert,
		IARG_FAST_ANALYSIS_CALL,
		IARG_REG_VALUE,
		thread_ctx_ptr,
		IARG_INST_PTR,
		IARG_PTR,
		ins,
		IARG_END);
	return;
}
