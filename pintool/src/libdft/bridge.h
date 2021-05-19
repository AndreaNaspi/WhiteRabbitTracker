#pragma once
#include "pin.H"
#include "libdft_api.h"
#include "../syshooking.h"
#include "../bufferLoggingInfo.h"
#include "../callStack.h"
#include <iostream>
using std::cerr;

#define RTAG thread_ctx->vcpu.gpr
#define R32TAG(RIDX) \
    {RTAG[(RIDX)][0], RTAG[(RIDX)][1], RTAG[(RIDX)][2], RTAG[(RIDX)][3]}

#define OP_0 0
#define OP_1 1
#define OP_NA "NA"

extern REG thread_ctx_ptr;

void initLoggerShadowCallStack(std::string fileName);
void instrumentForTaintCheck(INS ins);
void logHookId(CONTEXT* ctx, std::string hook_name, ADDRINT start_addr, UINT32 size);
void addTaintMemory(CONTEXT* ctx, ADDRINT addr, UINT32 size, tag_t tag, bool reset, std::string apiName);
void addTaintRegister(thread_ctx_t *thread_ctx, int gpr, tag_t tags[], bool reset);
void getMemoryTaints(ADDRINT addr, tag_t* tags, UINT32 size);