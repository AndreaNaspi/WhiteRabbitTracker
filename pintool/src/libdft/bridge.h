#pragma once
#include "pin.H"
#include "libdft_api.h"
#include <iostream>
using std::cerr;

#define RTAG thread_ctx->vcpu.gpr
#define R32TAG(RIDX) \
    {RTAG[(RIDX)][0], RTAG[(RIDX)][1], RTAG[(RIDX)][2], RTAG[(RIDX)][3]}

extern REG thread_ctx_ptr;

void instrumentForTaintCheck(INS ins);
void addTaintMemory(ADDRINT addr, UINT32 size, tag_t tag, bool reset, std::string apiName);
void addTaintRegister(thread_ctx_t *thread_ctx, int gpr, tag_t tags[], bool reset);
void getMemoryTaints(ADDRINT addr, tag_t* tags, UINT32 size);