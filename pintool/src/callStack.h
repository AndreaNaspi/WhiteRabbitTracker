#pragma once
#include "pin.H"

typedef struct callStackFrame_t {
	ADDRINT calladdr;
	ADDRINT retaddr;
	ADDRINT spaddr;
	ADDRINT hashID;
} callStackFrame, * callStackFrameP;

typedef struct callStackThread_t {
	std::vector<callStackFrame>* callStack; // Shadow stack
	UINT32 callStackTop;
} callStackThread, * callStackThreadP;

void callStackPush(callStackThreadP shadowStackThread, ADDRINT calladdr, ADDRINT retaddr, ADDRINT spaddr);

void callStackPop(callStackThreadP shadowStackThread, ADDRINT retadd, ADDRINT currentSP);

void alignCallStack(callStackThreadP shadowStackThread, ADDRINT currentSP, std::string fromWhere);
