#pragma once
#include "pin.h"
#include "bufferLoggingInfo.h"
#include "LoggingInfo.h"
#include <ZycoreExportConfig.h>
#include <ZydisExportConfig.h>
#include <Zycore/Zycore.h>
#include <Zydis/Zydis.h>

/* ===================================================================== */
/* Function to disassemble an instruction at a specific EIP              */
/* ===================================================================== */
std::string disassembleInstruction(ADDRINT address, ADDRINT instructionSize);

/* ===================================================================== */
/* Function to initialize the disassembler                               */
/* ===================================================================== */
int initializeDisassembler();