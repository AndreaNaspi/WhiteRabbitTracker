#pragma once
#include "pin.h"
#include "bufferLoggingInfo.h"
#include "LoggingInfo.h"
#include <ZycoreExportConfig.h>
#include <ZydisExportConfig.h>
#include <Zycore/Zycore.h>
#include <Zydis/Zydis.h>

/* ===================================================================== */
/* Function to initialize the disassembler                               */
/* ===================================================================== */
int initializeDisassembler();