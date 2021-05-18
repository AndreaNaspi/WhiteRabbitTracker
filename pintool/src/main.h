#pragma once
#include <iostream>
#include <fstream>
#include "pin.H"
#include "state.h"
#include "ProcessInfo.h"
#include "ModuleInfo.h"
#include "bufferLoggingInfo.h"
#include "LoggingInfo.h"
#include "SpecialInstructions.h"
#include "functions.h"
#include "HiddenElements.h"
#include "helper.h"
#include "syshooking.h"
#include "callStack.h"
#include "disassembler.h"
#include "taint.h"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;
// libdft
#include "libdft/libdft_config.h"
#include "libdft/bridge.h"
#include "libdft/libdft_api.h"
#include "libdft/tagmap.h"

/* ===================================================================== */
/* Function called for every loaded module                               */
/* ===================================================================== */
VOID ImageLoad(IMG Image, VOID *v);

/* ===================================================================== */
/* Function called for every unload module                               */
/* ===================================================================== */
VOID ImageUnload(IMG Image, VOID* v);

/* ===================================================================== */
/* Function called BEFORE every TRACE                                    */
/* ===================================================================== */
VOID InstrumentInstruction(TRACE trace, VOID *v);

/* ===================================================================== */
/* Function called BEFORE the analysis routine to enter critical section */
/* ===================================================================== */
VOID SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo, ADDRINT cur_eip);

/* ===================================================================== */
/* Function called for each ANALYSIS ROUTINE                             */
/* Parameters: addrFrom (address of instruction), addrTo (target address)*/
/* ===================================================================== */
VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo);

/* ===================================================================== */
/* Function to handle context change and retrieve exception reason       */
/* ===================================================================== */
static void OnCtxChange(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom, CONTEXT *ctxtTo, INT32 info, VOID *v);

/* ===================================================================== */
/* Function to handle each thread start and retrieve useful informations */
/* for libdft                                                            */
/* ===================================================================== */
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *);

/* ===================================================================== */
/* Function to handle each thread end and destroy libdft thread context  */
/* ===================================================================== */
VOID OnThreadFini(THREADID tid, const CONTEXT *ctxt, INT32, VOID *);

/* ===================================================================== */
/* Function to handle the exceptions (anti-DBI checks)                   */
/* ===================================================================== */
EXCEPT_HANDLING_RESULT internalExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v);

/* ===================================================================== */
/* Print Help Message (usage message)                                    */
/* ===================================================================== */
INT32 Usage();