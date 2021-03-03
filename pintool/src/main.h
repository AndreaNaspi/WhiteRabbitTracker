#pragma once

#include "pin.H"

/* ===================================================================== */
/* Function called for every loaded module                               */
/* ===================================================================== */
VOID ImageLoad(IMG Image, VOID *v);

/* ===================================================================== */
/* Function called for every unload module                               */
/* ===================================================================== */
VOID ImageUnload(IMG Image, VOID* v);

/* ===================================================================== */
/* Function called BEFORE every INSTRUCTION (ins)                        */
/* ===================================================================== */
VOID InstrumentInstruction(INS ins, VOID *v);

/* ===================================================================== */
/* Function called BEFORE the analysis routine to enter critical section */
/* ===================================================================== */
VOID SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo);

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
/* Print Help Message (usage message)                                    */
/* ===================================================================== */
INT32 Usage();