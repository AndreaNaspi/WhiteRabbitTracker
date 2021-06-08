#pragma once
#include "ModuleInfo.h"
#include "ProcessInfo.h"
#include "LoggingInfo.h"
#include "ExceptionHandler.h"
#include "HiddenElements.h"
#include "pin.H"
#include "state.h"
#include "winheaders.h"
#include "disassembler.h"
#include "libdft/libdft_config.h"
#include "libdft/bridge.h"
#include "libdft/libdft_api.h"
#include "libdft/tagmap.h"

#include <iostream>
#include <fstream>

#define MAX_CPUID 10
#define MAX_RDTSC 5
#define FPUIPOFFSET 0xc

class SpecialInstructionsHandler
{
public:
	/* ===================================================================== */
	/* Initialization function                                               */
	/* ===================================================================== */
	void init(ProcessInfo* pInfoParameter, LoggingInfo* logInfoParameter) {
		// Get class instance to access objects
		SpecialInstructionsHandler *classHandler = SpecialInstructionsHandler::getInstance();
		// Initialize variables with default values
		classHandler->pInfo = pInfoParameter;
		classHandler->logInfo = logInfoParameter;
		classHandler->cpuid_eax = 0;
	}

	/* ===================================================================== */
	/* singleton getInstance function                                        */
	/* ===================================================================== */
	static SpecialInstructionsHandler* getInstance();

	/* ===================================================================== */
	/* Utility function to initialize the FPU claim tool register            */
	/* ===================================================================== */
	static void fpuInit();

	/* ===================================================================== */
	/* Function to check for specific special instruction and insert handlers*/
	/* ===================================================================== */
	static void checkSpecialInstruction(INS ins);

	/* ===================================================================== */
	/* Function to handle and log the cpuid instruction                      */
	/* ===================================================================== */
	static void CpuidCalled(ADDRINT ip, CONTEXT* ctxt, ADDRINT cur_eip);

	/* ===================================================================== */
	/* Utility function to alter EBX, ECX, EDX (cpuid results) in case of    */
	/* cpuid instruction (avoid VM/Sandbox detection)                        */
	/* ===================================================================== */
	static void AlterCpuidValues(ADDRINT ip, CONTEXT* ctxt, ADDRINT cur_eip, ADDRINT* cpuidCount);

	/* ===================================================================== */
	/* Function to handle the rdtsc instruction                              */
	/* ===================================================================== */
	static void AlterRdtscValues(ADDRINT ip, CONTEXT * ctxt, ADDRINT cur_eip, ADDRINT *rdtscCount);

	/* ===================================================================== */
	/* Function to handle the int 2d and log the instruction                 */
	/* ===================================================================== */
	static void Int2dCalled(const CONTEXT* ctxt, ADDRINT cur_eip);

	/* ===================================================================== */
	/* Function to update the FPU structure in order to fake the address of  */
	/* the last executed FPU instruction                                     */
	/* ===================================================================== */
	static void FPU_UpdateFPUStatus(ADDRINT regValue, ADDRINT op);

	/* ===================================================================== */
	/* Function to return a fake instruction address for each FPU instruction*/
	/* (currently we return the spilledFPU register from the caller)         */
	/* ===================================================================== */
	static ADDRINT FPU_UpdateLastFpuIns(ADDRINT addr);

	/* ===================================================================== */
	/* Function to handle and log the 'in eax, dx' instruction               */
	/* ===================================================================== */
	static void InEaxEdxCalledAlterValueEbx(CONTEXT* ctxt, ADDRINT cur_eip);

	/* ===================================================================== */
	/* Function to handle the Obsidium disk drive name check                 */
	/* ===================================================================== */
	static void KillObsidiumDiskDriveCheck(CONTEXT* ctxt);

	/* ===================================================================== */
	/* Function to handle the Obsidium pattern matching to avoid dead path   */
	/* ===================================================================== */
	static void KillObsidiumDeadPath(CONTEXT* ctxt);

protected:
	/* ===================================================================== */
	/* Define variables                                                      */
	/* ===================================================================== */
	// Object that contains useful functions to access the process
	ProcessInfo* pInfo;
	// Object that contains useful functions for logging
	LoggingInfo* logInfo;
	// Object to save the cpuid parameter (EAX register)
	ADDRINT cpuid_eax;

	/* ===================================================================== */
	/* Utility function to handle registers for cpuid handling               */
	/* ===================================================================== */
	void regInit(REGSET* regsIn, REGSET* regsOut);

	/* ===================================================================== */
	/* Utility function to compare two strings (compare instruction name)    */
	/* ===================================================================== */
	bool isStrEqualI(std::string string1, std::string string2);

private: 
	/* ===================================================================== */
	/* Define variables                                                      */
	/* ===================================================================== */
	// Singleton object
	SpecialInstructionsHandler();
	static SpecialInstructionsHandler* instance;


};