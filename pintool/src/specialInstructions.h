#pragma once
#include "ModuleInfo.h"
#include "ProcessInfo.h"
#include "LoggingInfo.h"
#include "ExceptionHandler.h"
#include "pin.H"
#include "winheaders.h"

#include <iostream>
#include <fstream>

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
	static void AlterCpuidValues(ADDRINT ip, CONTEXT * ctxt, ADDRINT cur_eip);

	/* ===================================================================== */
	/* Utility functionts to alter edx and eax (rdtsc results) in case of    */
	/* rdtsc instruction (avoid VM/Sandbox detection)                        */
	/* ===================================================================== */
	static ADDRINT AlterRdtscValueEdx(const CONTEXT* ctxt, ADDRINT cur_eip);
	static ADDRINT AlterRdtscValueEax(const CONTEXT* ctxt, ADDRINT cur_eip);

	/* ===================================================================== */
	/* Function to handle the int 2d and log the instruction                 */
	/* ===================================================================== */
	static void Int2dCalled(const CONTEXT* ctxt, ADDRINT cur_eip);

	/* ===================================================================== */
	/* Function to handle and log the 'in eax, dx' instruction               */
	/* ===================================================================== */
	static void InEaxDxCalledAlterValueEbx(CONTEXT* ctxt, ADDRINT cur_eip);

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

	/* ===================================================================== */
	/* Utility function to alter the timer from the rdtsc results            */
	/* ===================================================================== */
	static ADDRINT setTimer(const CONTEXT* ctxt, bool isEax);

private: 
	/* ===================================================================== */
	/* Define variables                                                      */
	/* ===================================================================== */
	// Singleton object
	SpecialInstructionsHandler();
	static SpecialInstructionsHandler* instance;


};