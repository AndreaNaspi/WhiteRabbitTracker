#pragma once
#include "pin.H"
#include <iostream>

namespace W {
	#include <windows.h>
}

class ExceptionHandler {

public:
	/* ===================================================================== */
	/* singleton getInstance function                                        */
	/* ===================================================================== */
	static ExceptionHandler* getInstance();

	/* ===================================================================== */
	/* Function to execute an exception on a specific instruction (like int) */
	/* ===================================================================== */
	static void executeExceptionIns(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr);

	/* ===================================================================== */
	/* Function to set an exception that need to be executed                 */
	/* ===================================================================== */
	void setExceptionToExecute(W::UINT32 exceptionCode);

	/* ===================================================================== */
	/* Function to raise a pending exception                                 */
	/* ===================================================================== */
	void raisePendingException(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr);

	/* ===================================================================== */
	/* Utility function to check if the exception is in pending state        */
	/* ===================================================================== */
	bool isPendingException();

	/* ===================================================================== */
	/* Utility function to set the exception code to the current exception   */
	/* ===================================================================== */
	void setCode(W::UINT32 exceptionCode);

protected: 
	/* ===================================================================== */
	/* Define variables                                                      */
	/* ===================================================================== */
	// last address of a specific instruction
	ADDRINT lastAddress;
	// exception code
	W::UINT32 code;
	// boolean to define the pending state
	bool pending;
	// thread identifier
	THREADID tid;
	// context variable
	CONTEXT *ctx;
private:
	/* ===================================================================== */
	/* Define variables                                                      */
	/* ===================================================================== */
	// Singleton object
	ExceptionHandler();
	static ExceptionHandler* instance;
};
