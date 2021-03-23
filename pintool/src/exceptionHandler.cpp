#include "exceptionHandler.h"

/* ===================================================================== */
/* Initialization function                                               */
/* ===================================================================== */
ExceptionHandler::ExceptionHandler() {
	this->pending = FALSE;
}
// Singleton object
ExceptionHandler* ExceptionHandler::instance = nullptr;

/* ===================================================================== */
/* singleton getInstance function                                        */
/* ===================================================================== */
ExceptionHandler* ExceptionHandler::getInstance() {
	if (instance == nullptr)
		instance = new ExceptionHandler();
	return instance;
}

/* ===================================================================== */
/* Function to set an exception that need to be executed                 */
/* ===================================================================== */
void ExceptionHandler::setExceptionToExecute(W::UINT32 exceptionCode) {
	this->pending = TRUE;
	this->code = exceptionCode;
}

/* ===================================================================== */
/* Utility function to check if the exception is in pending state        */
/* ===================================================================== */
bool ExceptionHandler::isPendingException() {
	return this->pending;
}

/* ===================================================================== */
/* Function to raise a pending exception                                 */
/* ===================================================================== */
void ExceptionHandler::raisePendingException(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr) {
	EXCEPTION_INFO exc;
	if (this->pending == TRUE) {
		// We are interested only in a Windows environment
		PIN_InitWindowsExceptionInfo(&exc, this->code, accessAddr);
		// Add 0x1 to get the right address
		PIN_SetContextReg(ctx, REG_INST_PTR, PIN_GetContextReg(ctx, REG_INST_PTR) + 0x1);
		// Remove the exception from pending state
		this->pending = FALSE;
		// Raise current exception on a certain context and thread
		PIN_RaiseException(ctx, tid, &exc);
	}
}

/* ===================================================================== */
/* Function to execute an exception on a specific instruction (like int) */
/* ===================================================================== */
void ExceptionHandler::executeExceptionIns(CONTEXT *ctx, THREADID tid, ADDRINT accessAddr) {
	ExceptionHandler *eh = ExceptionHandler::getInstance();
	// Raise current exception on a certain context and thread
	eh->raisePendingException(ctx, tid, accessAddr);
}

/* ===================================================================== */
/* Utility function to set the exception code to the current exception   */
/* ===================================================================== */
void ExceptionHandler::setCode(W::UINT32 exceptionCode) {
	// Set exception code
	this->code = exceptionCode;
}