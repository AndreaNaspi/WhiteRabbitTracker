#include "bufferLoggingInfo.h"

inline BOOL scztoonIsFull(pintool_tls* tdata) {
	return tdata->drops + SIZE_SCZ >= SIZE_SCZTOON;
}

inline BOOL scztoonInstructionIsFull(pintool_tls* tdata) {
	return tdata->dropsInstruction + SIZE_SCZ >= SIZE_SCZTOON;
}

void scztoonToDisk(pintool_tls* tdata) {
	PIN_LockClient();
	if (!tdata->logfile) 
		goto EXIT;
	// Flush buffer to log file for the current thread
	int ret = fwrite(tdata->scztoon, tdata->drops, 1, tdata->logfile);
	if (ret != 1) {
		std::cerr << "Cannot flush scztoon to file!" << std::endl;
	}
EXIT:
	PIN_UnlockClient();
	tdata->drops = 0;
}

void scztoonInstructionToDisk(pintool_tls* tdata) {
	PIN_LockClient();
	if (!tdata->logfileInstruction)
		goto EXIT;
	// Flush buffered instruction logger to log file for the current thread
	int ret = fwrite(tdata->scztoonInstruction, tdata->dropsInstruction, 1, tdata->logfileInstruction);
	if (ret != 1) {
		std::cerr << "Cannot flush scztoon to file!" << std::endl;
	}
EXIT:
	PIN_UnlockClient();
	tdata->dropsInstruction = 0;
}


VOID threadInitLogger(THREADID tid, pintool_tls* tdata) {
	OS_MkDir(LOGPATH_TAINT, 755);
	// Initialize logging file for each thread
	char buf[256];
#define LOGNAME "tainted-%u.log"
	sprintf(buf, LOGPATH_TAINT LOGNAME, PIN_GetTid());
#undef LOGNAME
	tdata->logfile = fopen(buf, "wb");
	if (!tdata->logfile) {
		std::cerr << "Cannot create logfile in " << LOGPATH_TAINT << std::endl;
	}
	// Initialize logging instruction file for each thread
	char bufInstruction[256];
#define LOGNAME_INS "tainted-%u-ins.log"
	sprintf(bufInstruction, LOGPATH_TAINT LOGNAME_INS, PIN_GetTid());
#undef LOGNAME
	tdata->logfileInstruction = fopen(bufInstruction, "wb");
	if (!tdata->logfileInstruction) {
		std::cerr << "Cannot create logfile in " << LOGPATH_TAINT << std::endl;
	}
	// Initialize scztoon for the main log file
	tdata->scztoon = (char*)malloc(SIZE_SCZTOON);
	tdata->drops = 0;
	// Initialize scztoon for the instruction log file
	tdata->scztoonInstruction = (char*)malloc(SIZE_SCZTOON);
	tdata->dropsInstruction = 0;
}

VOID threadExitLogger(THREADID tid, pintool_tls* tdata) {
	// Flush buffered logger to disk
	if (tdata->drops > 0) 
		scztoonToDisk(tdata);
	free(tdata->scztoon);
	if (tdata->logfile) 
		fclose(tdata->logfile);
	// Flush buffered instruction logger to disk
	if (tdata->dropsInstruction > 0)
		scztoonInstructionToDisk(tdata);
	free(tdata->scztoonInstruction);
	if (tdata->logfileInstruction)
		fclose(tdata->logfileInstruction);
}

VOID logAlert(pintool_tls* tdata, const char* fmt, ...) {
	// Check if the buffer is full
	if (scztoonIsFull(tdata)) {
		scztoonToDisk(tdata);
	}
	// Write the current alaert to the buffer
	va_list args;
	va_start(args, fmt);
	int ret = vsnprintf(tdata->scztoon + tdata->drops, SIZE_SCZ, fmt, args);
	va_end(args);
	if (ret > 0) 
		tdata->drops += ret;
}

VOID logInstruction(pintool_tls* tdata, const char* fmt, ...) {
	// Check if the buffer is full
	if (scztoonInstructionIsFull(tdata)) {
		scztoonInstructionToDisk(tdata);
	}
	// Write the current alaert to the buffer
	va_list args;
	va_start(args, fmt);
	int ret = vsnprintf(tdata->scztoonInstruction + tdata->dropsInstruction, SIZE_SCZ, fmt, args);
	va_end(args);
	if (ret > 0)
		tdata->dropsInstruction += ret;
}