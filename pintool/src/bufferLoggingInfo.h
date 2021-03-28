#pragma once
#include <pin.H>
#include <iostream>
#include <fstream>
#include <intrin.h>

#define LOGPATH "C:\\pin315\\sniper\\"
#define LOG_ENABLED		1
#define LOG_ARG_COUNTS	1
#define USE_RDTSCP		1

// Syscall structure
typedef struct _syscall_t {
	ADDRINT syscall_number;
	union {
		ADDRINT args[12];
		struct {
			ADDRINT arg0, arg1, arg2, arg3;
			ADDRINT arg4, arg5, arg6, arg7;
			ADDRINT arg8, arg9, arg10, arg11;
		};
	};
} syscall_t;

typedef struct {
	syscall_t sc;
	FILE* logfile;
	char *scztoon; // B uffer for logging
	UINT32 drops;
} pintool_tls;

VOID threadInitLogger(THREADID tid, pintool_tls* tdata);
VOID threadExitLogger(THREADID tid, pintool_tls* tdata);
VOID logFun(pintool_tls* tdata, const char* fmt, ...);