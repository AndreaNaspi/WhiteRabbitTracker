#pragma once
#include <pin.H>
#include <iostream>
#include <fstream>
#include <intrin.h>

#define LOGPATH "C:\\Pin315\\"
#define LOGPATH_TAINT "C:\\Pin315\\taint\\"
#define SIZE_SCZTOON	5*1024*1024	// 5 MB (reduce with many threads?)
#define SIZE_SCZ		2048		// max bytes written at a time

namespace W {
#include "windows.h"
}

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
	char *scztoon; // Buffer for logging
	UINT32 drops;
} pintool_tls;

inline BOOL scztoonIsFull(pintool_tls* tdata);
void scztoonToDisk(pintool_tls* tdata);
VOID threadInitLogger(THREADID tid, pintool_tls* tdata);
VOID threadExitLogger(THREADID tid, pintool_tls* tdata);
VOID logAlert(pintool_tls* tdata, const char* fmt, ...);