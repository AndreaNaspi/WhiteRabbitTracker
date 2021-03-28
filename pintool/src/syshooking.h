#pragma once
#include "pin.h"
#include "bufferLoggingInfo.h"
#include "LoggingInfo.h"
#include <iostream>
using std::cerr;

extern TLS_KEY tls_key;

/** These numbers are tailored to Windows 7 SP1 **/
// We saw ordinals as high as 0x1a3 in ntdll
#define MAXSYSCALLS			0x200
// 0x1338 seen as max on https://j00ru.vexillium.org/syscalls/win32k/32/
#define MAXWIN32KSYSCALLS	0x1400

/* Embedded ordinals for Win7 SP1 */
// We subtract 0x1000 for array indexing
#define NTUSERENUMDISPLAYDEVICES	(0x1185-0x1000)
#define NTUSERFINDWINDOWSEX			(0x118C-0x1000)
// GDI from SoK
#define NTGDIPOLYTEXTOUTW			(0x10fa-0x1000)
#define NTGDIDRAWSTREAM				(0x12db-0x1000)

// BluePill won't need more than that
#define SYSCALL_NUM_ARG 11

// Function signature of our hook functions
typedef void(*syscall_hook)(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);

extern LoggingInfo* logModule;

namespace SYSHOOKING {
	VOID Init(LoggingInfo* logInfoParameter);
	VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
	VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
	BOOL ReturnsToUserCode(CONTEXT* ctx);
}

