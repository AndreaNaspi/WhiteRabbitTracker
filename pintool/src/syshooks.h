#pragma once
#include "syshooking.h"

// Misc parameters used in the implementation
#define MAX_HOOK_FUNCTIONS_INDEX	128
#define MAX_MAC_ADDRESS_SIZE		50
#define MAX_GETPROCADDR_ORDINAL		0x200
#define BP_NUMCORES		            4
#define BP_MINDISKGB                1073741824000 // 1000 GB
#define BP_MINRAMGB                 4294967296 // 4 GB
#define BP_TIMER                    150 // milliseconds
#define BP_ICMP_ECHO	            200 // milliseconds
#define BP_FAKEPROCESS              "abc.exe"
#define BP_FAKEPROCESSW             L"abc.exe"
#define PATH_BUFSIZE	            512

namespace SYSHOOKS {
	VOID NtQuerySystemInformation_exit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std);
}