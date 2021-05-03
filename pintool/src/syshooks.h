#pragma once
#include "state.h"
#include "syshooking.h"
#include "libdft/libdft_config.h"
#include "libdft/bridge.h"
#include "libdft/libdft_api.h"
#include "libdft/tagmap.h"

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
#define STR_QSI				        "a"
#define WSTR_CREATEFILE		        L"a"
#define PATH_BUFSIZE	            512

namespace SYSHOOKS {
	VOID NtDelayexecution_entry(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std);
	VOID NtCreateFile_entry(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std);
	VOID NtOpenKey_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std);
	VOID NtQueryInformationProcess_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std);
	VOID NtQuerySystemInformation_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std);
}