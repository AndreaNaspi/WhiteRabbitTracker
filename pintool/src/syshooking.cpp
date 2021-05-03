#include "pin.H"
#include "syshooking.h"
#include "memory.h"
#include "syshooks.h"
#include <iostream>
#include "process.h"
#include "state.h"
#include "HiddenElements.h"
#include "LoggingInfo.h"
#include "helper.h"
#include "itree.h"


namespace W {
#include "windows.h"
}

LoggingInfo* logModule;

namespace SYSHOOKING {
	CHAR* syscallIDs[MAXSYSCALLS];
	ADDRINT ntdllImgStart, ntdllImgEnd;

	typedef bool(*t_checkCS)(itreenode_t* node, itreenode_t* root, ADDRINT* ESP);
	t_checkCS checkCS_callback;

	// Entries NULL by default (POD)
	syscall_hook sysEntryHooks[MAXSYSCALLS];
	syscall_hook sysExitHooks[MAXSYSCALLS];
	syscall_hook win32sysEntryHooks[MAXWIN32KSYSCALLS-0x1000];
	syscall_hook win32sysExitHooks[MAXWIN32KSYSCALLS-0x1000];

	// Helpers function
	VOID getNtdllRangesAndWow64Info();
	VOID enumSyscalls();
	VOID registerHooks();
	VOID getArgumentsOnEntry(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...);
	int lookupIndex(const char* syscallName);
	bool checkCallSiteNTDLLWin32(itreenode_t* node, itreenode_t* root, ADDRINT* ESP);
	bool checkCallSiteNTDLLWow64(itreenode_t* node, itreenode_t* root, ADDRINT* ESP);

	// Initialization function
	VOID Init(LoggingInfo* logInfoParameter) {
		logModule = logInfoParameter;
		getNtdllRangesAndWow64Info();
		enumSyscalls();
		registerHooks();
	}

	// Analysis callback for Pin
	VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
		ADDRINT syscall_number = PIN_GetSyscallNumber(ctx, std);

		if (syscall_number == 0)
			return;

		pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
		syscall_t *sc = &tdata->sc;

		sc->syscall_number = syscall_number;

		if (syscall_number < MAXSYSCALLS) {
			syscall_hook hookEntry = sysEntryHooks[syscall_number];
			syscall_hook hookExit = sysExitHooks[syscall_number];

			// Fill sc (we may have a hook on exit only)
			if (hookEntry || hookExit) { 
				getArgumentsOnEntry(ctx, std, SYSCALL_NUM_ARG,
					0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3,
					4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7,
					8, &sc->arg8, 9, &sc->arg9, 10, &sc->arg10, 11, &sc->arg11);

				// Call onEntry hook
				if (hookEntry) hookEntry(sc, ctx, std);
			}
		} 
		else if (sc->syscall_number >= 0x1000 && sc->syscall_number < MAXWIN32KSYSCALLS) {
			ADDRINT num = sc->syscall_number - 0x1000;
			syscall_hook hookEntry = win32sysEntryHooks[num];
			syscall_hook hookExit = win32sysExitHooks[num];

			// Fill sc (we may have a hook on exit only)
			if (hookEntry || hookExit) { 
				getArgumentsOnEntry(ctx, std, SYSCALL_NUM_ARG,
					0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3,
					4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7,
					8, &sc->arg8, 9, &sc->arg9, 10, &sc->arg10, 11, &sc->arg11);

				// Call onEntry hook
				if (hookEntry) hookEntry(sc, ctx, std);
			}
		}
	}

	// Analysis callback for Pin
	VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
		pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, thread_id));
		syscall_t *sc = &tdata->sc;

		if (sc->syscall_number < MAXSYSCALLS) {
			syscall_hook hook = sysExitHooks[sc->syscall_number];
			if (hook) hook(sc, ctx, std);
		} else if (sc->syscall_number >= 0x1000 && sc->syscall_number < MAXWIN32KSYSCALLS) {
			ADDRINT num = sc->syscall_number - 0x1000;
			syscall_hook hook = win32sysExitHooks[num];
			if (hook) hook(sc, ctx, std);
		}
	}

	BOOL ReturnsToUserCode(CONTEXT* ctx) {
		ADDRINT *ESP = (ADDRINT*)PIN_GetContextReg(ctx, REG_STACK_PTR);
		State::globalState* gs = State::getGlobalState();
		itreenode_t* node = itree_search(gs->dllRangeITree, *ESP);
		if (node) {
			return checkCS_callback(node, gs->dllRangeITree, ESP);
		}
		return TRUE;
	}

	/** HELPER METHODS BEGIN HERE **/
 
	// Used in getNtdllRangesAndWow64Info()
	typedef NTSYSAPI W::PIMAGE_NT_HEADERS NTAPI _RtlImageNtHeader(
		W::PVOID ModuleAddress
	);

	static VOID getNtdllRangesAndWow64Info() {
		W::BOOL bWow64;
		W::IsWow64Process((W::HANDLE)(-1), &bWow64);
		checkCS_callback = (bWow64 != 0) ? checkCallSiteNTDLLWow64 : checkCallSiteNTDLLWin32;

		W::HMODULE image = W::GetModuleHandle("ntdll");

		_RtlImageNtHeader* fun = (_RtlImageNtHeader*)W::GetProcAddress(image, "RtlImageNtHeader");
		W::PIMAGE_NT_HEADERS headers = fun(image);

		ntdllImgStart = (ADDRINT)headers->OptionalHeader.ImageBase; // == (ADDRINT)image
		ntdllImgEnd = ntdllImgStart + headers->OptionalHeader.SizeOfImage;
	}

	// NTDLL parsing for syscall ordinal extraction
	static VOID enumSyscalls() {
		unsigned char *image = (unsigned char *)W::GetModuleHandle("ntdll");
		W::IMAGE_DOS_HEADER *dos_header = (W::IMAGE_DOS_HEADER *) image;
		W::IMAGE_NT_HEADERS *nt_headers = (W::IMAGE_NT_HEADERS *)(image + dos_header->e_lfanew);
		W::IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->
			OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		W::IMAGE_EXPORT_DIRECTORY *export_directory = (W::IMAGE_EXPORT_DIRECTORY *)(image + data_directory->VirtualAddress);
		W::DWORD *address_of_names = (W::DWORD*)(image + export_directory->AddressOfNames);
		W::DWORD *address_of_functions = (W::DWORD*)(image + export_directory->AddressOfFunctions);
		UINT16 *address_of_name_ordinals = (W::UINT16*)(image + export_directory->AddressOfNameOrdinals);
		W::DWORD number_of_names = MIN(export_directory->NumberOfFunctions, export_directory->NumberOfNames);

		for (W::DWORD i = 0; i < number_of_names; i++) {
			const char *name = (const char *)(image + address_of_names[i]);
			unsigned char *addr = image + address_of_functions[address_of_name_ordinals[i]];
			if (memcmp(name, "Nt", 2)) 
				continue;
			if (addr[0] == 0xb8 && (addr[5] == 0xb9 || addr[5] == 0x33 || addr[5] == 0xba)) {
				ADDRINT syscall_number = *(UINT32*)(addr + 1);
				ASSERT(!syscallIDs[syscall_number], "Multiple syscalls on same ordinal?");
				syscallIDs[syscall_number] = strdup(name);
			}
		}
	}

	static int lookupIndex(const char* syscallName) {
		for (int i = 0; i < MAXSYSCALLS; ++i) {
			if (!strcmp(syscallIDs[i], syscallName)) return i;
		}

		ASSERT(false, "Unknown system call number");
		return 0;
	}

	static VOID getArgumentsOnEntry(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...) {
		va_list args;
		va_start(args, count);
		for (int i = 0; i < count; i++) {
			int index = va_arg(args, int);
			ADDRINT *ptr = va_arg(args, ADDRINT *);
			*ptr = PIN_GetSyscallArgument(ctx, std, index);
		}
		va_end(args);
	}

	static bool checkCallSiteNTDLLWin32(itreenode_t* node, itreenode_t* root, ADDRINT* ESP) {
		ADDRINT addr = *ESP;
		if (addr < ntdllImgStart || addr > ntdllImgEnd) return false;

		// Not much black magic: retn [say 10h] or ret
		// C2 10 00
		uint8_t bytes[3] = { 0xFF, 0xFF, 0xFF };
		PIN_SafeCopy(bytes, (void*)addr, 6);

		if (!((bytes[0] == 0xC2 && bytes[2] == 0x00) || bytes[0] == 0xC3)) {
			ASSERT(false, "Check implementation for NTDLL call sites");
			return false;
		}

		// The RA for the caller will be at ESP+4
		ADDRINT ra = *((ADDRINT*)ESP + 1);

		node = itree_search(root, ra);
		if (node) 
			return false;
		return true;
	}

	static bool checkCallSiteNTDLLWow64(itreenode_t* node, itreenode_t* root, ADDRINT* ESP) {
		ADDRINT addr = *ESP;
		if (addr < ntdllImgStart || addr > ntdllImgEnd) return false;

		// black magic: add esp, 4 followed by retn [say 10h] or ret
		// 83 C4 04
		// C2 10 00
		uint8_t bytes[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; 
		PIN_SafeCopy(bytes, (void*)addr, 6);
		if (!(bytes[0] == 0x83 && bytes[1] == 0xC4 && bytes[2] == 0x04)) {
			ASSERT(false, "Check implementation for NTDLL call sites");
			return false;
		}

		if (!((bytes[3] == 0xC2 && bytes[5] == 0x00) || bytes[3] == 0xC3)) {
			ASSERT(false, "Check implementation for NTDLL call sites");
			return false;
		}

		// The RA for the caller will be at ESP+4
		ADDRINT ra = *((ADDRINT*)ESP + 1);

		node = itree_search(root, ra);
		if (node) 
			return false;
		return true;
	}

	static VOID registerHooks() {
		// Handle the NtDelayExecution API
		sysEntryHooks[lookupIndex("NtDelayExecution")] = &SYSHOOKS::NtDelayexecution_entry;
		// Handle the NtCreateFile API (Virtualbox/VMware files access) 
		sysEntryHooks[lookupIndex("NtCreateFile")] = &SYSHOOKS::NtCreateFile_entry;
		sysExitHooks[lookupIndex("NtCreateFile")] = &SYSHOOKS::NtCreateFile_exit;
		// Handle the NtOpenKey API (registry access)
		sysExitHooks[lookupIndex("NtOpenKey")] = &SYSHOOKS::NtOpenKey_exit;
		sysExitHooks[lookupIndex("NtOpenKeyEx")] = &SYSHOOKS::NtOpenKey_exit;
		// Handle the NtQueryInformationProcess API (process information access)
		sysExitHooks[lookupIndex("NtQueryInformationProcess")] = &SYSHOOKS::NtQueryInformationProcess_exit;
		// Handle the NtQuerySystemInformation API (firmware table access)
		sysExitHooks[lookupIndex("NtQuerySystemInformation")] = &SYSHOOKS::NtQuerySystemInformation_exit;
		// Handle the NtQueryAttributesFile API (file information access) 
		sysEntryHooks[lookupIndex("NtQueryAttributesFile")] = &SYSHOOKS::NtQueryAttributesFile_entry;
		sysExitHooks[lookupIndex("NtQueryAttributesFile")] = &SYSHOOKS::NtQueryAttributesFile_exit;
		// Win32 system APIs (embedded ordinals)
		win32sysExitHooks[NTUSERFINDWINDOWSEX] = &SYSHOOKS::NtUserFindWindowEx_exit;

		// Register analysis callbacks for Pin
		PIN_AddSyscallEntryFunction(&SyscallEntry, NULL);
		PIN_AddSyscallExitFunction(&SyscallExit, NULL);
	}
}