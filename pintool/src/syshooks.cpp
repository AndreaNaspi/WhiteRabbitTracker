#include "syshooks.h"
#include "memory.h"
#include "state.h"
#include "HiddenElements.h"
#include "helper.h"

/* ===================================================================== */
/* Define taint color                                                    */
/* ===================================================================== */
#define TAINT_COLOR_1 0x01
#define TAINT_COLOR_2 0x02
#define TAINT_COLOR_3 0x03
#define TAINT_COLOR_4 0x04
#define TAINT_COLOR_5 0x05
#define TAINT_COLOR_6 0x06
#define TAINT_COLOR_7 0x07
#define TAINT_COLOR_8 0x08

/* ============================================================================= */
/* Define macro to taint a register using thread_ctx_ptr and GPR from libdft     */
/* ============================================================================= */
#define TAINT_TAG_REG(ctx, taint_gpr, t0, t1, t2, t3) do { \
tag_t _tags[4] = {t0, t1, t2, t3}; \
thread_ctx_t *thread_ctx = (thread_ctx_t *)PIN_GetContextReg(ctx, thread_ctx_ptr); \
addTaintRegister(thread_ctx, taint_gpr, _tags, true); \
} while (0)

namespace SYSHOOKS {

	/* ===================================================================== */
	/* Handle the NtCreateFile API (Virtualbox/VMware files access)          */
	/* ===================================================================== */
	VOID NtCreateFile_entry(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		W::OBJECT_ATTRIBUTES *Obj = (W::OBJECT_ATTRIBUTES*)sc->arg2;
		W::ULONG mode = (W::ULONG)sc->arg7;
		W::PUNICODE_STRING p = Obj->ObjectName;

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(p->Buffer, value, PATH_BUFSIZE); 
		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			for (W::USHORT i = p->Length - 8; i < p->Length - 1; i += 2) {
				if (_knobBypass) {
					logModule->logBypass("NtCreateFile");
					memcpy((char *)p->Buffer + i, WSTR_CREATEFILE, sizeof(wchar_t));
					PIN_SafeCopy((char *)p->Buffer + i, WSTR_CREATEFILE, sizeof(wchar_t));
				}
			}
			// High false positive rate, taint only suspicious files
			addTaintMemory(ctx, (ADDRINT)p->Buffer, p->Length, TAINT_COLOR_1, true, "NtCreateFile");
		}
	}

	/* ===================================================================== */
	/* Handle the NtOpenKey API (registry access)                            */
	/* ===================================================================== */
	VOID NtOpenKey_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		W::PHANDLE khandle = (W::PHANDLE)sc->arg0;
		if (khandle == nullptr)
			return;

		OBJECT_ATTRIBUTES *oa = (OBJECT_ATTRIBUTES*)sc->arg2;
		W::PWSTR path = oa->ObjectName->Buffer;

		if (PIN_GetContextReg(ctx, REG_GAX) != ERROR_SUCCESS || path == NULL || *path == NULL)
			return;

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(path, value, PATH_BUFSIZE);
		if (HiddenElements::shouldHideRegOpenKeyStr(value)) {
			// Free right handle
			if (_knobBypass) {
				logModule->logBypass("NtOpenKey");
				W::CloseHandle(*khandle);
				*khandle = (W::HANDLE) - 1;
				ADDRINT _eax = CODEFORINVALIDHANDLE;
				PIN_SetContextReg(ctx, REG_GAX, _eax);
			}
			// Taint registry handler
			TAINT_TAG_REG(ctx, GPR_EAX, 1, 1, 1, 1);
			// High false positive rate, taint only suspicious registry access
			addTaintMemory(ctx, (ADDRINT)khandle, sizeof(W::HANDLE), TAINT_COLOR_1, true, "NtOpenKey");
		}
	}

	/* ===================================================================== */
	/* Handle the NtQueryInformationProcess API (process information access) */
	/* ===================================================================== */
	VOID NtQueryInformationProcess_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		W::PROCESSINFOCLASS ProcessInformationClass = (W::PROCESSINFOCLASS)sc->arg1;
		W::PVOID ProcessInformation = (W::PVOID)sc->arg2;
		W::ULONG ProcessInformationLength = (W::ULONG)sc->arg3;
		W::PULONG ReturnLength = (W::PULONG)sc->arg4;

		if (ProcessInformation != 0 && ProcessInformationLength != 0) {
			W::ULONG backupReturnLength = 0;
			if (ReturnLength != nullptr && (W::ULONG_PTR)ReturnLength >= (W::ULONG_PTR)ProcessInformation && (W::ULONG_PTR)ReturnLength <= (W::ULONG_PTR)ProcessInformation + ProcessInformationLength) {
				backupReturnLength = *ReturnLength;
			}

			if (ProcessInformationClass == ProcessDebugFlags) {
				// Gives Pin away as a debugger
				if (_knobBypass) {
					logModule->logBypass("NtQueryInformationProcess ProcessDebugFlags");
					*((W::ULONG *)ProcessInformation) = PROCESS_DEBUG_INHERIT;
				}
				addTaintMemory(ctx, (ADDRINT)ProcessInformation, ProcessInformationLength, TAINT_COLOR_1, true, "NtQueryInformationProcess ProcessDebugFlags");
			}
			else if (ProcessInformationClass == ProcessDebugObjectHandle) {
				// Set return value to STATUS_PORT_NOT_SET
				if (_knobBypass) {
					logModule->logBypass("NtQueryInformationProcess ProcessDebugObjectHandle");
					*((W::HANDLE *)ProcessInformation) = (W::HANDLE)0;
					ADDRINT _eax = CODEFORSTATUSPORTNOTSET;
					PIN_SetContextReg(ctx, REG_GAX, _eax);
				}
				addTaintMemory(ctx, (ADDRINT)ProcessInformation, ProcessInformationLength, TAINT_COLOR_1, true, "NtQueryInformationProcess ProcessDebugObjectHandle");
			}
			else if (ProcessInformationClass == ProcessDebugPort) {
				// Set debug port to null
				if (_knobBypass) {
					logModule->logBypass("NtQueryInformationProcess ProcessDebugPort");
					*((W::HANDLE *)ProcessInformation) = (W::HANDLE)0;
				}
				addTaintMemory(ctx, (ADDRINT)ProcessInformation, ProcessInformationLength, TAINT_COLOR_1, true, "NtQueryInformationProcess ProcessDebugPort");
			}
			if (backupReturnLength != 0) {
				*ReturnLength = backupReturnLength;
			}
		}

	}

	/* ===================================================================== */
	/* Handle the NtQuerySystemInformation API (firmware table access)       */
	/* ===================================================================== */
	VOID NtQuerySystemInformation_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		if (sc->arg0 == SystemFirmwareTableInformation) {
			PSYSTEM_FIRMWARE_TABLE_INFORMATION sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
			if (sfti->Action == SystemFirmwareTable_Get) {
				ADDRINT sizeOut = *(W::ULONG*)sc->arg3;
				ADDRINT sizeIn = (W::ULONG)sc->arg2;
				if (sizeOut > sizeIn) return;

				// Virtualbox part
				char vbox[] = { "VirtualBox" };
				char vbox2[] = { "vbox" };
				char vbox3[] = { "VBOX" };
				char escape[] = { "          " };
				char escape2[] = { "    " };
				W::ULONG sizeVbox = (W::ULONG)Helper::_strlen_a(vbox);
				W::ULONG sizeVbox2 = (W::ULONG)Helper::_strlen_a(vbox2);
				W::ULONG sizeVbox3 = (W::ULONG)Helper::_strlen_a(vbox3);


				PSYSTEM_FIRMWARE_TABLE_INFORMATION info = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
				// Scan entire bios in order to find vbox string
				logModule->logBypass("NtQuerySystemInformation VBox");
				for (size_t i = 0; i < info->TableBufferLength - sizeVbox; i++) {
					if (memcmp(info->TableBuffer + i, vbox, sizeVbox) == 0 && _knobBypass) {
						PIN_SafeCopy(info->TableBuffer + i, escape, sizeof(escape));
					}
					else if (memcmp(info->TableBuffer + i, vbox2, sizeVbox2) == 0 ||
						memcmp(info->TableBuffer + i, vbox3, sizeVbox3) == 0 && _knobBypass) {
						PIN_SafeCopy(info->TableBuffer + i, escape2, sizeof(escape2));
					}
				}

				// VMware part
				char vmware[] = { "VMware" };
				char escape3[] = { "      " };
				W::ULONG vmwareSize = (W::ULONG)Helper::_strlen_a(vmware);

				logModule->logBypass("NtQuerySystemInformation VMware");
				for (size_t i = 0; i < info->TableBufferLength - vmwareSize; i++) {
					if (memcmp(info->TableBuffer + i, vmware, vmwareSize) == 0 && _knobBypass) {
						PIN_SafeCopy(info->TableBuffer + i, escape3, sizeof(escape3));
					}
				}

				addTaintMemory(ctx, (ADDRINT)info->TableBuffer, info->TableBufferLength, TAINT_COLOR_1, true, "NtQuerySystemInformation SystemFirmwareTableInformation");
			}
		}
	}
}
