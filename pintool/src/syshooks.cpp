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

	VOID NtOpenKey_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		W::PHANDLE khandle = (W::PHANDLE)sc->arg0;
		if (khandle == nullptr) return;

		OBJECT_ATTRIBUTES *oa = (OBJECT_ATTRIBUTES*)sc->arg2;
		W::PWSTR path = oa->ObjectName->Buffer;

		if (PIN_GetContextReg(ctx, REG_GAX) != ERROR_SUCCESS || path == NULL || *path == NULL)
			return;

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(path, value, PATH_BUFSIZE);

		if (HiddenElements::shouldHideRegOpenKeyStr(value)) {
			// free right handle
			if (_knobBypass) {
				W::CloseHandle(*khandle);
				*khandle = (W::HANDLE) - 1;
				ADDRINT _eax = CODEFORINVALIDHANDLE;
				PIN_SetContextReg(ctx, REG_GAX, _eax);
				logModule->logBypass("NtOpenKey");
			}
			TAINT_TAG_REG(ctx, GPR_EAX, 1, 1, 1, 1);
			addTaintMemory((ADDRINT)khandle, sizeof(W::HANDLE), TAINT_COLOR_1, true, "NtOpenKey");
			return;
		}
	}

	VOID NtQuerySystemInformation_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		if (sc->arg0 == SystemFirmwareTableInformation) {
			PSYSTEM_FIRMWARE_TABLE_INFORMATION sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
			if (sfti->Action == SystemFirmwareTable_Get) {
				ADDRINT sizeOut = *(W::ULONG*)sc->arg3;
				ADDRINT sizeIn = (W::ULONG)sc->arg2;
				if (sizeOut > sizeIn) return;

				// virtualbox part
				char vbox[] = { "VirtualBox" };
				char vbox2[] = { "vbox" };
				char vbox3[] = { "VBOX" };
				char escape[] = { "          " };
				char escape2[] = { "    " };
				W::ULONG sizeVbox = (W::ULONG)Helper::_strlen_a(vbox);
				W::ULONG sizeVbox2 = (W::ULONG)Helper::_strlen_a(vbox2);
				W::ULONG sizeVbox3 = (W::ULONG)Helper::_strlen_a(vbox3);


				PSYSTEM_FIRMWARE_TABLE_INFORMATION info = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
				// scan entire bios in order to find vbox string
				if (_knobBypass) {
					for (size_t i = 0; i < info->TableBufferLength - sizeVbox; i++) {
						if (memcmp(info->TableBuffer + i, vbox, sizeVbox) == 0) {
							PIN_SafeCopy(info->TableBuffer + i, escape, sizeof(escape));
						}
						else if (memcmp(info->TableBuffer + i, vbox2, sizeVbox2) == 0 ||
							memcmp(info->TableBuffer + i, vbox3, sizeVbox3) == 0) {
							PIN_SafeCopy(info->TableBuffer + i, escape2, sizeof(escape2));
						}
					}
					logModule->logBypass("NtQuerySystemInformation VBox");
				}

				// VMware part
				char vmware[] = { "VMware" };
				char escape3[] = { "      " };
				W::ULONG vmwareSize = (W::ULONG)Helper::_strlen_a(vmware);

				if (_knobBypass) {
					for (size_t i = 0; i < info->TableBufferLength - vmwareSize; i++) {
						if (memcmp(info->TableBuffer + i, vmware, vmwareSize) == 0) {
							PIN_SafeCopy(info->TableBuffer + i, escape3, sizeof(escape3));
						}
					}
					logModule->logBypass("NtQuerySystemInformation VMware");
				}
				addTaintMemory((ADDRINT)info->TableBuffer, info->TableBufferLength, TAINT_COLOR_1, true, "NtQuerySystemInformation SystemFirmwareTableInformation");
			}
		}
	}
}
