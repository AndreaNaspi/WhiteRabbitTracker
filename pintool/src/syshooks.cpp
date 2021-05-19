#include "syshooks.h"
#include "memory.h"
#include "state.h"
#include "HiddenElements.h"
#include "taint.h"
#include "helper.h"

namespace SYSHOOKS {

	/* ===================================================================== */
	/* Handle the NtDelayExecution API                                       */
	/* ===================================================================== */
	VOID NtDelayexecution_entry(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::LARGE_INTEGER* li = (W::LARGE_INTEGER*)sc->arg1;
		W::UINT ll = (-li->QuadPart) / 10000LL;
		if (ll == 0 || ll > 1000000000)
			return;

		FetchTimeState;
		tinfo->sleepMs += ll;
		tinfo->sleepMsTick += ll;
		if (tinfo->lastMs == ll) {
			tinfo->numLastMs++;
		}
		else {
			tinfo->lastMs = ll;
			tinfo->numLastMs = 0;
		}

		// Reset the sleep value
		if (tinfo->numLastMs >= 5) {
			li->QuadPart = 0;
		}
		else {
			if (tinfo->sleepTime == 0)
				li->QuadPart = -BP_TIMER * 10000LL;
			else
				li->QuadPart = -tinfo->sleepTime * 10000LL;
		}
	}

	/* ===================================================================== */
	/* Handle the NtCreateFile API (Virtualbox/VMware files access)          */
	/* ===================================================================== */
	VOID NtCreateFile_entry(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::OBJECT_ATTRIBUTES *Obj = (W::OBJECT_ATTRIBUTES*)sc->arg2;
		W::ULONG mode = (W::ULONG)sc->arg7;
		W::PUNICODE_STRING p = Obj->ObjectName;
		State::apiOutputs* apiOutputs = State::getApiOutputs();

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(p->Buffer, value, PATH_BUFSIZE); 
		apiOutputs->ntCreateFileBuffer = p->Buffer;
		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			if (_knobBypass) {
				char logName[256] = "NtCreateFile ";
				strcat(logName, value);
				logModule->logBypass(logName);
				//VBOXGUEST pass for Obsidium anti-vm and anti-dbi
				char* defaultGenericFilenames[] = { "VBOXGUEST", NULL };
				if (lookupSubstring(value, defaultGenericFilenames) && mode == 1) {
					apiOutputs->obsidiumCreateFile = true;
				}
				for (W::USHORT i = p->Length - 8; i < p->Length - 1; i += 2) {
					memcpy((char*)p->Buffer + i, WSTR_CREATEFILE, sizeof(wchar_t));
					PIN_SafeCopy((char*)p->Buffer + i, WSTR_CREATEFILE, sizeof(wchar_t));
				}
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtCreateFile API (Virtualbox/VMware files access)          */
	/* ===================================================================== */
	VOID NtCreateFile_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::PHANDLE handle = (W::PHANDLE)sc->arg0;
		W::OBJECT_ATTRIBUTES* Obj = (W::OBJECT_ATTRIBUTES*)sc->arg2;
		W::ULONG mode = (W::ULONG)sc->arg7;
		W::PUNICODE_STRING p = Obj->ObjectName;
		State::apiOutputs* apiOutputs = State::getApiOutputs();

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(apiOutputs->ntCreateFileBuffer, value, PATH_BUFSIZE);
		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			// High false positive rate, taint only suspicious files
#if TAINT_NTCREATEFILE
			logHookId(ctx, "NtCreateFile", (ADDRINT)handle, sizeof(W::HANDLE));
			addTaintMemory(ctx, (ADDRINT)handle, sizeof(W::HANDLE), TAINT_COLOR_1, true, "NtCreateFile");
#endif
			if (apiOutputs->obsidiumCreateFile && _knobBypass) {
				PIN_SetContextReg(ctx, REG_GAX, -1);
				apiOutputs->obsidiumCreateFile = false;
			}
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
				char logName[256] = "NtOpenKey ";
				strcat(logName, value);
				logModule->logBypass(logName);
				W::CloseHandle(*khandle);
				*khandle = (W::HANDLE) - 1;
				ADDRINT _eax = CODEFORINVALIDHANDLE;
				PIN_SetContextReg(ctx, REG_GAX, _eax);
			}
#if TAINT_NTOPENKEY
			// Taint registry handler
			TAINT_TAG_REG(ctx, GPR_EAX, 1, 1, 1, 1);
			// High false positive rate, taint only suspicious registry access
			logHookId(ctx, "NtOpenKey", (ADDRINT)khandle, sizeof(W::HANDLE));
			addTaintMemory(ctx, (ADDRINT)khandle, sizeof(W::HANDLE), TAINT_COLOR_1, true, "NtOpenKey");
#endif
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
					logModule->logBypass("NTQIP-ProcessDebugFlags");
					*((W::ULONG*)ProcessInformation) = PROCESS_DEBUG_INHERIT;
				}
#if TAINT_NTQIP_DEBUGFLAG
				logHookId(ctx, "NTQIP-ProcessDebugFlags", (ADDRINT)ProcessInformation, ProcessInformationLength);
				addTaintMemory(ctx, (ADDRINT)ProcessInformation, ProcessInformationLength, TAINT_COLOR_1, true, "NTQIP-ProcessDebugFlags");
#endif
			}			
			else if (ProcessInformationClass == ProcessDebugObjectHandle) {
				// Set return value to STATUS_PORT_NOT_SET
				if (_knobBypass) {
					logModule->logBypass("NTQIP-ProcessDebugObjectHandle");
					*((W::HANDLE *)ProcessInformation) = (W::HANDLE)0;
					ADDRINT _eax = CODEFORSTATUSPORTNOTSET;
					PIN_SetContextReg(ctx, REG_GAX, _eax);
				}
#if TAINT_NTQIP_DEBUGOBJECT
				logHookId(ctx, "NTQIP-ProcessDebugObjectHandle", (ADDRINT)ProcessInformation, ProcessInformationLength);
				addTaintMemory(ctx, (ADDRINT)ProcessInformation, ProcessInformationLength, TAINT_COLOR_1, true, "NTQIP-ProcessDebugObjectHandle");
#endif
			}
			else if (ProcessInformationClass == ProcessDebugPort) {
				// Set debug port to null
				if (_knobBypass) {
					logModule->logBypass("NTQIP-ProcessDebugPort");
					*((W::HANDLE *)ProcessInformation) = (W::HANDLE)0;
				}
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
		if (sc->arg0 == SystemProcessInformation) {
			//cast to our structure in order to retrieve the information returned from the NtSystemQueryInformation function
			PSYSTEM_PROCESS_INFO spi;
			spi = (PSYSTEM_PROCESS_INFO)sc->arg1;
			W::ULONG s = (W::ULONG)sc->arg2;
			//avoid null pointer exception
			if (spi == NULL)
				return;

			while (spi->NextEntryOffset) {

				if (spi->ImageName.Buffer != nullptr) {
					char value[PATH_BUFSIZE];
					GET_STR_TO_UPPER(spi->ImageName.Buffer, value, PATH_BUFSIZE);
					if (_knobBypass) {
						logModule->logBypass("NtQSI-SystemProcessInformation");
						if (HiddenElements::shouldHideProcessStr(value)) {
							PIN_SafeCopy(spi->ImageName.Buffer, BP_FAKEPROCESSW, sizeof(BP_FAKEPROCESSW));
						}
					}
#if TAINT_NTQSI_PROCESSINFO
					logHookId(ctx, "NTQSI-SystemProcessInformation", (ADDRINT)spi, s);
					TAINT_TAG_REG(ctx, GPR_EAX, TAINT_COLOR_5, TAINT_COLOR_5, TAINT_COLOR_5, TAINT_COLOR_5);

					addTaintMemory(ctx, (ADDRINT) & (spi->NextEntryOffset), sizeof(W::ULONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->NumberOfThreads), sizeof(W::ULONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");

					addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.HighPart), sizeof(W::LONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.LowPart), sizeof(W::DWORD), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.u.HighPart), sizeof(W::LONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.u.LowPart), sizeof(W::DWORD), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.QuadPart), sizeof(W::LONGLONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");

					addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.HighPart), sizeof(W::LONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.LowPart), sizeof(W::DWORD), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.u.HighPart), sizeof(W::LONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.u.LowPart), sizeof(W::DWORD), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.QuadPart), sizeof(W::LONGLONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");

					addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.HighPart), sizeof(W::LONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.LowPart), sizeof(W::DWORD), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.u.HighPart), sizeof(W::LONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.u.LowPart), sizeof(W::DWORD), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.QuadPart), sizeof(W::LONGLONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");

					addTaintMemory(ctx, (ADDRINT)(spi->ImageName.Buffer), spi->ImageName.Length, TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->BasePriority), sizeof(W::ULONG), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->ProcessId), sizeof(W::HANDLE), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
					addTaintMemory(ctx, (ADDRINT) & (spi->InheritedFromProcessId), sizeof(W::HANDLE), TAINT_COLOR_5, true, "NTQSI-SystemProcessInformation");
#endif
				}
				spi = (PSYSTEM_PROCESS_INFO)((W::LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry
			}
		}
		else if (sc->arg0 == SystemModuleInformation) {

			PRTL_PROCESS_MODULES pmi = (PRTL_PROCESS_MODULES)sc->arg1;

			if (pmi == NULL)
				return;

			if ((W::ULONG*)sc->arg3 == nullptr) 
				return;

			ADDRINT sizeOut = *(W::ULONG*)sc->arg3;
			ADDRINT sizeIn = (W::ULONG)sc->arg2;
			W::ULONG s = (W::ULONG)sc->arg2;
			if (sizeOut > sizeIn) 
				return;

			unsigned long size = pmi->NumberOfModules;

#if TAINT_NTQSI_MODULEINFO
			logHookId(ctx, "NTQSI-SystemModuleInformation", (ADDRINT)pmi, s);
#endif

			for (size_t i = 0; i < size; i++) {
				if (strstr((char*)pmi->Modules[i].FullPathName, "VBox") != NULL) {

					TAINT_TAG_REG(ctx, GPR_EAX, TAINT_COLOR_4, TAINT_COLOR_4, TAINT_COLOR_4, TAINT_COLOR_4);

					char* tmpAddr = (char*)pmi->Modules[i].FullPathName;
					size_t len = strlen(tmpAddr) + 1;
#if TAINT_NTQSI_MODULEINFO
					addTaintMemory(ctx, (ADDRINT) & (pmi->NumberOfModules), sizeof(W::ULONG), TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].Section), sizeof(W::HANDLE), TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT)(pmi->Modules[i].MappedBase), 4U, TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT)(pmi->Modules[i].ImageBase), 4U, TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].ImageSize), sizeof(W::ULONG), TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].Flags), sizeof(W::ULONG), TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].LoadOrderIndex), sizeof(W::USHORT), TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].InitOrderIndex), sizeof(W::USHORT), TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].LoadCount), sizeof(W::USHORT), TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].OffsetToFileName), sizeof(W::USHORT), TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
					addTaintMemory(ctx, (ADDRINT)(pmi->Modules[i].FullPathName), len, TAINT_COLOR_4, true, "NTQSI-SystemModuleInformation");
#endif
					for (size_t i = 0; i < len - 1; i++) {
						if(_knobBypass)
							PIN_SafeCopy(tmpAddr + i, "a", sizeof(char));
					}
				}
			}
		}
		else if (sc->arg0 == SystemFirmwareTableInformation) {
			PSYSTEM_FIRMWARE_TABLE_INFORMATION sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
			if (sfti->Action == SystemFirmwareTable_Get) {
				ADDRINT sizeOut = *(W::ULONG*)sc->arg3;
				ADDRINT sizeIn = (W::ULONG)sc->arg2;
				if (sizeOut > sizeIn) return;

				// Virtualbox part
				// different colors for each suspicious string
				char vbox[] = { "VirtualBox" };
				char vbox2[] = { "vbox" };
				char vbox3[] = { "VBOX" };
				char vbox4[] = { "Virtual Machine" };
				char escape[] = { "aaaaaaaaaa" };
				char escape2[] = { "aaaa" };
				char escape3[] = { "aaaaaaa aaaaaaa" };
				W::ULONG sizeVbox = (W::ULONG)Helper::_strlen_a(vbox);
				W::ULONG sizeVbox2 = (W::ULONG)Helper::_strlen_a(vbox2);
				W::ULONG sizeVbox3 = (W::ULONG)Helper::_strlen_a(vbox3);
				W::ULONG sizeVbox4 = (W::ULONG)Helper::_strlen_a(vbox4);

				PSYSTEM_FIRMWARE_TABLE_INFORMATION info = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
				// Scan entire bios in order to find vbox strings
				logModule->logBypass("NtQSI-SystemFirmwareTableInformation VBox");
				for (size_t i = 0; i < info->TableBufferLength - sizeVbox; i++) {
					if (memcmp(info->TableBuffer + i, vbox, sizeVbox) == 0 && _knobBypass) {
						PIN_SafeCopy(info->TableBuffer + i, escape, sizeof(escape));
					}
					else if (memcmp(info->TableBuffer + i, vbox2, sizeVbox2) == 0 ||
						memcmp(info->TableBuffer + i, vbox3, sizeVbox3) == 0 && _knobBypass) {
						PIN_SafeCopy(info->TableBuffer + i, escape2, sizeof(escape2));
					}
					else if (memcmp(info->TableBuffer + i, vbox4, sizeVbox4) == 0) {
						PIN_SafeCopy(info->TableBuffer + i, escape3, sizeof(escape3));
					}
				}

				// Scan entire bios in order to find VMware string
				char vmware[] = { "VMware" };
				char vmware2[] = { "Virtual Machine" };
				char escape4[] = { "aaaaaa" };
				char escape5[] = { "aaaaaaa aaaaaaa" };
				W::ULONG vmwareSize = (W::ULONG)Helper::_strlen_a(vmware);
				W::ULONG vmwareSize2 = (W::ULONG)Helper::_strlen_a(vmware2);

				logModule->logBypass("NtQSI-SystemFirmwareTableInformation VMWare");
				for (size_t i = 0; i < info->TableBufferLength - vmwareSize; i++) {
					if (memcmp(info->TableBuffer + i, vmware, vmwareSize) == 0 && _knobBypass) {
						PIN_SafeCopy(info->TableBuffer + i, escape4, sizeof(escape4));
					}
					else if (memcmp(info->TableBuffer + i, vmware2, vmwareSize2) == 0) {
						PIN_SafeCopy(info->TableBuffer + i, escape5, sizeof(escape5));
					}
				}

				// Bypass a possible signature detection
				PIN_SetContextReg(ctx, REG_EAX, 0);

				// Taint the table buffer
#if TAINT_NTQSI_FIRMWAREINFO
				logHookId(ctx, "NtQSI-SystemFirmwareTableInformation", (ADDRINT)info->TableBuffer, info->TableBufferLength);
				addTaintMemory(ctx, (ADDRINT)info->TableBuffer, info->TableBufferLength, TAINT_COLOR_1, true, "NtQSI-SystemFirmwareTableInformation");
#endif
			}
		}
		else if (sc->arg0 == SystemKernelDebuggerInformation) {
			PSYSTEM_KERNEL_DEBUGGER_INFORMATION skdi = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)sc->arg1;
			W::ULONG s = (W::ULONG)sc->arg2;
			logModule->logBypass("NtQSI-SystemKernelDebuggerInformation");
#if TAINT_NTQSI_KERNELINFO
			logHookId(ctx, "NtQSI-SystemKernelDebuggerInformation", (ADDRINT)skdi, s);
			TAINT_TAG_REG(ctx, GPR_EAX, TAINT_COLOR_6, TAINT_COLOR_6, TAINT_COLOR_6, TAINT_COLOR_6);
			addTaintMemory(ctx, (ADDRINT) & (skdi->KernelDebuggerEnabled), sizeof(W::BOOLEAN), TAINT_COLOR_6, true, "NtQSI-SystemKernelDebuggerInformation");
			addTaintMemory(ctx, (ADDRINT) & (skdi->KernelDebuggerNotPresent), sizeof(W::BOOLEAN), TAINT_COLOR_6, true, "NtQSI-SystemKernelDebuggerInformation");
#endif
		}
	}

	/* ===================================================================== */
	/* Handle the NtQueryAttributesFile API (file information access)        */
	/* ===================================================================== */
	VOID NtQueryAttributesFile_entry(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::OBJECT_ATTRIBUTES* Obj = (W::OBJECT_ATTRIBUTES*)sc->arg0;
		W::PUNICODE_STRING p = Obj->ObjectName;
		State::apiOutputs* apiOutputs = State::getApiOutputs();

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(p->Buffer, value, PATH_BUFSIZE); 
		apiOutputs->ntQueryAttributesFileBuffer = p->Buffer;

		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			char logName[256] = "NtQueryAttributesFile ";
			strcat(logName, value);
			logModule->logBypass(logName);
			for (W::USHORT i = p->Length - 8; i < p->Length - 1; i += 2) {
				PIN_SafeCopy((char*)p->Buffer + i, WSTR_FILE, sizeof(wchar_t));
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtQueryAttributesFile API (file information access)        */
	/* ===================================================================== */
	VOID NtQueryAttributesFile_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::OBJECT_ATTRIBUTES* Obj = (W::OBJECT_ATTRIBUTES*)sc->arg0;
		W::FILE_BASIC_INFO* basicInfo = (W::FILE_BASIC_INFO*)sc->arg1;
		W::PUNICODE_STRING p = Obj->ObjectName;
		State::apiOutputs* apiOutputs = State::getApiOutputs();

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(apiOutputs->ntQueryAttributesFileBuffer, value, PATH_BUFSIZE);

		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
#if TAINT_NTQUERYATTRIBUTESFILE
			TAINT_TAG_REG(ctx, GPR_EAX, TAINT_COLOR_1, TAINT_COLOR_1, TAINT_COLOR_1, TAINT_COLOR_1);
			logHookId(ctx, "NtQueryAttributesFile", (ADDRINT)basicInfo, sizeof(W::FILE_BASIC_INFO));
			//Tainting the wholw FILE_BASIC_INFO data structure
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.HighPart), sizeof(W::LONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.LowPart), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.u.HighPart), sizeof(W::LONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.u.LowPart), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.QuadPart), sizeof(W::LONGLONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");

			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.HighPart), sizeof(W::LONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.LowPart), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.u.HighPart), sizeof(W::LONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.u.LowPart), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.QuadPart), sizeof(W::LONGLONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");

			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.HighPart), sizeof(W::LONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.LowPart), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.u.HighPart), sizeof(W::LONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.u.LowPart), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.QuadPart), sizeof(W::LONGLONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");

			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.HighPart), sizeof(W::LONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.LowPart), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.u.HighPart), sizeof(W::LONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.u.LowPart), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.QuadPart), sizeof(W::LONGLONG), TAINT_COLOR_1, true, "NtQueryAttributesFile");

			addTaintMemory(ctx, (ADDRINT) & (basicInfo->FileAttributes), sizeof(W::DWORD), TAINT_COLOR_1, true, "NtQueryAttributesFile");
#endif
		}
	}

	/* ===================================================================== */
	/* Handle the NtUserFindWindowEx API (Virtualbox/VMware window access)   */
	/* ===================================================================== */
	VOID NtUserFindWindowEx_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::PUNICODE_STRING path1 = (W::PUNICODE_STRING)sc->arg2;
		W::PUNICODE_STRING path2 = (W::PUNICODE_STRING)sc->arg3;

		char value[PATH_BUFSIZE] = { 0 };

		if (_knobBypass) {
			// Bypass the first path
			if (path1 != NULL && path1->Buffer != NULL) {
				GET_STR_TO_UPPER(path1->Buffer, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideWindowStr(value)) {
					char logName[256] = "FindWindow ";
					strcat(logName, value);
					logModule->logBypass(logName);
					ADDRINT _eax = 0;
					PIN_SetContextReg(ctx, REG_GAX, _eax);
				}
			}

			// Bypass the second path
			if (path2 != NULL && path2->Buffer != NULL) {
				memset(value, 0, PATH_BUFSIZE);
				GET_STR_TO_UPPER(path2->Buffer, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideWindowStr(value)) {
					char logName[256] = "FindWindow ";
					strcat(logName, value);
					logModule->logBypass(logName);					
					ADDRINT _eax = 0;
					PIN_SetContextReg(ctx, REG_GAX, _eax);
				}
			}
		}
		// Taint registry handler
#if TAINT_NTFINDWINDOW
		TAINT_TAG_REG(ctx, GPR_EAX, 1, 1, 1, 1);
#endif
	}
}
