#include "syshooks.h"
#include "memory.h"
#include "state.h"
#include "HiddenElements.h"
#include "helper.h"

namespace SYSHOOKS {

	VOID NtQuerySystemInformation_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {

		if (sc->arg0 == SystemProcessInformation) {
			// Cast to our structure to retrieve the information returned from the NtSystemQueryInformation function
			PSYSTEM_PROCESS_INFO spi = (PSYSTEM_PROCESS_INFO)sc->arg1;
			// Avoid null pointer exception
			if (spi == NULL) 
				return; 
			// Iterate through all processes 
			while (spi->NextEntryOffset) {
				if (spi->ImageName.Buffer != nullptr) {
					char value[PATH_BUFSIZE];
					GET_STR_TO_UPPER(spi->ImageName.Buffer, value, PATH_BUFSIZE);
					std::cerr << "SYSTEM HOOKING " << value << std::endl;
					if (HiddenElements::shouldHideProcessStr(value)) {
						PIN_SafeCopy(spi->ImageName.Buffer, BP_FAKEPROCESSW, sizeof(BP_FAKEPROCESSW));
					}
				}
				// Calculate the address of the next entry.
				spi = (PSYSTEM_PROCESS_INFO)((W::LPBYTE)spi + spi->NextEntryOffset);
			}

		}
	}
}
