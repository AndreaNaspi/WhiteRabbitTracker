#include "ProcessInfo.h"

/* ===================================================================== */
/* Check if the foreign module name is equal to my module name           */
/* ===================================================================== */
bool ProcessInfo::is_my_name(const std::string & module_name, std::string my_name) {
    std::size_t found = module_name.find(my_name);
    if (found != std::string::npos) {
        return true;
    }
    return false;
}

/* ===================================================================== */
/* Add a new module to our process                                       */
/* ===================================================================== */
bool ProcessInfo::addModule(IMG Image) {
	// If this module is an object of observation, add its sections also
	if (m_myPid == 0 && is_my_name(IMG_Name(Image), m_AnalysedApp)) {
		m_myPid = PIN_GetPid();
		myModuleBase = IMG_LoadOffset(Image);
		// Enumerate sections and add to the module
		addModuleSections(Image, myModuleBase);
	}
	return true;
}

/* ===================================================================== */
/* Enumerate and add sections to the new module                          */
/* ===================================================================== */
void ProcessInfo::addModuleSections(IMG Image, ADDRINT ImageBase) {
    for (SEC sec = IMG_SecHead(Image); SEC_Valid(sec); sec = SEC_Next(sec)) {
		// Create and init the new section
        s_module section;
        init_section(section, ImageBase, sec);
		// Append the new section to the map m_sections (this map contains pairs: <section.start, section>)
        m_Sections[section.start] = section;
    }
}

/* ===================================================================== */
/* Saves transition between sections within the target module            */
/* Input: current RVA within the target module                           */
/* Output: true if the section chagned, false otherwise                  */
/* ===================================================================== */
const bool ProcessInfo::updateTracedModuleSection(ADDRINT Rva) {
    // Saved section of the target module (initialize to null pointer)
    static s_module* prevSec = nullptr;

    // Current section of the target module (by RVA)
    const s_module* currSec = getSecByAddr(Rva);

	// If the sections are different, update the stored section and return true
    if (prevSec != currSec) {
        prevSec = (s_module*)currSec;
        return true;
    }
	// Otherwise, return false
    return false;
}

/* ===================================================================== */
/* Function to add the current image to the interval tree                */
/* ===================================================================== */
void ProcessInfo::addCurrentImageToTree(IMG img) {
	if (IMG_IsMainExecutable(img)) {
		return;
	}
	// Get the current image name (e.g. DLL name)
	const char* imgName = IMG_Name(img).c_str();
	char* data = strdup(imgName);
	size_t len = strlen(data) + 1;
	while (len--) 
		data[len] = tolower(data[len]);

	// Consider only Windows images (e.g. Windows DLLs)
	if (strstr(data, "windows\\system32\\") || strstr(data, "windows\\syswow64\\") || strstr(data, "windows\\winsxs\\")) {
		// Get the image start address
		ADDRINT imgStart = IMG_LowAddress(img);

		// Get the image end address
		ADDRINT imgEnd = IMG_HighAddress(img);

		// Access to global state
		PIN_LockClient();
		State::globalState* gs = State::getGlobalState();

		// Parse the export table of the current image
		/*
		std::map<W::DWORD, std::string> exportsMap;
		std::map<W::DWORD, W::DWORD> rvaToFileOffsetMap;
		std::cerr << imgName << std::endl;
		parseExportTable((W::PBYTE)imgStart, exportsMap, rvaToFileOffsetMap, false);
		std::cerr << "\n" << std::endl;
		for (auto const& p : exportsMap)
		{
			std::cout << p.first << ' ' << p.second << '\n';
		}*/



		// If the interval tree does not exist, create it
		if (gs->dllRangeITree == NULL) {
			gs->dllRangeITree = itree_init(imgStart, imgEnd, (void*)data);
		}
		// Else, add the current image to the interval tree
		else {
			bool success = itree_insert(gs->dllRangeITree, imgStart, imgEnd, (void*)data);
			// Check for possible error
			if (!success) {
				fprintf(stderr, "==> Duplicate range insertion for DLL %s\n", data);
			}
		}
		PIN_UnlockClient();

		// Check if the resulting tree is valid
		bool validIntervalTree = itree_verify(gs->dllRangeITree);
		if (!validIntervalTree) {
			itree_print(gs->dllRangeITree, 0);
			ASSERT(false, "Broken DLL interval tree");
		}

	}
	else {
		free(data);
		return;
	}

}

/* ===================================================================== */
/* Function to remove the current image from the interval tree           */
/* ===================================================================== */
void ProcessInfo::removeCurrentImageFromTree(IMG img) {
	// We only want to track main executable images
	if (IMG_IsMainExecutable(img)) {
		return;
	}

	// Get the image start address
	ADDRINT imgStart = IMG_LowAddress(img);
	// Get the image end address 
	ADDRINT imgEnd = IMG_HighAddress(img);
	// Access to global state
	PIN_LockClient();
	State::globalState* gs = State::getGlobalState();
	// Check if the interval tree exists
	if (gs->dllRangeITree) {
		// Delete the unloaded image
		gs->dllRangeITree = itree_delete(gs->dllRangeITree, imgStart, imgEnd);
		// Check if the resulting tree is valid
		bool validIntervalTree = itree_verify(gs->dllRangeITree);
		if (!validIntervalTree) {
			itree_print(gs->dllRangeITree, 0);
			ASSERT(false, "Broken DLL interval tree");
		}
	}
	PIN_UnlockClient();
}

static W::PIMAGE_SECTION_HEADER peGetEnclosingSectionHeader(W::DWORD rva, W::PIMAGE_NT_HEADERS32 pNTHeader) {
	W::PIMAGE_SECTION_HEADER section = (W::PIMAGE_SECTION_HEADER)((W::ULONG_PTR)(pNTHeader) 
		                                                          + FIELD_OFFSET(W::IMAGE_NT_HEADERS, OptionalHeader) 
		                                                          + ((pNTHeader))->FileHeader.SizeOfOptionalHeader);
	unsigned i;
	for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++) {
		W::DWORD size = section->Misc.VirtualSize;
		if (0 == size)
			size = section->SizeOfRawData;
		if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
			return section;
	}
	return 0;
}

static W::LPVOID peGetPtrFromRVA(W::DWORD rva, W::PIMAGE_NT_HEADERS32 pNTHeader, W::PBYTE imageBase) {
	W::PIMAGE_SECTION_HEADER pSectionHdr;
	int delta;

	pSectionHdr = peGetEnclosingSectionHeader(rva, pNTHeader);
	if (!pSectionHdr)
		return 0;

	delta = (int)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
	return (W::PVOID)(imageBase + rva - delta);
}


/* ===================================================================== */
/* Function to parse the export table of a certain image                 */
/* ===================================================================== */
bool ProcessInfo::parseExportTable(W::PBYTE pImageBase, std::map<W::DWORD, std::string> &exportsMap, std::map<W::DWORD, W::DWORD> &rvaToFileOffsetMap, bool addFwdAndData) {
	W::PIMAGE_DOS_HEADER dosHeader = (W::PIMAGE_DOS_HEADER)pImageBase;

	W::PIMAGE_NT_HEADERS32 pNTHeader = MakePtr(W::PIMAGE_NT_HEADERS32, dosHeader, dosHeader->e_lfanew);
	if(pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		fprintf(stderr, "IMAGE_NT_OPTIONAL_HDR64_MAGIC not supported yet\n");
		return false;
	}

	W::PIMAGE_EXPORT_DIRECTORY pExportDir;
	W::PIMAGE_SECTION_HEADER header;
	W::PDWORD pdwFunctions = NULL;
	W::PDWORD pszFuncNames = NULL;
	W::PWORD pwOrdinals = NULL;
	W::DWORD exportsStartRVA, exportsEndRVA;

	exportsStartRVA = GetImgDirEntryRVA(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);
	exportsEndRVA = exportsStartRVA + GetImgDirEntrySize(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);

	header = peGetEnclosingSectionHeader(exportsStartRVA, pNTHeader);
	if (!header) {
		fprintf(stderr, "Could not find Exports header!\n");
		return false;
	}

	pExportDir = (W::PIMAGE_EXPORT_DIRECTORY)peGetPtrFromRVA(exportsStartRVA, pNTHeader, pImageBase);
	pdwFunctions = (W::PDWORD)peGetPtrFromRVA(pExportDir->AddressOfFunctions, pNTHeader, pImageBase);
	pwOrdinals = (W::PWORD)peGetPtrFromRVA(pExportDir->AddressOfNameOrdinals, pNTHeader, pImageBase);
	pszFuncNames = (W::PDWORD)peGetPtrFromRVA(pExportDir->AddressOfNames, pNTHeader, pImageBase);
	
	if (!pExportDir || !pdwFunctions || !pwOrdinals || !pszFuncNames) {
		fprintf(stderr, "Some PE fields seem just not okay!\n");
		return false;
	}

	size_t forwarders = 0, data = 0;
	size_t unnamed = pExportDir->NumberOfFunctions - pExportDir->NumberOfNames;

	W::DWORD fixAddr = header->VirtualAddress - header->PointerToRawData;
	for (size_t j = 0; j < pExportDir->NumberOfNames; ++j) {
		W::DWORD addr_name = pszFuncNames[j];
		W::DWORD rva = pdwFunctions[pwOrdinals[j]];
		W::PCHAR name = (W::PCHAR)(pImageBase + addr_name - fixAddr);

		if (exportsStartRVA <= rva && rva < exportsEndRVA) {
			forwarders++;
			if (addFwdAndData) {
				exportsMap.insert(std::make_pair(0, name));
			}
			continue;
		}

		W::PIMAGE_SECTION_HEADER section = peGetEnclosingSectionHeader(rva, pNTHeader);
		W::DWORD fileOffset = (rva - section->VirtualAddress + section->PointerToRawData);

		if (section->Characteristics & IMAGE_SCN_CNT_CODE) {
			exportsMap.insert(std::make_pair(rva, name));
			rvaToFileOffsetMap.insert(std::make_pair(rva, fileOffset));
		}
	}
	return true;
}