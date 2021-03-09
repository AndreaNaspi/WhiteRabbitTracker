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