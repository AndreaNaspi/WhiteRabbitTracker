#include "ModuleInfo.h"
#include <string>

/* ===================================================================== */
/* Init the current section (populate struct variables)                  */
/* ===================================================================== */
bool init_section(s_module &section, const ADDRINT &ImageBase, const SEC &sec) {
	// Check if the real virtual address of the section is outside the image
    if (SEC_Address(sec) < ImageBase) {
        return false;
    }
	// Get section name
    section.name = SEC_Name(sec);
	// Get section start address (real virtual address of section - image base)
    section.start = SEC_Address(sec) - ImageBase;
	// Get section end address (real virtual address of section + section size)
    section.end = section.start + SEC_Size(sec);

    return true;
}

/* ===================================================================== */
/* Utility function to get a section from an address                     */
/* ===================================================================== */
const s_module* get_by_addr(ADDRINT Address, std::map<ADDRINT, s_module> &modules) {
	// Get an iterator to upper bound of the address
    std::map<ADDRINT, s_module>::iterator bound = modules.upper_bound(Address);
	// Get an iterator to the first element of the map (section module container)
    std::map<ADDRINT, s_module>::iterator itr = modules.begin();

	// Iterate until upper bound
    for (; itr != bound; itr++) {
		// Get second element from the iterator (get the s_module struct)
        s_module &mod = itr->second;
		// If our address is between section start and section end, return the current section
        if (Address >= mod.start && Address < mod.end) {
            return &mod;
        }
    }
	// Otherwise, return null pointer (not found)
    return nullptr;
}

/* ===================================================================== */
/* Get a function at a specific address                                  */
/* ===================================================================== */
std::string get_func_at(ADDRINT callAddr) {
	// Get the associated image and check if is valid
    IMG pImg = IMG_FindByAddress(callAddr);
    if (!IMG_Valid(pImg)) {
		// Return error message if not valid
        std::ostringstream sstr;
        sstr << "[ " << callAddr << "]*";
        return sstr.str();
    }
	// Get base address (offset) from the image
    const ADDRINT base = IMG_LoadOffset(pImg);
	// Get the address associated to the routine (RTN)
    RTN rtn = RTN_FindByAddress(callAddr);
	// Check if the routine is valid
    if (!RTN_Valid(rtn)) {
		// Return error message if not valid
        std::ostringstream sstr;
        sstr << "[ + " << (callAddr - base) << "]*";
        return sstr.str();
    }
	// Get routine name
    std::string name = RTN_Name(rtn);
	// Get routine address
    ADDRINT rtnAddr = RTN_Address(rtn);
	// If the address correspond to the routine address, return routine name
    if (rtnAddr == callAddr) {
        return name;
    }
    // Otherwise, it means that the address doesn't start at the beginning of the routine, so return the difference from the routine address
    const ADDRINT diff = callAddr - rtnAddr;
    std::ostringstream sstr;
    sstr << "[" << name << "+" << std::hex << diff << "]*";
    return sstr.str();
}

/* ===================================================================== */
/* Utility function to get offset from an address,                       */
/* otherwise return page address                                         */
/* ===================================================================== */
ADDRINT get_mod_base(ADDRINT Address) {
	IMG img = IMG_FindByAddress(Address);
	// If image is valid, return offset
	if (IMG_Valid(img)) {
		const ADDRINT base = IMG_LoadOffset(img);
		return base;
	}
	// Otherwise, return unknown address
	return UNKNOWN_ADDR;
}
ADDRINT get_base(ADDRINT Address) {
	ADDRINT base = get_mod_base(Address);
	// If the address is known, return offset
	if (base != UNKNOWN_ADDR) {
		return base;
	}
	// Otherwise, return page address
	return GetPageOfAddr(Address);
}

/* ===================================================================== */
/* Get relative virtual address from an address (address - base)         */
/* ===================================================================== */
ADDRINT addr_to_rva(ADDRINT Address) {
	// Get base address
    ADDRINT base = get_base(Address);
    if (base == UNKNOWN_ADDR) {
        return Address;
    }
	// Subtract base from address and return it
    return Address - base;
}
