#pragma once

#include "pin.H"

#include <map>

#define UNKNOWN_ADDR ~ADDRINT(0)

/* ===================================================================== */
/* Define a section module structure                                     */
/*   name: section name                                                  */
/*   start: start address of the section                                 */
/*   end: end address of the section                                     */
/*   is_valid: boolean variable to check if a specific section is valid  */
/* ===================================================================== */
struct s_module {
    std::string name;
    ADDRINT start;
    ADDRINT end;
    bool is_valid;
};

/* ===================================================================== */
/* Init the current section (populate struct variables)                  */
/* ===================================================================== */
bool init_section(s_module &section, const ADDRINT &ImageBase, const SEC &sec);

/* ===================================================================== */
/* Utility function to get a section from an address (return a section)  */
/* ===================================================================== */
const s_module* get_by_addr(ADDRINT Address, std::map<ADDRINT, s_module> &modules);

/* ===================================================================== */
/* Get a function at a specific address                                  */
/* ===================================================================== */
std::string get_func_at(ADDRINT callAddr);

/* ===================================================================== */
/* Utility function to get offset from an address,                       */
/* otherwise return page address                                         */
/* ===================================================================== */
ADDRINT get_mod_base(ADDRINT Address);
ADDRINT get_base(ADDRINT Address);

/* ===================================================================== */
/* Get relative virtual address from an address (address - base)         */
/* ===================================================================== */
ADDRINT addr_to_rva(ADDRINT Address);
