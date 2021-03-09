#pragma once

#include "pin.H"

#include <map>
#include <iostream>
#include "state.h"
#include "itree.h"
#include "ModuleInfo.h"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;

#define UNKNOWN_ADDR ~ADDRINT(0)

class ProcessInfo
{
public:
	/* ===================================================================== */
	/* ProcessInfo constructor with default values                           */
	/* ===================================================================== */
    ProcessInfo(): m_myPid(0), isInit(false) {
    }

	/* ===================================================================== */
	/* Initialization function                                               */
	/* ===================================================================== */
    bool init(std::string app) {
		// check if already initialized (singleton)
        if (isInit) {
            return false;
        }
		isInit = true;
		// initialize app
        m_AnalysedApp = app;
        // unknown pid
		m_myPid = 0;  
        // unknown module
		myModuleBase = UNKNOWN_ADDR;
        return true;
    }

	/* ===================================================================== */
	/* Check if the foreign module name is equal to my module name           */
	/* ===================================================================== */
	bool is_my_name(const std::string &module_name, std::string my_name);

	/* ===================================================================== */
	/* Add a new module to our process                                       */
	/* ===================================================================== */
    bool addModule(IMG Image);

	/* ===================================================================== */
	/* Enumerate and add sections to the new module                          */
	/* ===================================================================== */
	void addModuleSections(IMG Image, ADDRINT ImageBase);

	/* ===================================================================== */
	/* Saves transition between sections within the target module            */
	/* Input: current RVA within the target module                           */
	/* Output: true if the section chagned, false otherwise                  */
	/* ===================================================================== */
	const bool updateTracedModuleSection(ADDRINT Rva);

	/* ===================================================================== */
	/* Function to add the current image to the interval tree                */
	/* ===================================================================== */
	void addCurrentImageToTree(IMG img);

	/* ===================================================================== */
	/* Function to remove the current image from the interval tree           */
	/* ===================================================================== */
	void removeCurrentImageFromTree(IMG img);

	/* ===================================================================== */
	/* Utility function to get a section from an address (return a section)  */
	/* ===================================================================== */
    const s_module* getSecByAddr(ADDRINT Address) {
        return get_by_addr(Address, m_Sections);
    }

	/* ===================================================================== */
	/* Utility function to check if an address is in the same image          */
	/* ===================================================================== */
    bool isMyAddress(ADDRINT Address) {
		// Check if is an unknown address
        if (Address == UNKNOWN_ADDR) {
            return false;
        }
		// Get my image and foreign image
        IMG myImg = IMG_FindByAddress(myModuleBase);
        IMG otherImg = IMG_FindByAddress(Address);
		// Check if the images are both valid
        if (!IMG_Valid(myImg) || !IMG_Valid(otherImg)) {
            return false;
        }
		// Check if the images offset are equal
        if (IMG_LoadOffset(myImg) == IMG_LoadOffset(otherImg)) {
            return true;
        }
        return false;
    }
    
protected:
	/* ===================================================================== */
	/* Define variables                                                      */
	/* ===================================================================== */
	
	// Map of sections (this map contains pairs: <section.start, section>)
    std::map<ADDRINT, s_module> m_Sections;
    // Module base address
	ADDRINT myModuleBase;
	// Application name (e.g. sample.exe)
    std::string m_AnalysedApp;
	// Process PID
    INT m_myPid;
	// Init boolean variable (singleton)
    bool isInit;
};

