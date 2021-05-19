#pragma once
#include "pin.H"

#include <iostream>
#include <fstream>

#define MAIN_LOG_NAME "profile.log"
#define CALLSTACK_LOG_NAME "callstack.log"

class LoggingInfo
{
public:
	/* ===================================================================== */
	/* LoggingInfo constructor                                               */
	/* ===================================================================== */
	LoggingInfo() {
	}

	/* ===================================================================== */
	/* LoggingInfo deconstructor (destroy instance, free up memory)          */
	/* ===================================================================== */
	~LoggingInfo() {
		// Close file if already open
		if (m_traceFile.is_open()) {
			m_traceFile.close();
		}
	}

	/* ===================================================================== */
	/* Init function to get file name in input and savea it                  */
	/* ===================================================================== */
	void init(std::string fileName) {
		// Check if file name is empty or null
		if (fileName.empty()) {
			fileName = "profile.log";
		} 
		// Save the file name in a global variable
		m_logFileName = fileName;
		// Create or open the file
		createFile();
	}

	/* ===================================================================== */
	/* Log API call with dll name (module) and function name (func)          */
	/* ===================================================================== */
	void logCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const std::string module, const std::string func = "");
	/* ===================================================================== */
	/* Log call to a called page base (shellcode?)                           */
	/* ===================================================================== */
	void logCall(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT calledPageBase, const ADDRINT callAddr);
	/* ===================================================================== */
	/* Log a section change                                                  */
	/* ===================================================================== */
	void logSectionChange(const ADDRINT addr, std::string sectionName);
	/* ===================================================================== */
	/* Log a new section change                                              */
	/* ===================================================================== */
	void logNewSectionCalled(const ADDRINT addFrom, std::string prevSection, std::string currSection);
	/* ===================================================================== */
	/* Log a new exception                                                   */
	/* ===================================================================== */
	void logException(const ADDRINT addrFrom, std::string reason);
	/* ===================================================================== */
	/* Log a new bypassed instruction/API                                    */
	/* ===================================================================== */
	void logBypass(std::string bypassIdentifier);
	/* ===================================================================== */
	/* Utility function to extract a dll name from module name (parsing)     */
	/* ===================================================================== */
	std::string get_dll_name(const std::string& str);

protected:
	/* ===================================================================== */
	/* Define variables                                                      */
	/* ===================================================================== */
	// File name
	std::string m_logFileName;
	// Output file stream object
	std::ofstream m_traceFile;

	/* ===================================================================== */
	/* Utility function to create or open the output file                    */
	/* ===================================================================== */
	bool createFile() {
		// If is already open, exit
		if (m_traceFile.is_open()) {
			return true;
		}
		// Otherwise, open the file and return the status
		m_traceFile.open(m_logFileName.c_str());
		if (m_traceFile.is_open()) {
			return true;
		}
		return false;
	}
};
