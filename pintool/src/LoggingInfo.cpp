#include "LoggingInfo.h"

/* ===================================================================== */
/* Define delimeter (default format: RVA;event)                          */
/* ===================================================================== */
#define DELIMITER ';'

/* ===================================================================== */
/* Utility function to extract a dll name from module name (parsing)     */
/* ===================================================================== */
std::string LoggingInfo::get_dll_name(const std::string& str) {
	std::size_t len = str.length();
	std::size_t found = str.find_last_of("/\\");
	std::size_t ext = str.find_last_of(".");
	if (ext >= len) return "";

	std::string name = str.substr(found + 1, ext - (found + 1));
	std::transform(name.begin(), name.end(), name.begin(), tolower);
	return name;
}

/* ===================================================================== */
/* Log API call with dll name (module) and function name (func)          */
/* ===================================================================== */
void LoggingInfo::logCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const std::string module, const std::string func) {
	// Check if the file exist
	if (!createFile()) {
		return;
	} 
	// Write the RVA address into the output file 
	ADDRINT rva = (isRVA) ? prevAddr : prevAddr - prevModuleBase;
	m_traceFile << "-- " << std::hex << rva << DELIMITER;

	// Extract the DLL name and write it into the output file (substitute with get_dll_name(module) for a short log)
	m_traceFile << get_dll_name(module) << ".dll";

	// If the function name exists, write it into the output file
	if (func.length() > 0) {
		m_traceFile << "." << func;
	}
	// Otherwise, write end line and flush 
	m_traceFile << std::endl;
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log call to a called page base (shellcode?)                           */
/* ===================================================================== */
void LoggingInfo::logCall(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT calledPageBase, const ADDRINT callAddr) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write the called page base and relative RVA to the output file
	if (prevBase) {
		m_traceFile << "> " << prevBase << "+";
	}
	const ADDRINT rva = callAddr - calledPageBase;
	m_traceFile 
		<< "-- "
		<< std::hex << prevAddr
		<< DELIMITER
		<< "called: ?? [" << calledPageBase << "+" << rva << "]"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log a section change                                                  */
/* ===================================================================== */
void LoggingInfo::logSectionChange(const ADDRINT prevAddr, std::string name) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write the section change with relative previous address and section name
	m_traceFile
		<< std::hex << prevAddr
		<< DELIMITER
		<< "section: [" << name << "]"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log a new section change                                              */
/* ===================================================================== */
void LoggingInfo::logNewSectionCalled(const ADDRINT prevAddr, std::string prevSection, std::string currSection) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write a new section change with relative previous address, previous section name and new section name
	m_traceFile
		<< std::hex << prevAddr
		<< DELIMITER
		<< "[" << prevSection << "] -> [" << currSection << "]"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log a new exception                                                   */
/* ===================================================================== */
void LoggingInfo::logException(const ADDRINT addrFrom, std::string reason) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write the new exception with relative previous address
	m_traceFile
		<< "[EXCEPTION] " << 
		std::hex << addrFrom
		<< DELIMITER
		<< "exception: [" << reason << "]"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log a new bypassed instruction/API                                    */
/* ===================================================================== */
void LoggingInfo::logBypass(std::string bypassIdentifier) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write the new exception with relative previous address
	m_traceFile
		<< "[BYPASS] "
		<< bypassIdentifier
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log a new tainted branch                                              */
/* ===================================================================== */
void LoggingInfo::logTaintedBranch(ADDRINT addr, ADDRINT targetAddress, std::string ins, ADDRINT hash) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	char buf[1024]; 
	sprintf(buf, "0x%08x %s 0x%08x", addr, ins.c_str(), hash);
	// Write the new tainted branch with the relative information
	m_traceFile
		<< "[TAINTED_BRANCH] "
		<< std::string(buf)
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}